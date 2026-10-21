package awg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// serverPort is the port the in-tunnel stub of mon-server listens on. Any
// port does; 8443 only reads like the real thing.
const serverPort = 8443

// TestProbeThroughTunnel is the success path of spec §5 without a single
// packet leaving this process: two netstack devices — the mon-client under
// test and a stand-in for the AWG server — hold a real AmneziaWG tunnel over
// loopback UDP, and mon-server's tunnel probe is answered from inside it.
//
// It pins what a good AWG probe looks like on the wire: ok, an egressIp
// that is the tunnel address the packets really came from, and all four
// timings measured (spec §5, protocol §5.3).
func TestProbeThroughTunnel(t *testing.T) {
	// Not parallel, and neither are its siblings below: each test holds two
	// netstack devices talking over loopback UDP, and running them side by
	// side only adds scheduling noise to measurements the test then
	// asserts on.
	far := startFarEnd(t, http.HandlerFunc(probeEcho))

	// The near end: exactly the config mon-client would get from
	// mon-server, pointing at the far end's loopback endpoint.
	clientCfg := far.clientConf(t, fmt.Sprintf("127.0.0.1:%d", far.port))

	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: far.pool}}
	key := proto.TargetKey{InboundKind: "awg", InboundID: 7, Path: "direct"}
	b := tunnelBudgets()

	res := p.Probe(context.Background(), far.probeURL(), "tok", key, clientCfg, b)
	if !res.Ok {
		t.Fatalf("probe failed: reason=%q detail=%q", deref(res.Reason), deref(res.Detail))
	}
	for name, v := range map[string]*int64{
		"handshakeMs": res.HandshakeMs,
		"connectMs":   res.ConnectMs,
		"tlsMs":       res.TlsMs,
		"ttfbMs":      res.TtfbMs,
	} {
		if v == nil {
			t.Errorf("%s is null, want a measurement", name)
			continue
		}
		if *v < 0 || *v > b.Budget.Milliseconds() {
			t.Errorf("%s = %d, out of range", name, *v)
		}
	}
	if res.EgressIp == nil || *res.EgressIp != clientTunnelIP {
		t.Errorf("egressIp = %v, want %q", res.EgressIp, clientTunnelIP)
	}
	if res.Reason != nil || res.Detail != nil {
		t.Errorf("a successful probe carries reason=%v detail=%v", res.Reason, res.Detail)
	}
	if res.TargetKey != key {
		t.Errorf("target key = %v, want %v", res.TargetKey, key)
	}
}

// TestProbeThroughTunnelEndpointHostname is decision #53 п. 1: a `.conf`
// whose Endpoint is a host name, not an IP. amneziawg-go only takes
// `endpoint=<ip>:<port>` over UAPI and never resolves (research #60), so
// before the fix every such probe failed in IpcSet with "unable to parse
// IP" and was reported as a false awg_no_handshake. The probe now resolves
// the name itself, right before building the device, and the tunnel comes
// up exactly as it does for an IP.
func TestProbeThroughTunnelEndpointHostname(t *testing.T) {
	far := startFarEnd(t, http.HandlerFunc(probeEcho))
	clientCfg := far.clientConf(t, fmt.Sprintf("awg-server.test:%d", far.port))

	res := &fakeResolver{addrs: map[string][]netip.Addr{
		"awg-server.test": {netip.MustParseAddr("127.0.0.1")},
	}}
	p := Prober{Log: silent(), Resolver: res, tlsConfig: &tls.Config{RootCAs: far.pool}}
	got := p.Probe(context.Background(), far.probeURL(), "tok",
		proto.TargetKey{InboundKind: "awg", InboundID: 7, Path: "direct"}, clientCfg, tunnelBudgets())

	if !got.Ok {
		t.Fatalf("probe through a hostname endpoint failed: reason=%q detail=%q", deref(got.Reason), deref(got.Detail))
	}
	if got.HandshakeMs == nil {
		t.Error("handshakeMs is null: the device never handshook with the resolved endpoint")
	}
	if calls := res.calls(); len(calls) != 1 || calls[0] != "awg-server.test" {
		t.Errorf("resolver calls = %v, want one lookup of awg-server.test", calls)
	}
}

// TestProbeThroughTunnelWrongNonce is spec §5's http_error: mon-server
// answered, but with someone else's nonce, so the response cannot be
// attributed to this probe.
func TestProbeThroughTunnelWrongNonce(t *testing.T) {
	far := startFarEnd(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEcho(w, r, "someone-elses-nonce")
	}))
	clientCfg := far.clientConf(t, fmt.Sprintf("127.0.0.1:%d", far.port))

	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: far.pool}}
	res := p.Probe(context.Background(), far.probeURL(), "tok",
		proto.TargetKey{InboundKind: "awg", InboundID: 7, Path: "direct"}, clientCfg, tunnelBudgets())

	if res.Ok {
		t.Fatal("a probe whose nonce was not echoed back counted as a success")
	}
	if got := deref(res.Reason); got != proto.ReasonHTTPError {
		t.Errorf("reason = %q, want %q", got, proto.ReasonHTTPError)
	}
	if res.HandshakeMs == nil || res.TlsMs == nil {
		t.Error("a failure after TLS must still carry the phases it did measure")
	}
}

// TestProbeWaitsForALateHandshake is #102: in production a standby edge
// lost the AWG server's handshake response on its way back, amneziawg-go
// sent the next initiation ~5 s later and that one went through — but the
// probe had already given up at connectMs (5 s) and reported
// awg_no_handshake. A lossy relay between the two ends drops the far end's
// first two responses, so the handshake only completes on the third
// initiation, ~10 s in: twice connectMs, well inside the 30 s budget. The
// probe must wait for it and succeed.
func TestProbeWaitsForALateHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for two WireGuard handshake retries (~10 s)")
	}
	far := startFarEnd(t, http.HandlerFunc(probeEcho))
	relay := startLossyRelay(t, far.port, 2)
	clientCfg := far.clientConf(t, fmt.Sprintf("127.0.0.1:%d", relay.port))

	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: far.pool}}
	b := probe.Budgets{Budget: 30 * time.Second, Connect: 5 * time.Second, TLS: 10 * time.Second, Headers: 10 * time.Second}
	res := p.Probe(context.Background(), far.probeURL(), "tok",
		proto.TargetKey{InboundKind: "awg", InboundID: 7, Path: "edge:proxy2"}, clientCfg, b)

	if !res.Ok {
		t.Fatalf("probe failed: reason=%q detail=%q (dropped %d responses)", deref(res.Reason), deref(res.Detail), relay.dropped())
	}
	if relay.dropped() != 2 {
		t.Fatalf("relay dropped %d responses, want 2", relay.dropped())
	}
	if res.HandshakeMs == nil || *res.HandshakeMs <= b.Connect.Milliseconds() {
		t.Errorf("handshakeMs = %s, want past connectMs (%dms): the handshake came on a retry", msString(res.HandshakeMs), b.Connect.Milliseconds())
	}
	if res.TlsMs == nil || res.TtfbMs == nil {
		t.Error("the HTTP half after a late handshake must still be measured")
	}
}

// lossyRelay is a UDP relay between the near end and the far end that
// drops the first few datagrams coming back from the far end — the AWG
// handshake responses, since nothing else travels that way before a
// handshake — the way the return path from a standby edge did (#102).
type lossyRelay struct {
	port int // the relay's UDP port on 127.0.0.1, the near end's Endpoint

	mu       sync.Mutex
	toDrop   int
	nDropped int
}

func (r *lossyRelay) dropped() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nDropped
}

// startLossyRelay relays between a near end that will send to the
// returned port and the far end on farPort, dropping the far end's first
// drop datagrams.
func startLossyRelay(t *testing.T, farPort, drop int) *lossyRelay {
	t.Helper()
	near, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	t.Cleanup(func() { _ = near.Close() })
	farConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: farPort})
	if err != nil {
		t.Fatalf("relay dial far end: %v", err)
	}
	t.Cleanup(func() { _ = farConn.Close() })

	r := &lossyRelay{port: near.LocalAddr().(*net.UDPAddr).Port, toDrop: drop}
	var (
		peerMu sync.Mutex
		peer   *net.UDPAddr
	)
	go func() { // near end → far end
		buf := make([]byte, 65535)
		for {
			n, from, err := near.ReadFromUDP(buf)
			if err != nil {
				return
			}
			peerMu.Lock()
			peer = from
			peerMu.Unlock()
			_, _ = farConn.Write(buf[:n])
		}
	}()
	go func() { // far end → near end, minus the first few
		buf := make([]byte, 65535)
		for {
			n, err := farConn.Read(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			drop := r.nDropped < r.toDrop
			if drop {
				r.nDropped++
			}
			r.mu.Unlock()
			peerMu.Lock()
			to := peer
			peerMu.Unlock()
			if drop || to == nil {
				continue
			}
			_, _ = near.WriteToUDP(buf[:n], to)
		}
	}()
	return r
}

// farEnd is the stand-in AWG server of the tunnel tests: a netstack device
// on loopback UDP that knows the client's public key, with an HTTPS
// handler for GET /v1/probe listening inside the tunnel.
type farEnd struct {
	port          int // the far end's UDP port on 127.0.0.1
	pool          *x509.CertPool
	serverPubB64  string
	clientPrivB64 string
}

// startFarEnd brings the far end up for the length of the test. It binds
// ListenPort 0 and asks afterwards which port it actually got — picking a
// "free" port by opening and closing a socket first would be a race every
// other test on the machine can win.
func startFarEnd(t *testing.T, handler http.Handler) *farEnd {
	t.Helper()
	serverPrivB64, serverPubB64, _ := keypair(t)
	clientPrivB64, clientPubB64, _ := keypair(t)

	serverCfg := parseConf(t, fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
ListenPort = 0
%s

[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, serverTunnelIP, serverPrivB64, awgObfuscation, clientPubB64, clientTunnelIP))
	server, err := Open(serverCfg)
	if err != nil {
		t.Fatalf("open server device: %v", err)
	}
	t.Cleanup(server.Close)
	port := listenPort(t, server)

	cert, pool := selfSigned(t, serverTunnelIP)
	fa, pn := fullAddr(netip.AddrPortFrom(netip.MustParseAddr(serverTunnelIP), serverPort))
	ln, err := gonet.ListenTCP(server.tun.stack, fa, pn)
	if err != nil {
		t.Fatalf("listen inside the tunnel: %v", err)
	}
	httpSrv := &http.Server{Handler: handler}
	serving := make(chan struct{})
	go func() {
		close(serving)
		_ = httpSrv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}}))
	}()
	t.Cleanup(func() { _ = httpSrv.Close() })
	<-serving

	return &farEnd{port: port, pool: pool, serverPubB64: serverPubB64, clientPrivB64: clientPrivB64}
}

// clientConf is the near end's `.conf` with the far end as its peer at
// endpoint, exactly the shape mon-client gets from mon-server.
func (f *farEnd) clientConf(t *testing.T, endpoint string) *config.AWGConfig {
	t.Helper()
	return parseConf(t, fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
MTU = 1420
%s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
`, clientTunnelIP, f.clientPrivB64, awgObfuscation, f.serverPubB64, endpoint))
}

func (f *farEnd) probeURL() string {
	return fmt.Sprintf("https://%s:%d/v1/probe", serverTunnelIP, serverPort)
}

// tunnelBudgets are generous on purpose: these are not latency tests, and
// a loaded CI box can take seconds to get two netstacks and an AWG
// handshake going — a probe that ran out of connect budget would be
// reported as a tunnel failure rather than a slow machine.
func tunnelBudgets() probe.Budgets {
	return probe.Budgets{Budget: 60 * time.Second, Connect: 20 * time.Second, TLS: 20 * time.Second, Headers: 20 * time.Second}
}

// probeEcho is GET /v1/probe as mon-server implements it (protocol §5.2).
func probeEcho(w http.ResponseWriter, r *http.Request) { writeEcho(w, r, r.URL.Query().Get("n")) }

func writeEcho(w http.ResponseWriter, r *http.Request, nonce string) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.ProbeEcho{
		Nonce:    nonce,
		EgressIp: host,
		ServerTs: time.Now().UnixMilli(),
	})
}

// parseConf is the tests' shorthand for a `.conf` that must be valid.
func parseConf(t *testing.T, conf string) *config.AWGConfig {
	t.Helper()
	cfg, err := config.ParseAWGConf(conf)
	if err != nil {
		t.Fatalf("ParseAWGConf: %v\n%s", err, conf)
	}
	return cfg
}

// listenPort asks a device which UDP port its bind actually got, out of
// the UAPI dump amneziawg-go answers `get=1` with. It is how a test can
// let the kernel choose the far end's port (ListenPort 0) and still point
// the near end at it, without ever holding a port open just to find out
// that it was free a moment ago.
func listenPort(t *testing.T, d *Device) int {
	t.Helper()
	dump, err := d.dev.IpcGet()
	if err != nil {
		t.Fatalf("uapi get: %v", err)
	}
	for _, line := range strings.Split(dump, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "listen_port="); ok {
			port, err := strconv.Atoi(value)
			if err != nil {
				t.Fatalf("listen_port %q: %v", value, err)
			}
			return port
		}
	}
	t.Fatalf("no listen_port in the uapi dump:\n%s", dump)
	return 0
}

// selfSigned mints a throwaway certificate for an IP, plus the pool that
// trusts it. The real mon-server has a publicly trusted certificate; these
// tests only need the probe's TLS handshake to be a real one.
func selfSigned(t *testing.T, ip string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: ip},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(ip)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool.AddCert(parsed)
	return cert, pool
}
