package awg

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// silent keeps the one-line-per-probe log (spec §7) out of the test output
// while still exercising the logging path.
func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// confFor builds a `.conf` pointing at endpoint with freshly minted keys.
func confFor(t *testing.T, endpoint string, peerPubB64 string) *config.AWGConfig {
	t.Helper()
	privB64, _, _ := keypair(t)
	if peerPubB64 == "" {
		_, peerPubB64, _ = keypair(t)
	}
	conf := fmt.Sprintf(`[Interface]
Address = 10.66.66.2/32
PrivateKey = %s
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 45
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
`, privB64, peerPubB64, endpoint)
	return parseConf(t, conf)
}

// TestProbeNoHandshake is the reason dictionary's awg_no_handshake (spec
// §5): a peer that never answers — here an address in the TEST-NET-3
// documentation range, which nothing routes — leaves last_handshake_time at
// zero, and the probe must say so. It says so at the end of the probe's
// budget, not after connectMs (#102): a handshake that lands anywhere
// inside the budget would still have counted.
func TestProbeNoHandshake(t *testing.T) {
	t.Parallel()

	cfg := confFor(t, "203.0.113.7:51820", "")
	b := probe.Budgets{Budget: 2 * time.Second, Connect: 400 * time.Millisecond, TLS: time.Second, Headers: time.Second}

	start := time.Now()
	res := Prober{Log: silent()}.Probe(context.Background(), "https://203.0.113.7:8443/v1/probe", "tok", proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}, cfg, b)
	elapsed := time.Since(start)

	if res.Ok {
		t.Fatalf("probe to a black hole succeeded: %+v", res)
	}
	if got := deref(res.Reason); got != proto.ReasonAWGNoHandshake {
		t.Fatalf("reason = %q, want %q (detail %q)", got, proto.ReasonAWGNoHandshake, deref(res.Detail))
	}
	if res.HandshakeMs != nil {
		t.Errorf("handshakeMs = %d, want null when no handshake happened", *res.HandshakeMs)
	}
	if d := deref(res.Detail); !strings.HasPrefix(d, "last_handshake_time=0 after ") || !strings.Contains(d, "1 handshake attempt") {
		t.Errorf("detail = %q, want the wait and the number of handshake attempts", d)
	}
	if elapsed < b.Budget-100*time.Millisecond {
		t.Errorf("probe gave up after %s, want it to wait out the %s budget, not connectMs (%s)", elapsed, b.Budget, b.Connect)
	}
	if elapsed > b.Budget+2*time.Second {
		t.Errorf("probe took %s, want it to give up shortly after the %s budget", elapsed, b.Budget)
	}
	if res.TargetKey.String() != "awg:0:proxy" {
		t.Errorf("target key = %q", res.TargetKey.String())
	}
}

// TestProbeBadConfig checks that a device that cannot even be built is
// reported, not panicked over: the tunnel never existed, so spec §5's word
// for it is awg_no_handshake.
func TestProbeBadConfig(t *testing.T) {
	t.Parallel()

	cfg := confFor(t, "203.0.113.7:51820", "")
	// A private key that is not a key at all: IpcSet rejects it.
	cfg.UAPI = "private_key=not-hex\n"
	res := Prober{Log: silent()}.Probe(context.Background(), "https://203.0.113.7:8443/v1/probe", "tok",
		proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}, cfg, probe.Budgets{Budget: time.Second, Connect: 100 * time.Millisecond})
	if res.Ok || deref(res.Reason) != proto.ReasonAWGNoHandshake {
		t.Fatalf("got %+v, want a failed awg_no_handshake result", res)
	}
	// Decision #53 п. 2: a device error stays a probe failure, and its text
	// is the detail, so the operator sees what amneziawg-go refused.
	if d := deref(res.Detail); !strings.Contains(d, "apply uapi config") {
		t.Errorf("detail = %q, want the IpcSet error", d)
	}
}

// TestProbeHostPort covers the dial address a probe URL implies.
func TestProbeHostPort(t *testing.T) {
	t.Parallel()

	tests := []struct{ url, want string }{
		{"https://10.0.0.1:8443/v1/probe", "10.0.0.1:8443"},
		{"https://10.0.0.1/v1/probe", "10.0.0.1:443"},
		{"http://10.0.0.1/v1/probe", "10.0.0.1:80"},
		{"https://[2001:db8::1]:8443/v1/probe", "[2001:db8::1]:8443"},
	}
	for _, tc := range tests {
		got, err := probeHostPort(tc.url)
		if err != nil {
			t.Errorf("%s: %v", tc.url, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s → %q, want %q", tc.url, got, tc.want)
		}
	}
	for _, bad := range []string{"ftp://10.0.0.1/x", "/v1/probe", "://"} {
		if _, err := probeHostPort(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

// TestTruncateDetail pins spec §5's 256-character cap on detail. The nonce
// itself is no longer minted here — probe.Do (internal/client/probe/do.go)
// owns that now, and its own tests (TestDo_SendsTargetNonceAndToken) cover
// the 16-byte base64url shape for both probes.
func TestTruncateDetail(t *testing.T) {
	t.Parallel()

	long := ""
	for i := 0; i < 400; i++ {
		long += "ы"
	}
	res := failure(proto.TargetKey{}, probe.Phases{}, nil, proto.ReasonHTTPError, long)
	if n := len([]rune(deref(res.Detail))); n != maxDetail {
		t.Errorf("detail is %d runes, want %d", n, maxDetail)
	}
}

// TestOnceConnClosesUnderlyingOnce pins the guard around the connection a
// probe hands over to http.Transport: both owners close it (the probe's
// own defer and the transport, which has keep-alives disabled), and the
// second Close must not reach the gVisor endpoint — where it would surface
// as "use of closed network connection" on a probe that had already
// succeeded.
func TestOnceConnClosesUnderlyingOnce(t *testing.T) {
	t.Parallel()

	inner := &countingConn{}
	c := &onceConn{Conn: inner}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if inner.closes != 1 {
		t.Fatalf("underlying Close called %d times, want 1", inner.closes)
	}
}

// countingConn is a net.Conn that only counts its own Close; every other
// method would panic, which is exactly right — nothing but Close is under
// test here.
type countingConn struct {
	net.Conn
	closes int
}

func (c *countingConn) Close() error {
	c.closes++
	return nil
}
