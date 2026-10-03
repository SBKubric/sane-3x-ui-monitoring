package awg

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// awgServerImage is the upstream AmneziaWG image used as the far end of the
// tunnel. It carries amneziawg-go, awg and iproute2 (research §3.1).
const awgServerImage = "amneziavpn/amneziawg-go:latest"

// serverTunnelIP is the address the server container puts on its awg0. It
// is the probe target of the live test: reaching it at all proves that
// encrypted traffic crossed the netstack tunnel in both directions.
const serverTunnelIP = "10.66.66.1"

// clientTunnelIP is the netstack device's own address; the server's peer
// entry allows exactly it.
const clientTunnelIP = "10.66.66.2"

// awgObfuscation is the AmneziaWG obfuscation block both ends must agree on
// (research §3.7) — junk packets, init/response padding and header types.
const awgObfuscation = `Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 45
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890`

// TestIntegrationNetstackHandshake is the live run the research left
// UNVERIFIED (research §8, spec §9): an in-process netstack device against a
// real amneziawg-go server, once with the right peer key and once with a
// wrong one.
//
// What it can and cannot assert. mon-server is not reachable from inside
// the tunnel here — nothing in the server container routes or NATs traffic
// out of awg0 — so the HTTPS half of a probe cannot succeed. What the test
// does prove is the half step 6 owns:
//
//   - right key: the handshake completes (handshakeMs is measured) and the
//     tunnel carries real traffic, because the probe's TCP connect to the
//     server's own tunnel address gets an answer from the server's kernel;
//     the probe therefore fails for some reason other than awg_no_handshake;
//   - wrong key: the server never replies to an unauthorised initiation
//     (research §3.5), last_handshake_time stays zero, and the probe reports
//     awg_no_handshake.
//
// It is opt-in: it skips without docker, and under -short.
func TestIntegrationNetstackHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: needs docker and a real AWG server")
	}
	requireDocker(t)

	serverPriv, serverPub, _ := keypair(t)
	clientPriv, clientPub, _ := keypair(t)
	_, strangerPub, _ := keypair(t)

	endpoint := startAWGServer(t, serverPriv, clientPub)
	t.Logf("awg server endpoint %s", endpoint)

	probeURL := fmt.Sprintf("https://%s:8443/v1/probe", serverTunnelIP)
	key := proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}
	b := probe.Budgets{Budget: 10 * time.Second, Connect: 5 * time.Second, TLS: 5 * time.Second, Headers: 5 * time.Second}

	t.Run("right peer key completes a handshake", func(t *testing.T) {
		cfg := clientConf(t, clientPriv, serverPub, endpoint)
		res := Prober{Log: silent()}.Probe(context.Background(), probeURL, "tok", key, cfg, b)
		t.Logf("result: ok=%v reason=%q detail=%q handshakeMs=%s connectMs=%s",
			res.Ok, deref(res.Reason), deref(res.Detail), msString(res.HandshakeMs), msString(res.ConnectMs))

		if res.HandshakeMs == nil {
			t.Fatalf("handshakeMs is null: the netstack device never completed a handshake (%q: %q)",
				deref(res.Reason), deref(res.Detail))
		}
		if *res.HandshakeMs < 0 || *res.HandshakeMs > b.Budget.Milliseconds() {
			t.Errorf("handshakeMs = %d, want 0..%d", *res.HandshakeMs, b.Budget.Milliseconds())
		}
		// The probe target is the server's own tunnel address and
		// nothing listens there, so the failure must be the RST the
		// server's kernel sent back *through the tunnel* — which is
		// the proof that encrypted traffic crossed netstack in both
		// directions, not merely that a handshake happened.
		if got := deref(res.Reason); got != proto.ReasonTCPRefused {
			t.Errorf("reason = %q (detail %q), want %q: the tunnel did not carry the connect",
				got, deref(res.Detail), proto.ReasonTCPRefused)
		}
	})

	t.Run("wrong peer key is awg_no_handshake", func(t *testing.T) {
		cfg := clientConf(t, clientPriv, strangerPub, endpoint)
		res := Prober{Log: silent()}.Probe(context.Background(), probeURL, "tok", key, cfg, b)
		t.Logf("result: ok=%v reason=%q detail=%q handshakeMs=%s",
			res.Ok, deref(res.Reason), deref(res.Detail), msString(res.HandshakeMs))

		if res.Ok {
			t.Fatal("a probe through a tunnel to a peer that does not know us succeeded")
		}
		if got := deref(res.Reason); got != proto.ReasonAWGNoHandshake {
			t.Errorf("reason = %q, want %q", got, proto.ReasonAWGNoHandshake)
		}
		if res.HandshakeMs != nil {
			t.Errorf("handshakeMs = %d, want null", *res.HandshakeMs)
		}
	})
}

// clientConf builds the client side of the tunnel: our private key, the
// peer's public key, AllowedIPs 0.0.0.0/0 (the probe target lives inside
// the tunnel) and the container's endpoint.
func clientConf(t *testing.T, privB64, peerPubB64, endpoint string) *config.AWGConfig {
	t.Helper()
	conf := fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
MTU = 1420
%s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s
`, clientTunnelIP, privB64, awgObfuscation, peerPubB64, endpoint)
	cfg, err := config.ParseAWGConf(conf)
	if err != nil {
		t.Fatalf("ParseAWGConf: %v", err)
	}
	return cfg
}

// startAWGServer brings up amneziawg-go in a container and returns the
// `host:port` the netstack client should dial. The container needs
// NET_ADMIN and /dev/net/tun because it uses a real TUN interface — the
// netstack client, the thing under test, needs neither (research §3.1).
//
// The configuration is written by the container's own shell rather than
// bind-mounted, so the test works even when it runs in a sibling container
// whose filesystem the docker daemon cannot see. The endpoint is the
// container's bridge address rather than a published port, for the same
// reason.
func startAWGServer(t *testing.T, serverPrivB64, clientPubB64 string) string {
	t.Helper()

	script := fmt.Sprintf(`set -e
cat > /awg0.conf <<'CONF'
[Interface]
PrivateKey = %s
ListenPort = 51820
%s

[Peer]
PublicKey = %s
AllowedIPs = %s/32
CONF
amneziawg-go awg0
awg setconf awg0 /awg0.conf
ip addr add %s/24 dev awg0
ip link set up dev awg0
sleep 600
`, serverPrivB64, awgObfuscation, clientPubB64, clientTunnelIP, serverTunnelIP)

	out, err := exec.Command("docker", "run", "-d",
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		awgServerImage, "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("server container logs:\n%s", logs)
			show, _ := exec.Command("docker", "exec", id, "awg", "show").CombinedOutput()
			t.Logf("awg show:\n%s", show)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})

	// Wait until the interface is configured: `awg show` listing the peer
	// means setconf ran and the UDP socket is listening.
	deadline := time.Now().Add(30 * time.Second)
	for {
		show, err := exec.Command("docker", "exec", id, "awg", "show", "awg0").CombinedOutput()
		if err == nil && strings.Contains(string(show), "peer:") {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Fatalf("awg server never came up: %v\n%s\nlogs:\n%s", err, show, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}

	ip, err := exec.Command("docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", id).Output()
	if err != nil {
		t.Fatalf("docker inspect: %v", err)
	}
	addr := strings.TrimSpace(string(ip))
	if addr == "" {
		t.Fatal("server container has no bridge address")
	}
	return addr + ":51820"
}

// requireDocker skips the test when docker cannot be used from here — which
// is the normal case inside the build container (brief §4).
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("integration test: docker not on PATH")
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("integration test: docker daemon not reachable: %v\n%s", err, out)
	}
}

func msString(v *int64) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%dms", *v)
}
