package awg

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
)

// keypair mints a Curve25519 keypair in the two spellings this test needs:
// base64 for the `.conf` (what the panel hands out) and hex for the UAPI
// dump (what device.IpcGet prints). amneziawg-go keeps its own key
// generator unexported, so the clamping is done here the way WireGuard
// specifies it.
func keypair(t *testing.T) (privB64, pubB64, pubHex string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub),
		hex.EncodeToString(pub)
}

// TestUAPIRoundTrip is the unit half of step 6: a `.conf` translated by
// internal/client/config is accepted verbatim by a real amneziawg-go device,
// and the device's own UAPI dump shows the peer that was asked for
// (spec §5, research §3.4). It touches no network — the device is created,
// configured and closed without a single packet leaving it.
func TestUAPIRoundTrip(t *testing.T) {
	t.Parallel()

	privB64, _, _ := keypair(t)
	_, peerPubB64, peerPubHex := keypair(t)
	pskRaw := make([]byte, 32)
	if _, err := rand.Read(pskRaw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pskB64 := base64.StdEncoding.EncodeToString(pskRaw)
	pskHex := hex.EncodeToString(pskRaw)

	conf := fmt.Sprintf(`[Interface]
Address = 10.66.66.2/32
PrivateKey = %s
MTU = 1420
DNS = 1.1.1.1
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
PresharedKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.7:51820
PersistentKeepalive = 25
`, privB64, peerPubB64, pskB64)

	cfg, err := config.ParseAWGConf(conf)
	if err != nil {
		t.Fatalf("ParseAWGConf: %v", err)
	}

	dev, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	dump, err := dev.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, want := range []string{
		"public_key=" + peerPubHex,
		"preshared_key=" + pskHex,
		"endpoint=198.51.100.7:51820",
		"allowed_ip=0.0.0.0/0",
		"jc=4", "jmin=40", "jmax=70", "s1=15", "s2=45",
		"h1=1234567", "h2=2345678", "h3=3456789", "h4=4567890",
		"last_handshake_time_sec=0",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("IpcGet dump has no %q; dump:\n%s", want, dump)
		}
	}
	// PersistentKeepalive is dropped on purpose (research §3.6): the
	// device is recreated every probe and never needs a NAT mapping kept
	// alive.
	if strings.Contains(cfg.UAPI, "persistent_keepalive") {
		t.Errorf("UAPI still carries persistent_keepalive:\n%s", cfg.UAPI)
	}
	// A device that has never talked to its peer reports no handshake —
	// that is the awg_no_handshake condition of spec §5.
	if _, ok := dev.LastHandshake(); ok {
		t.Error("LastHandshake reports a handshake on a device that never sent a packet")
	}
}

// TestParseLastHandshake covers the UAPI text the handshake timing is read
// from: a never-handshaked peer reads as "no handshake", and with several
// peers the newest one wins (spec §5, research §3.5).
func TestParseLastHandshake(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dump    string
		wantOk  bool
		wantSec int64
	}{
		{
			name:   "never",
			dump:   "private_key=00\npublic_key=aa\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n",
			wantOk: false,
		},
		{
			name:    "one peer",
			dump:    "public_key=aa\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=500000000\n",
			wantOk:  true,
			wantSec: 1700000000,
		},
		{
			name: "newest of several",
			dump: "public_key=aa\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=0\n" +
				"public_key=bb\nlast_handshake_time_sec=1700000009\nlast_handshake_time_nsec=0\n" +
				"public_key=cc\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n",
			wantOk:  true,
			wantSec: 1700000009,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseLastHandshake(tc.dump)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOk)
			}
			if ok && got.Unix() != tc.wantSec {
				t.Errorf("sec = %d, want %d", got.Unix(), tc.wantSec)
			}
		})
	}
}

// TestHandshakeLogCountsAttempts checks the device.Logger adapter: every
// "Sending handshake initiation" line is one attempt, the retry chatter and
// unrelated errors are dropped, and an error about an initiation is kept
// for the awg_no_handshake detail (spec §5, #102).
func TestHandshakeLogCountsAttempts(t *testing.T) {
	t.Parallel()

	h := &handshakeLog{}
	if got := h.String(); got != "0 handshake attempts" {
		t.Errorf("fresh log = %q, want %q", got, "0 handshake attempts")
	}
	l := h.logger()
	l.Verbosef("%v - Sending handshake initiation", "peer(abc)")
	if got := h.String(); got != "1 handshake attempt" {
		t.Errorf("after one initiation = %q, want %q", got, "1 handshake attempt")
	}
	for i := 2; i <= 4; i++ {
		l.Verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", "peer(abc)", 5, i)
		l.Verbosef("%v - Sending handshake initiation", "peer(abc)")
	}
	l.Errorf("Routine: receive - stopped")
	if got := h.String(); got != "4 handshake attempts" {
		t.Errorf("after four initiations = %q, want %q", got, "4 handshake attempts")
	}

	l.Errorf("%v - Failed to send handshake initiation: %v", "peer(abc)", "network is unreachable")
	want := "4 handshake attempts; peer(abc) - Failed to send handshake initiation: network is unreachable"
	if got := h.String(); got != want {
		t.Errorf("after a send error = %q, want %q", got, want)
	}
}
