// Package awg probes an AmneziaWG target from inside this process: every
// probe builds a fresh gVisor netstack device from the target's `.conf`,
// dials mon-server's tunnel probe through it and reports how long the AWG
// handshake, the TCP connect, the TLS handshake and the first byte took
// (spec §5, research §3.4, §6.2).
//
// Nothing here touches the kernel: no TUN interface, no route, no
// capability. That is the whole reason netstack was chosen over a real
// interface — a mon-client may watch a dozen AWG targets on one box and
// must not need NET_ADMIN to do it (research §3.4, §4).
package awg

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
)

// initiationMark is the substring amneziawg-go logs every time it sends a
// handshake initiation ("peer(…) - Sending handshake initiation"), the
// first one and every retry ~5 s later alike. WireGuard has no handshake
// *error* — an unauthorised or unreachable peer simply never replies — so
// how many initiations went unanswered is the most a failed probe can say
// in its `detail` (spec §5, reason awg_no_handshake; #102).
const initiationMark = "Sending handshake initiation"

// initiationErrorMark is the substring of amneziawg-go's error lines about
// an initiation it could not build or send ("Failed to send handshake
// initiation: <err>", "Failed to create initiation message: <err>"): the
// one case where the device knows why there was no handshake, e.g. the
// host has no route to the endpoint.
const initiationErrorMark = "initiation"

// Device is one live netstack AWG tunnel: the gVisor stack, the
// amneziawg-go device driving it, and the record of handshake attempts the
// device logged while it was up.
//
// It is deliberately single-use. Keeping a device alive across probes would
// mean a handshake is only re-done every 120 s (RekeyAfterTime), so four of
// five probes could not measure one at all; recreating it per probe costs a
// single initiation plus Jc junk packets a minute and buys a handshake
// measurement every cycle (research §3.6, spec §5).
type Device struct {
	dev *device.Device
	tun *netTUN
	hs  *handshakeLog
}

// Open brings up a fresh netstack device for cfg: a netTUN with the
// `.conf`'s addresses and MTU (our copy of amneziawg-go's CreateNetTUN —
// see netTUN for why), NewDevice on a batch-1 UDP bind (probeBind — see
// there why not the default one), IpcSet with the UAPI blob
// internal/client/config already rendered in IpcSet order, then Up
// (research §3.4).
//
// The stack has no DNS resolver: mon-client always dials mon-server by
// address, never by name (spec §4), so a resolver inside the tunnel would
// only add a failure mode.
func Open(cfg *config.AWGConfig) (*Device, error) {
	if cfg == nil {
		return nil, fmt.Errorf("awg: no config")
	}
	hs := &handshakeLog{}
	tun, err := newNetTUN(cfg.LocalAddresses, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("awg: create netstack tun: %w", err)
	}
	dev := newDevice(tun, hs.logger())
	if err := dev.IpcSet(cfg.UAPI); err != nil {
		dev.Close()
		return nil, fmt.Errorf("awg: apply uapi config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("awg: bring device up: %w", err)
	}
	return &Device{dev: dev, tun: tun, hs: hs}, nil
}

// newDevice is the one way this package builds an amneziawg-go device, so
// Check judges a config on the very device Open would run it on: netTUN
// underneath, probeBind for the UDP side.
func newDevice(tun *netTUN, log *device.Logger) *device.Device {
	return device.NewDevice(tun, newProbeBind(), log)
}

// DialContext opens a TCP connection through the tunnel. It is the
// http.Transport's dialer as well as the probe's own connect measurement:
// httptrace's ConnectStart/ConnectDone never fire for a custom dialer,
// because net.Dialer is what reads the trace out of the context and gVisor
// does not (research §6.2).
func (d *Device) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tun.DialContext(ctx, network, address)
}

// LastHandshake reports the newest peer handshake the device knows about,
// parsed out of the UAPI `get=1` dump (`last_handshake_time_sec` /
// `_nsec`). ok is false while no peer has ever completed one — UAPI spells
// that as a zero timestamp, and it is exactly the awg_no_handshake
// condition of spec §5.
//
// The newest of all peers is taken because a `.conf` may list several and
// any one of them completing means the tunnel carries traffic.
func (d *Device) LastHandshake() (t time.Time, ok bool) {
	dump, err := d.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	return parseLastHandshake(dump)
}

// HandshakeAttempts describes the handshake attempts the device made, for
// use in an awg_no_handshake Result.Detail (spec §5): how many initiations
// it sent and, when one could not be sent at all, amneziawg-go's last error
// about it.
func (d *Device) HandshakeAttempts() string {
	return d.hs.String()
}

// Close tears the device and its netstack down. It is safe to call twice,
// which matters because every probe defers it (spec §5: the device must go
// away even when the probe failed half way).
func (d *Device) Close() {
	if d == nil || d.dev == nil {
		return
	}
	d.dev.Close()
	d.dev = nil
}

// parseLastHandshake reads the newest last_handshake_time out of a UAPI
// get=1 dump. Kept separate from LastHandshake so it can be tested without
// a device.
func parseLastHandshake(dump string) (time.Time, bool) {
	var sec, nsec int64
	var best time.Time
	var ok bool
	flush := func() {
		if sec == 0 && nsec == 0 {
			return
		}
		if t := time.Unix(sec, nsec); !ok || t.After(best) {
			best, ok = t, true
		}
	}
	for _, line := range strings.Split(dump, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "public_key":
			// A new peer block starts: bank whatever the previous
			// one reported before its fields are overwritten.
			flush()
			sec, nsec = 0, 0
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	flush()
	return best, ok
}

// handshakeLog is the device.Logger adapter: it counts the handshake
// initiations the device sent, keeps the last error about one, and throws
// the rest of amneziawg-go's very chatty verbose output away. mon-client's
// own log is slog on stdout (spec §7); the device's log exists only to give
// a failed probe a `detail`.
type handshakeLog struct {
	mu          sync.Mutex
	initiations int
	lastErr     string
}

// logger hands amneziawg-go a Logger for both levels. "Sending handshake
// initiation" is a *verbose* line in amneziawg-go, the send failures are
// error lines.
func (h *handshakeLog) logger() *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			if strings.Contains(format, initiationMark) {
				h.mu.Lock()
				h.initiations++
				h.mu.Unlock()
			}
		},
		Errorf: func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			if strings.Contains(line, initiationErrorMark) {
				h.mu.Lock()
				h.lastErr = line
				h.mu.Unlock()
			}
		},
	}
}

// String is the attempts part of a detail: "3 handshake attempts", plus
// "; <last error>" when an initiation could not be sent.
func (h *handshakeLog) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	noun := "attempts"
	if h.initiations == 1 {
		noun = "attempt"
	}
	out := fmt.Sprintf("%d handshake %s", h.initiations, noun)
	if h.lastErr != "" {
		out += "; " + h.lastErr
	}
	return out
}
