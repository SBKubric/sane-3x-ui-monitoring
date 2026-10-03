// Package probe runs one tunnel probe and turns its outcome into the
// protocol's result (protocol §5.2, §5.3, spec §5): a GET to mon-server's
// /v1/probe sent *through* a tunnel, timed with net/http/httptrace, and a
// failure named with one entry of the reason dictionary.
//
// The package is deliberately split in three: Do is the HTTP half (it knows
// nothing about xray or AWG — it takes a ready *http.Transport), Classify is
// the pure error → reason mapping, and Xray is the xray-specific wrapper that
// builds the socks5 transport and asks the child process' stderr for a better
// explanation. The AWG probe (step 6) reuses Do and Classify with a netstack
// transport; the cycle runner (step 7) drives Prober.Xray for every target in
// parallel.
package probe

import (
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// Spec §5 defaults: the probe parameters mon-client falls back to when the
// config document leaves one at zero. A 60 s cycle has to fit a full-budget
// probe plus the heartbeat (30 s + 10 s); the budget is 30 s rather than the
// research §5 20 s so that an AWG probe can sit out a few WireGuard
// handshake retries, ~5 s apart (#102). They are duplicated on mon-server's
// side in store.DefaultSettings, so a mon-client that never got a document
// still probes with the same timings as one that did.
const (
	DefaultBudget  = 30 * time.Second
	DefaultConnect = 5 * time.Second
	DefaultTLS     = 10 * time.Second
	DefaultHeaders = 10 * time.Second
)

// Budgets are the four timeouts one probe runs under (spec §5): Budget is the
// whole probe's context deadline, and the other three cut a single phase short
// so that a failure can be named after the phase that hung instead of
// collapsing into a plain probe_timeout.
type Budgets struct {
	// Budget is the deadline of the whole probe — context.WithTimeout around
	// the request. Exceeding it with no phase-specific error is probe_timeout.
	Budget time.Duration
	// Connect is net.Dialer.Timeout: for xray the dial is to loopback, so it
	// really bounds the socks handshake; for AWG it bounds only the TCP
	// connect through the tunnel, counted from the WireGuard handshake —
	// the handshake itself may take the whole Budget (#102).
	Connect time.Duration
	// TLS is Transport.TLSHandshakeTimeout. For an xray probe this is the
	// first end-to-end phase (Reality handshake + real server → mon-server TCP
	// + TLS 1.3, research §6.1), which is why tls_timeout is its own reason.
	TLS time.Duration
	// Headers is Transport.ResponseHeaderTimeout. The echo body is tiny, so
	// anything slower than this is the tunnel, not the response.
	Headers time.Duration
}

// BudgetsFrom converts the config document's probe parameters (protocol §4.2)
// into durations, substituting the spec §5 default for every field the
// document left at zero — a document built before an admin ever saved
// settings, or one whose fields mon-server chose not to send, must still
// produce a runnable probe rather than an instant timeout.
func BudgetsFrom(p proto.ProbeParams) Budgets {
	return Budgets{
		Budget:  msOr(p.BudgetMs, DefaultBudget),
		Connect: msOr(p.ConnectMs, DefaultConnect),
		TLS:     msOr(p.TlsMs, DefaultTLS),
		Headers: msOr(p.HeadersMs, DefaultHeaders),
	}
}

// msOr is "this many milliseconds, or the default when unset". Negative values
// are treated as unset too: they would otherwise make every probe fail
// instantly with a deadline already in the past.
func msOr(ms int64, def time.Duration) time.Duration {
	if ms <= 0 {
		return def
	}
	return time.Duration(ms) * time.Millisecond
}
