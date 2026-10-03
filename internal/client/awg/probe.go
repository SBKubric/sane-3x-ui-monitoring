package awg

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// handshakePollInterval is how often the UAPI dump is read while waiting
// for the AWG handshake (spec §5: "опрос ~50 мс"). It is a poll and not a
// callback because amneziawg-go exposes the completion only as state, never
// as an event (research §3.5).
const handshakePollInterval = 50 * time.Millisecond

// maxDetail is the cap on Result.Detail (spec §5: detail ≤ 256 characters),
// the same number as internal/client/probe.MaxDetail — kept as its own
// constant because failure (below) truncates AWG's own manually-composed
// details (the handshake attempts, amneziawg-go's error) before any of
// internal/client/probe's code ever sees them.
const maxDetail = 256

// Prober probes AWG targets and logs one line per result (spec §7).
// It exists only to carry the logger: everything else a probe needs comes
// from its arguments, because a probe holds no state between cycles by
// design (research §3.6).
type Prober struct {
	// Log receives the one-line-per-probe report. Nil means
	// slog.Default().
	Log *slog.Logger

	// Resolver turns a peer Endpoint that names a host into the IP
	// amneziawg-go insists on (decision #53 п. 1). Nil means
	// net.DefaultResolver, the host's own resolver.
	Resolver Resolver

	// tlsConfig overrides the probe's TLS settings. In production it is
	// always nil: mon-server presents a publicly trusted certificate
	// (mon-server spec §2), so the system roots are exactly right. The
	// package's own tests set it to trust the throwaway certificate of
	// the mon-server stub they run inside a test tunnel. It is handed to
	// probe.Do via transport.TLSClientConfig, which Do leaves untouched
	// for exactly this reason (internal/client/probe/do.go).
	tlsConfig *tls.Config
}

// Probe runs one AWG probe with the default logger. It is the form the
// probe runner (step 7) calls when it has no logger of its own.
func Probe(ctx context.Context, probeURL, token string, key proto.TargetKey, cfg *config.AWGConfig, b probe.Budgets) proto.Result {
	return Prober{}.Probe(ctx, probeURL, token, key, cfg, b)
}

// Probe runs one AWG probe end to end (spec §5, research §6.2):
//
//	fresh device → dial mon-server through the tunnel (connectMs measured
//	by hand, since httptrace cannot see a gVisor dialer) → handshakeMs from
//	the UAPI last_handshake_time polled every 50 ms until the end of the
//	budget → the connect, given connectMs from the handshake → the shared
//	HTTP half (internal/client/probe.Do) hands over that same connection
//	for tlsMs, ttfbMs and the nonce echo, in what is left of the budget →
//	200 with the same nonce is a success.
//
// The device is always closed before returning, including on every failure
// path: a leaked device keeps a UDP socket and a gVisor stack alive for the
// life of the process, and mon-client does this once a minute per target.
//
// Wall-clock time is read with time.Now() here rather than through
// clock.Clock: these are physical latency measurements of a real network
// exchange, and a fake clock would only make them lie (brief §1, same
// exemption as internal/client/probe's httptrace timings).
func (p Prober) Probe(ctx context.Context, probeURL, token string, key proto.TargetKey, cfg *config.AWGConfig, b probe.Budgets) proto.Result {
	ctx, cancel := context.WithTimeout(ctx, b.Budget)
	defer cancel()

	res := p.probe(ctx, probeURL, token, key, cfg, b)
	p.log(res)
	return res
}

func (p Prober) probe(ctx context.Context, probeURL, token string, key proto.TargetKey, cfg *config.AWGConfig, b probe.Budgets) proto.Result {
	var handshakeMs *int64

	addr, err := probeHostPort(probeURL)
	if err != nil {
		return failure(key, probe.Phases{}, handshakeMs, proto.ReasonHTTPError, err.Error())
	}

	// The endpoint is resolved on every probe, right before the device is
	// built, so a name whose address changed is followed within a cycle
	// (decision #53 п. 1). A name that does not resolve means no tunnel,
	// so it is the same awg_no_handshake as a device that would not come
	// up — the reason dictionary has no DNS entry, and detail names the
	// host.
	uapi, err := resolveEndpoints(ctx, p.resolver(), cfg.UAPI)
	if err != nil {
		return failure(key, probe.Phases{}, handshakeMs, proto.ReasonAWGNoHandshake, err.Error())
	}
	resolved := *cfg
	resolved.UAPI = uapi

	dev, err := Open(&resolved)
	if err != nil {
		// The tunnel never existed, so no handshake ever happened:
		// awg_no_handshake is the dictionary's word for it (spec §5), and
		// the device's own error (IpcSet, Up) is the detail. It is retried
		// next cycle like any other failed probe (decision #53 п. 2).
		return failure(key, probe.Phases{}, handshakeMs, proto.ReasonAWGNoHandshake, err.Error())
	}
	defer dev.Close()

	// t0 is taken before the first dial because that dial is what makes
	// netstack push a packet into the device, which is what queues the
	// handshake initiation (research §6.2).
	//
	// The dial lives as long as the probe's budget (#102): the SYN it sends
	// waits, staged inside amneziawg-go, for as long as the handshake takes,
	// and goes out the moment the handshake lands. Its connect phase proper
	// is bounded separately below, from the handshake on.
	t0 := time.Now()
	dialCtx, cancelDial := context.WithCancel(ctx)
	defer cancelDial()

	type dialResult struct {
		conn net.Conn
		err  error
		took time.Duration
	}
	dialed := make(chan dialResult, 1)
	go func() {
		start := time.Now()
		c, err := dev.DialContext(dialCtx, "tcp", addr)
		dialed <- dialResult{conn: c, err: err, took: time.Since(start)}
	}()

	// The handshake is waited for until the end of the probe's budget, not
	// for connectMs (#102): WireGuard retries an unanswered initiation only
	// every ~5 s, so a connectMs-long wait turned a single lost UDP packet
	// into a failed probe. Any handshake inside the budget counts.
	hs, gotHandshake := pollHandshake(ctx, dev)
	if gotHandshake {
		handshakeMs = msPtr(hs.Sub(t0))
	}

	// Once the handshake has landed, the SYN rides the tunnel and the
	// connect phase begins: it gets connectMs from here (still inside the
	// budget), and a connect that does not finish in it is tcp_timeout.
	// The dial is waited out rather than cancelled the moment the
	// handshake lands, because the handshake is not the end of the
	// connect — cancelling it then would abort a connect that had not had
	// a single round trip to succeed in and report its abort as a tcp
	// failure. Without a handshake the budget is already spent, and the
	// dial (bound to it through dialCtx) is only collected.
	var d dialResult
	connectTimedOut := false
	if gotHandshake {
		timer := time.NewTimer(b.Connect)
		select {
		case d = <-dialed:
		case <-timer.C:
			connectTimedOut = true
			cancelDial()
			d = <-dialed
		}
		timer.Stop()
	} else {
		cancelDial()
		d = <-dialed
	}
	// The handed-over connection is closed exactly once, however many
	// owners it ends up with: this defer always runs, and http.Transport
	// closes the connection it was handed too (DisableKeepAlives). Without
	// the guard the second Close lands on a gVisor endpoint that is
	// already gone, which surfaces as a "use of closed network connection"
	// error on a probe that otherwise succeeded.
	var conn net.Conn
	if d.conn != nil {
		conn = &onceConn{Conn: d.conn}
		defer conn.Close()
	}
	connectMs := msPtr(d.took)

	if !gotHandshake {
		detail := fmt.Sprintf("last_handshake_time=0 after %dms, %s", time.Since(t0).Milliseconds(), dev.HandshakeAttempts())
		return failure(key, probe.Phases{ConnectMs: connectMs}, handshakeMs, proto.ReasonAWGNoHandshake, detail)
	}
	if connectTimedOut && d.conn == nil {
		detail := fmt.Sprintf("connect through the tunnel did not finish %dms after the handshake", b.Connect.Milliseconds())
		return failure(key, probe.Phases{}, handshakeMs, proto.ReasonTCPTimeout, detail)
	}
	if d.err != nil {
		// The dial's own failure is classified the same way the shared
		// HTTP half would (internal/client/probe.Classify): gVisor's
		// "connection was refused" and the kernel's "connection refused"
		// both name tcp_refused there now, so this no longer needs its
		// own copy of that knowledge (brief §3.7, §3.8).
		reason, detail := probe.Classify(d.err, probe.Phases{}, b)
		return failure(key, probe.Phases{ConnectMs: connectMs}, handshakeMs, reason, detail)
	}

	// The connection whose connect was measured is the one the request
	// rides: dialing a second time would cost another round trip inside
	// the tunnel and report a connectMs that belongs to no request. Do
	// keeps this dialer (internal/client/probe/do.go) precisely because it
	// only installs its own net.Dialer when transport.DialContext is nil.
	transport := &http.Transport{
		DialContext:     (&onceDialer{conn: conn, fallback: dev.DialContext}).dial,
		TLSClientConfig: p.tlsConfig,
	}
	defer transport.CloseIdleConnections()

	ph, echo, err := probe.Do(ctx, transport, probeURL, token, key, b)
	// ph.ConnectMs is Do's own httptrace measurement, which never fires for
	// a handed-over gVisor connection (research §6.2) — connectMs stays the
	// manually measured dial above in every Result this function returns.
	if err != nil {
		reason, detail := probe.Classify(err, ph, b)
		return failure(key, probe.Phases{ConnectMs: connectMs, TlsMs: ph.TlsMs, TtfbMs: ph.TtfbMs}, handshakeMs, reason, detail)
	}
	return proto.Result{
		TargetKey:   key,
		Ok:          true,
		ConnectMs:   connectMs,
		TlsMs:       ph.TlsMs,
		TtfbMs:      ph.TtfbMs,
		HandshakeMs: handshakeMs,
		EgressIp:    &echo.EgressIp,
	}
}

// pollHandshake waits for the peer's first handshake, reading the UAPI dump
// every handshakePollInterval until it appears or the probe's budget (ctx)
// runs out (spec §5, #102).
func pollHandshake(ctx context.Context, dev *Device) (time.Time, bool) {
	ticker := time.NewTicker(handshakePollInterval)
	defer ticker.Stop()
	for {
		if t, ok := dev.LastHandshake(); ok {
			return t, true
		}
		select {
		case <-ctx.Done():
			// One last look: the handshake may have landed while
			// the budget was expiring.
			return dev.LastHandshake()
		case <-ticker.C:
		}
	}
}

// onceDialer hands the pre-dialed connection to the first dial and dials
// through the tunnel for any later one. With DisableKeepAlives and a single
// request there is only ever the first, but a fallback keeps a redirect or
// a transport retry from failing in a way that would be reported as a
// tunnel problem.
type onceDialer struct {
	mu       sync.Mutex
	conn     net.Conn
	fallback func(ctx context.Context, network, address string) (net.Conn, error)
}

func (o *onceDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	o.mu.Lock()
	c := o.conn
	o.conn = nil
	o.mu.Unlock()
	if c != nil {
		return c, nil
	}
	return o.fallback(ctx, network, address)
}

// onceConn is a net.Conn whose Close runs at most once, reporting the
// first Close's result to every later caller. A probe's connection has two
// owners by construction — the probe itself, which dialed it and defers
// its Close, and the http.Transport it is handed to, which closes it after
// the response because keep-alives are disabled — and neither can be
// dropped: the transport must close it when the request fails early, and
// the probe must close it when Do never got as far as using it.
type onceConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *onceConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}

// resolver is the Resolver to use, defaulting to the host's own.
func (p Prober) resolver() Resolver {
	if p.Resolver == nil {
		return net.DefaultResolver
	}
	return p.Resolver
}

// log writes the one line per probe spec §7 asks for.
func (p Prober) log(res proto.Result) {
	l := p.Log
	if l == nil {
		l = slog.Default()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "probe %s ", res.TargetKey)
	if res.Ok {
		b.WriteString("ok")
	} else {
		b.WriteString("FAIL " + deref(res.Reason))
	}
	writeMs(&b, "hs", res.HandshakeMs)
	writeMs(&b, "connect", res.ConnectMs)
	writeMs(&b, "tls", res.TlsMs)
	writeMs(&b, "ttfb", res.TtfbMs)
	if d := deref(res.Detail); d != "" {
		b.WriteString(" " + d)
	}
	if res.Ok {
		l.Info(b.String())
	} else {
		l.Warn(b.String())
	}
}

func writeMs(b *strings.Builder, name string, v *int64) {
	if v != nil {
		fmt.Fprintf(b, " %s=%dms", name, *v)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// failure builds a failed Result, keeping every phase that was measured
// before the failure (protocol §5.3 wants the partial timings). ph carries
// connectMs/tlsMs/ttfbMs (probe.Phases, shared with internal/client/probe);
// handshakeMs is AWG's own manual measurement and has no equivalent there.
func failure(key proto.TargetKey, ph probe.Phases, handshakeMs *int64, reason, detail string) proto.Result {
	detail = truncate(detail, maxDetail)
	return proto.Result{
		TargetKey:   key,
		Ok:          false,
		ConnectMs:   ph.ConnectMs,
		TlsMs:       ph.TlsMs,
		TtfbMs:      ph.TtfbMs,
		HandshakeMs: handshakeMs,
		Reason:      &reason,
		Detail:      &detail,
	}
}

// truncate cuts a detail to n runes (spec §5: ≤ 256 characters).
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// probeHostPort is the `host:port` the tunnel dials for a probe URL,
// defaulting the port from the scheme the way net/http would.
func probeHostPort(probeURL string) (string, error) {
	u, err := url.Parse(probeURL)
	if err != nil {
		return "", fmt.Errorf("probe url %q: %w", probeURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("probe url %q has no host", probeURL)
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("probe url %q: unsupported scheme %q", probeURL, u.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// msPtr rounds a duration to whole milliseconds for the wire (protocol
// §5.3 carries every timing as an integer number of milliseconds).
func msPtr(d time.Duration) *int64 {
	ms := d.Milliseconds()
	return &ms
}
