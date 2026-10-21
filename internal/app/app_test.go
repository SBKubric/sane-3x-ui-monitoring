package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlsxtest"
)

// newTestApp builds an App in "files" TLS mode against a fresh self-signed
// cert and a fresh temp-file store, listening on an OS-assigned loopback
// port. It registers t.Cleanup to shut the App down so no test leaks a
// goroutine into the next one under -race.
func newTestApp(t *testing.T) (*App, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)

	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	cfg := &config.Config{
		Listen:   "127.0.0.1:0",
		PublicIP: "127.0.0.1",
		DataDir:  dir,
		TLS:      config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}

	a, err := New(Deps{Cfg: cfg, Store: st, Clock: clock.Real{}, Notifier: tg.Nop{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test cert")
	}

	return a, &tls.Config{RootCAs: pool}
}

// TestStartAndHealthz checks the "files" mode happy path the issue's test
// list names: the listener comes up and answers /healthz over real TLS
// trusted only because the client was handed this specific self-signed
// cert — proving Start actually serves the tls.Config tlsx.Build produced,
// not some other listener.
func TestStartAndHealthz(t *testing.T) {
	a, clientTLS := newTestApp(t)

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// syncBuffer is a bytes.Buffer the default slog handler can write to from
// the offline sweep's goroutine while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestStart_ReportsServerReady checks decision #84's plumbing: once the
// listener can complete handshakes (at once in "files" mode), Start hands
// the engine its serverReadyAt, which is what writes the one start-up line
// about mon-server's own downtime. The offline sweep counts silence from
// that same moment; internal/state's MarkOffline tests cover the counting.
func TestStart_ReportsServerReady(t *testing.T) {
	logs := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	a, _ := newTestApp(t)
	last := clock.Ms(time.Now().Add(-5 * time.Minute))
	mc := &store.MonClient{
		Id: "ams-1", Name: "ams-1", Region: "NL", Enabled: true,
		State: store.MonClientOnline, ApprovedAt: last, LastHeartbeat: &last,
	}
	if err := a.deps.Store.DB.Create(mc).Error; err != nil {
		t.Fatalf("create mon-client: %v", err)
	}

	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "started; last heartbeat seen 5m0s ago") {
		if time.Now().After(deadline) {
			t.Fatalf("logs = %q, want the start-up line about the last heartbeat", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestShutdown_WaitsForInFlightRequest checks the graceful-shutdown
// requirement (spec §2): Shutdown must not return while a handler is still
// running, and the in-flight request must still complete successfully
// rather than being cut off.
func TestShutdown_WaitsForInFlightRequest(t *testing.T) {
	a, clientTLS := newTestApp(t)

	release := make(chan struct{})
	handlerStarted := make(chan struct{})
	a.Server().Engine.GET("/block", func(c *gin.Context) {
		close(handlerStarted)
		<-release
		c.String(http.StatusOK, "done")
	})

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}

	type result struct {
		status int
		err    error
	}
	reqDone := make(chan result, 1)
	go func() {
		resp, err := client.Get("https://" + addr + "/block")
		if err != nil {
			reqDone <- result{err: err}
			return
		}
		defer resp.Body.Close()
		reqDone <- result{status: resp.StatusCode}
	}()

	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked handler never started")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- a.Shutdown(ctx)
	}()

	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned before the in-flight request finished")
	case <-time.After(200 * time.Millisecond):
		// expected: Shutdown is still waiting on /block.
	}

	close(release)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the handler was released")
	}

	res := <-reqDone
	if res.err != nil {
		t.Fatalf("in-flight request failed: %v", res.err)
	}
	if res.status != http.StatusOK {
		t.Fatalf("in-flight request status = %d, want 200", res.status)
	}
}

// TestShutdown_ReturnsPromptlyWithNoRequests checks that Shutdown does not
// itself impose any delay when there is nothing to wait for — it must not,
// say, always block for the full grace period.
func TestShutdown_ReturnsPromptlyWithNoRequests(t *testing.T) {
	a, _ := newTestApp(t)
	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Shutdown took %v with no in-flight requests, want well under 1s", elapsed)
	}
}

// TestRun_ShutsDownWhenContextCancelled checks the top-level lifecycle
// cmd/mon-server drives: Run blocks while ctx is live and returns once it is
// cancelled, after shutting the listener down. Start/Shutdown themselves are
// covered above; this only needs to prove Run wires ctx cancellation to
// shutdown and returns.
func TestRun_ShutsDownWhenContextCancelled(t *testing.T) {
	a, _ := newTestApp(t)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Give Run's Start() a moment to happen before cancelling; Run logs
	// "listening" synchronously right after Start returns, so a short,
	// generous sleep is enough without needing to observe the address.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

// TestRun_ReturnsErrorWhenAcceptLoopDiesUnexpectedly checks that Run does
// not park forever on <-ctx.Done() when the server has already stopped
// serving for a reason other than Shutdown (here: its listener fd closed
// out from under it). Run must notice via serveErrCh and return a non-nil
// error promptly instead of hanging until the test's own context is ever
// cancelled (in production: until the process is killed, serving nothing).
func TestRun_ReturnsErrorWhenAcceptLoopDiesUnexpectedly(t *testing.T) {
	a, _ := newTestApp(t)

	// Never cancelled by this test: if Run were to (incorrectly) only
	// watch ctx.Done(), it would hang until the 5s select below times out,
	// which is exactly the failure mode this test exists to catch.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Wait for Run's Start() to publish the bound listener on lnCh (a
	// synchronized handoff — reading a.ln directly here would race Start's
	// write to it) before reaching in — this test is in-package precisely
	// so it can — and closing it out from under the server, simulating a
	// dead accept loop.
	var ln net.Listener
	select {
	case ln = <-a.lnCh:
	case <-time.After(5 * time.Second):
		t.Fatal("listener was never bound")
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener out from under the server: %v", err)
	}

	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("Run: want a non-nil error when the accept loop dies unexpectedly, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return promptly after the listener died out from under it")
	}
}

// TestApp_ReadTimeoutClosesStalledBody checks the public-listener timeout
// fix: a client that sends a request's headers (with a Content-Length
// promising a body) and then never sends that body must be disconnected
// within the configured read timeout, not left tying up a handler
// goroutine indefinitely. It uses newApp's unexported timeout override so
// the test runs in milliseconds instead of sleeping for the real 30s
// production value.
func TestApp_ReadTimeoutClosesStalledBody(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)

	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	cfg := &config.Config{
		Listen:   "127.0.0.1:0",
		PublicIP: "127.0.0.1",
		DataDir:  dir,
		TLS:      config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}

	const shortReadTimeout = 300 * time.Millisecond
	a, err := newApp(Deps{Cfg: cfg, Store: st, Clock: clock.Real{}, Notifier: tg.Nop{}}, shortReadTimeout, writeTimeout)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	a.Server().Engine.POST("/upload", func(c *gin.Context) {
		_, _ = io.Copy(io.Discard, c.Request.Body)
		c.Status(http.StatusOK)
	})

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test cert")
	}

	// pr is a body that promises 10 bytes (ContentLength below) but never
	// delivers any: the handler's io.Copy blocks reading from it exactly
	// like it would block reading a real mon-client connection that sent
	// headers and then stalled.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/upload", pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = 10

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	start := time.Now()
	respCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		respCh <- err
	}()

	// Whether the round trip ends in an error (connection reset/closed
	// while the client was still trying to deliver the body) or in a
	// response (the server gave up reading the body and replied anyway),
	// what matters is that it happens promptly: readTimeout must actually
	// bound the wait, instead of the handler's io.Copy blocking forever on
	// a body that never arrives.
	select {
	case <-respCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("client.Do did not return within 2s of a %v read timeout — the server appears to be blocked waiting for the stalled body", shortReadTimeout)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("round trip with a stalled body took %v, want well under 1.5s (readTimeout=%v)", elapsed, shortReadTimeout)
	}
}

// TestShutdown_JoinsTheBackgroundJobs checks that the panel poll loop (spec
// §4), the mon-client liveness sweep (spec §7.3) and the hourly retention
// job (spec §3) are started by Start and actually joined by Shutdown: a
// goroutine still running after Shutdown returned would keep writing to
// (or deleting from) a database the process believes it has closed, and
// would show up as a leak under -race.
func TestShutdown_JoinsTheBackgroundJobs(t *testing.T) {
	a, _ := newTestApp(t)

	if a.Poller() == nil {
		t.Fatal("New did not wire a panel poller")
	}
	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !a.pollStopped.Load() {
		t.Fatal("Shutdown returned while the panel poll loop was still running")
	}
	// The 20s mon-client liveness job (spec §7.3) is joined the same way,
	// and for the same reason: it writes to the database on every tick.
	if !a.offlineStopped.Load() {
		t.Fatal("Shutdown returned while the offline sweep was still running")
	}
	// The hourly retention job (spec §3, issue #13) is joined the same
	// way: Shutdown must not return while it could still be deleting rows.
	if !a.retentionStopped.Load() {
		t.Fatal("Shutdown returned while the retention job was still running")
	}
	if a.Poller().PanelDown() {
		t.Fatal("an unconfigured mon-server must not start out in PANEL_DOWN")
	}
}

// hangingNotifier is a tg.Notifier that ignores ctx entirely and blocks
// until released — standing in for a collaborator that does not honour
// cancellation as diligently as the panel HTTPClient does (plausible for the
// real Telegram client's own HTTP call, step 9's problem to get right, not
// this one's). It is what makes TestShutdown_AbandonsAHungPollerWhenItsCtxExpires
// a genuine reproduction: the panel HTTPClient's request-scoped cancellation
// alone cannot be relied on to unstick every cycle promptly.
type hangingNotifier struct{ release chan struct{} }

func (h *hangingNotifier) Send(context.Context, string) error {
	<-h.release
	return nil
}

// TestShutdown_AbandonsAHungPollerWhenItsCtxExpires checks the self-check
// finding on Shutdown's other lifecycle point: joining the panel poll loop
// must be bounded by Shutdown's own ctx, not by however long the poller
// actually takes to return. A cycle stuck inside a collaborator that does
// not honour ctx cancellation must not be able to keep Shutdown from ever
// returning — it comes back once its own ctx expires, having abandoned the
// still-running poller rather than waited on it forever. Without the bound
// this reproduces the old bug: Shutdown would hang until the notifier is
// released, however long that takes.
func TestShutdown_AbandonsAHungPollerWhenItsCtxExpires(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	notifier := &hangingNotifier{release: make(chan struct{})}

	cfg := &config.Config{
		Listen:   "127.0.0.1:0",
		PublicIP: "127.0.0.1",
		DataDir:  dir,
		TLS:      config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}
	a, err := New(Deps{Cfg: cfg, Store: st, Clock: clock.Real{}, Notifier: notifier})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	// Registered after the Shutdown cleanup above, so t.Cleanup's LIFO order
	// runs this first: unblock the notifier before that final Shutdown call
	// has to abandon it a second time, so the goroutine this test
	// intentionally stalls does not leak into the rest of the test binary's
	// life.
	t.Cleanup(func() { close(notifier.release) })

	stub := paneltest.NewStub(t)
	stub.SetMonEnabled(false) // bare 404 on every request (contract §2)

	set := store.DefaultSettings()
	set.PanelURL = stub.URL()
	set.MonToken = stub.Token()
	if err := st.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The first cycle runs immediately (no minute-long wait needed): the
	// bare 404 fires notifyRejected on its very first Poll, which is where
	// the poll loop is now stuck inside notifier.Send.
	time.Sleep(150 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Shutdown took %v, want to return once its own ctx expired rather than wait forever on the stuck notifier", elapsed)
	}
	if a.pollStopped.Load() {
		t.Fatal("the poll loop is reported stopped, but its notifier is still blocked — the test's own premise is broken")
	}
}

// TestRegistry_WiredIntoServer checks step 4's wiring: New builds a
// non-nil Registry, exposed through App.Registry, and the same instance
// backs the POST /v1/register route New mounted on Server().V1 — a real
// registration request over the App's own TLS listener gets the protocol's
// 202, not the JSON error envelope's "no such route".
func TestRegistry_WiredIntoServer(t *testing.T) {
	a, clientTLS := newTestApp(t)
	if a.Registry() == nil {
		t.Fatal("Registry() = nil, want a constructed *registry.Registry")
	}

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	body := bytes.NewBufferString(`{"pairingCode":"ABCDEF","hostname":"h","version":"0.1.0","publicIp":"203.0.113.5"}`)
	resp, err := client.Post("https://"+addr+"/v1/register", "application/json", body)
	if err != nil {
		t.Fatalf("POST /v1/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
}

// TestProbeURL checks spec §5's probeUrl is built from bootstrap config —
// the public IP plus the listener's own port, and 443 when Listen names no
// usable port at all.
func TestProbeURL(t *testing.T) {
	cases := []struct {
		name     string
		publicIP string
		listen   string
		want     string
	}{
		{name: "explicit port", publicIP: "203.0.113.10", listen: "0.0.0.0:8443", want: "https://203.0.113.10:8443/v1/probe"},
		{name: "default https port", publicIP: "203.0.113.10", listen: "0.0.0.0:443", want: "https://203.0.113.10:443/v1/probe"},
		{name: "no port at all", publicIP: "203.0.113.10", listen: "0.0.0.0", want: "https://203.0.113.10:443/v1/probe"},
		{name: "empty listen", publicIP: "203.0.113.10", listen: "", want: "https://203.0.113.10:443/v1/probe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeURL(&config.Config{PublicIP: tc.publicIP, Listen: tc.listen})
			if got != tc.want {
				t.Fatalf("probeURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConfigs_WiredIntoServer checks step 5's wiring end to end: App builds
// a ConfigBuilder, exposes it through Configs(), and GET /v1/config is
// mounted behind the client-token middleware on the App's own listener. A
// mon-server that has never reached a panel has no document to serve, so
// the authenticated fetch is the spec §5 cold-start answer — 503
// config_not_ready — rather than a 404 from an unmounted route.
func TestConfigs_WiredIntoServer(t *testing.T) {
	a, clientTLS := newTestApp(t)
	if a.Configs() == nil {
		t.Fatal("Configs() = nil, want a constructed *registry.ConfigBuilder")
	}

	ctx := context.Background()
	reg := a.Registry()
	out, err := reg.Register(ctx, registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "h", RemoteIP: "198.51.100.7"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Approve(ctx, out.RequestID, registry.ApproveInput{Name: "ams-1"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := reg.Poll(ctx, out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if poll.Token == "" {
		t.Fatal("Poll handed out no client token")
	}

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/v1/config", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+poll.Token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/config: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("config_not_ready")) {
		t.Fatalf("body = %s, want the config_not_ready error code", body)
	}
}

// TestState_WiredIntoServer checks step 6's wiring the same way: App builds
// the state engine, exposes it through State(), and POST /v1/heartbeat is
// mounted behind the client-token middleware on the App's own listener. A
// real approved token goes over the real TLS listener, and the answer is
// the protocol §5.3 body with the cycle acknowledged — which also proves
// the engine reached the same database the registry approved into.
func TestState_WiredIntoServer(t *testing.T) {
	a, clientTLS := newTestApp(t)
	if a.State() == nil {
		t.Fatal("State() = nil, want a constructed *state.Engine")
	}

	ctx := context.Background()
	reg := a.Registry()
	out, err := reg.Register(ctx, registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "h", RemoteIP: "198.51.100.8"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Approve(ctx, out.RequestID, registry.ApproveInput{Name: "ams-1"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := reg.Poll(ctx, out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	body := `{"monClientId":"ams-1","configRevision":"","client":{"version":"0.1.0"},` +
		`"cycles":[{"seq":42,"ts":0,"unverified":false,"results":[]}]}`
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/heartbeat", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+poll.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/heartbeat: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, respBody)
	}

	var got state.HeartbeatResponse
	if err := json.Unmarshal(respBody, &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, respBody)
	}
	if got.AckSeq != 42 || got.ServerTs == 0 {
		t.Fatalf("body = %+v, want the cycle acknowledged with a server timestamp", got)
	}

	mc, err := reg.Get(ctx, "ams-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if mc.State != store.MonClientOnline {
		t.Fatalf("mon-client state = %s, want ONLINE after a heartbeat over the listener", mc.State)
	}
}

// TestEvents_FirstHeartbeatReachesThePanel is decision #50's end-to-end
// regression check: a freshly approved mon-client's first heartbeat files a
// mon_client ONLINE transition, and the next poll cycle delivers it to a
// panel stub that validates events against the contract's dictionary. While
// mon-server sent that transition "from NEVER" the panel rejected it, so the
// panel never learned the box had come up.
func TestEvents_FirstHeartbeatReachesThePanel(t *testing.T) {
	a, clientTLS := newTestApp(t)
	stub := paneltest.NewStub(t)
	set := store.DefaultSettings()
	set.PanelURL = stub.URL()
	set.MonToken = stub.Token()
	if err := a.deps.Store.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	ctx := context.Background()
	reg := a.Registry()
	out, err := reg.Register(ctx, registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "h", RemoteIP: "198.51.100.10"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Approve(ctx, out.RequestID, registry.ApproveInput{Name: "ams-1"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := reg.Poll(ctx, out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	body := `{"monClientId":"ams-1","configRevision":"","client":{"version":"0.1.0"},` +
		`"cycles":[{"seq":1,"ts":0,"unverified":false,"results":[]}]}`
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/heartbeat", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+poll.Token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/heartbeat: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, respBody)
	}

	if err := a.Poller().Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if rej := stub.RejectedEvents(); len(rej) != 0 {
		t.Fatalf("panel rejected %+v, want every event mon-server sends inside the contract's dictionary", rej)
	}
	var online bool
	for _, ev := range stub.Events() {
		if ev.Kind == "mon_client" && ev.MonClientID == "ams-1" && ev.To == store.MonClientOnline {
			online = ev.From == ""
		}
	}
	if !online {
		t.Fatalf("panel events = %+v, want mon_client ams-1 \"\" → ONLINE", stub.Events())
	}
}

// TestStats_WiredIntoServer checks step 7's wiring end to end, on the App's
// own listener and against a real panel stub: a heartbeat's probe results
// become a 5-minute bucket (spec §7.4), and once the bucket has closed —
// five minutes of window plus the one-minute grace, stepped through on the
// Fake clock — the next poll cycle sends it to POST /stats (spec §4 step 4).
// Nothing here reaches into the buckets directly, so it fails if either
// half of the wiring (engine Stats sink, poller StatsFlusher) is missing.
func TestStats_WiredIntoServer(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(time.Date(2025, 9, 12, 10, 0, 0, 0, time.UTC))
	cfg := &config.Config{
		Listen:   "127.0.0.1:0",
		PublicIP: "127.0.0.1",
		DataDir:  dir,
		TLS:      config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}
	a, err := New(Deps{Cfg: cfg, Store: st, Clock: clk, Notifier: tg.Nop{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test cert")
	}
	clientTLS := &tls.Config{RootCAs: pool}

	// A panel with one xray inbound and its probe material, so the config
	// builder has a target to hand the mon-client at all.
	stub := paneltest.NewStub(t)
	stub.SetInbounds([]panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Tag: "inbound-443", Protocol: "vless", Port: 443, Enable: true}})
	stub.SetItems(store.PathDirect, []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe"}})
	set := store.DefaultSettings()
	set.PanelURL = stub.URL()
	set.MonToken = stub.Token()
	if err := st.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	ctx := context.Background()
	reg := a.Registry()
	out, err := reg.Register(ctx, registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "h", RemoteIP: "198.51.100.9"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Approve(ctx, out.RequestID, registry.ApproveInput{Name: "ams-1", Paths: []string{store.PathDirect, store.PathHops}}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := reg.Poll(ctx, out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// One cycle so the poller has probe material and the config builder has
	// given this mon-client its target; without it the heartbeat's results
	// are stripped as unknown targets (spec §7.1).
	if err := a.Poller().Poll(ctx); err != nil {
		t.Fatalf("first Poll: %v", err)
	}

	body := `{"monClientId":"ams-1","configRevision":"","client":{"version":"0.1.0"},"cycles":[` +
		`{"seq":1,"ts":` + strconv.FormatInt(clock.Ms(clk.Now()), 10) + `,"unverified":false,"results":[` +
		`{"inboundKind":"xray","inboundId":12,"path":"direct","ok":true,"tlsMs":42}]}]}`
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/heartbeat", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+poll.Token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/heartbeat: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, respBody)
	}

	if got := len(stub.Stats()); got != 0 {
		t.Fatalf("panel already holds %d stat rows, but the bucket has not closed yet", got)
	}

	// Five minutes of window plus the one-minute grace (spec §7.4).
	clk.Advance(6 * time.Minute)
	if err := a.Poller().Poll(ctx); err != nil {
		t.Fatalf("second Poll: %v", err)
	}

	stats := stub.Stats()
	if len(stats) != 1 {
		t.Fatalf("panel holds %d stat rows (%+v), want the one closed bucket", len(stats), stats)
	}
	got := stats[0]
	if got.MonClientId != "ams-1" || got.InboundKind != store.InboundKindXray || got.InboundId != 12 ||
		got.Path != store.PathDirect || got.NOk != 1 || got.NFail != 0 {
		t.Fatalf("stat = %+v, want the heartbeat's one successful direct probe", got)
	}
	if got.LatencyAvgMs == nil || *got.LatencyAvgMs != 42 {
		t.Fatalf("latencyAvgMs = %v, want 42 from the probe's tlsMs", got.LatencyAvgMs)
	}
}

// TestProbe_WiredIntoServer checks step 8's wiring end to end: GET
// /v1/probe is mounted behind the client-token middleware on the App's own
// listener and answers spec §7.5's echo, using the same real, approved
// token TestConfigs_WiredIntoServer uses for /v1/config.
func TestProbe_WiredIntoServer(t *testing.T) {
	a, clientTLS := newTestApp(t)

	ctx := context.Background()
	reg := a.Registry()
	out, err := reg.Register(ctx, registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "h", RemoteIP: "198.51.100.7"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Approve(ctx, out.RequestID, registry.ApproveInput{Name: "ams-1"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := reg.Poll(ctx, out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if poll.Token == "" {
		t.Fatal("Poll handed out no client token")
	}

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/v1/probe?target=xray:12:proxy&n=abc123", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+poll.Token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/probe: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"nonce":"abc123"`)) {
		t.Fatalf("body = %s, want the echoed nonce", body)
	}
}

// TestPerHop_WiredEndToEnd walks decision #61 through the wired App against
// a contract-3 panel stub: a mon-client on paths direct and hops probes
// direct and proxy while the panel has no chain; once a hop is probed, proxy's
// target is removed without an event and the hop's target takes its place;
// switching the active edge changes neither the config revision nor any
// target; a hop that leaves takes its targets with it, silently.
func TestPerHop_WiredEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC))
	cfg := &config.Config{
		Listen: "127.0.0.1:0", PublicIP: "127.0.0.1", DataDir: dir,
		TLS: config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}
	a, err := New(Deps{Cfg: cfg, Store: st, Clock: clk, Notifier: tg.Nop{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	link := func(host string) []panel.ProbeItem {
		return []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe@" + host + ":443"}}
	}
	stub := paneltest.NewStub(t)
	stub.SetInbounds([]panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Protocol: "vless", Port: 443, Enable: true}})
	stub.SetOverride(true, "a.example.net")
	stub.SetItems(store.PathDirect, link("real.example.net"))
	stub.SetItems(store.PathProxy, link("a.example.net"))
	stub.SetItems("edge:edge-a", link("a.example.net"))
	stub.SetItems("edge:edge-b", link("b.example.net"))
	set := store.DefaultSettings()
	set.PanelURL = stub.URL()
	set.MonToken = stub.Token()
	set.RealHost = "real.example.net"
	if err := st.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	ctx := context.Background()
	reg := a.Registry()
	out, err := reg.Register(ctx, registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "h", RemoteIP: "198.51.100.9"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := reg.Approve(ctx, out.RequestID, registry.ApproveInput{Name: "ams-1", Paths: []string{store.PathDirect, store.PathHops}}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	seq := int64(0)
	beat := func(paths ...string) {
		t.Helper()
		mc, err := reg.Get(ctx, "ams-1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		seq++
		var results []state.Result
		for _, p := range paths {
			results = append(results, state.Result{InboundKind: store.InboundKindXray, InboundID: 12, Path: p, Ok: true})
		}
		clk.Advance(time.Minute)
		if _, err := a.State().Heartbeat(ctx, mc, &state.HeartbeatRequest{
			MonClientID: "ams-1", Client: state.ClientInfo{Version: "0.1.0"},
			Cycles: []state.Cycle{{Seq: seq, Ts: clock.Ms(clk.Now()), Results: results}},
		}); err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
	}
	poll := func() {
		t.Helper()
		if err := a.Poller().Poll(ctx); err != nil {
			t.Fatalf("Poll: %v", err)
		}
	}
	targets := func() string {
		t.Helper()
		var rows []store.Target
		if err := st.DB.Order("path").Find(&rows).Error; err != nil {
			t.Fatalf("read targets: %v", err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Path+"="+r.State)
		}
		return strings.Join(out, ",")
	}
	revision := func() string {
		t.Helper()
		rev, err := a.Configs().CurrentRevision(ctx, "ams-1")
		if err != nil {
			t.Fatalf("CurrentRevision: %v", err)
		}
		return rev
	}

	poll()
	beat(store.PathDirect, store.PathProxy)
	if got := targets(); got != "direct=UP,proxy=UP" {
		t.Fatalf("targets without a chain = %s", got)
	}
	if snap := stub.Ensured(); len(snap) == 0 || strings.Join(snap[0][0].Paths, ",") != "direct,hops" {
		t.Fatalf("ensure snapshot = %+v, want ams-1 with paths direct,hops", snap)
	}
	poll()
	sent := len(stub.Events())

	hops := []paneltest.Hop{
		{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "joined"},
		{Name: "edge-b", Role: "edge", Host: "b.example.net", State: "joined"},
	}
	stub.SetChain("edge-a", hops)
	poll()
	if got := targets(); got != "direct=UP" {
		t.Fatalf("targets once hops are probed = %s, want proxy removed", got)
	}
	beat(store.PathDirect, "edge:edge-a", "edge:edge-b")
	if got := targets(); got != "direct=UP,edge:edge-a=UP,edge:edge-b=UP" {
		t.Fatalf("targets on the chain = %s", got)
	}
	poll()
	for _, ev := range stub.Events()[sent:] {
		if ev.Path == store.PathProxy {
			t.Fatalf("an event was sent for the retired proxy target: %+v", ev)
		}
	}
	sent = len(stub.Events())

	// The active edge switches: new panel revision, same config, no events.
	before := revision()
	stub.SetChain("edge-b", hops)
	poll()
	beat(store.PathDirect, "edge:edge-a", "edge:edge-b")
	poll()
	if after := revision(); after != before {
		t.Fatalf("config revision %s → %s on an active edge switch, want unchanged", before, after)
	}
	if evs := stub.Events()[sent:]; len(evs) != 0 {
		t.Fatalf("an active edge switch produced events: %+v", evs)
	}

	// edge-a starts draining: its target goes, silently.
	stub.SetChain("edge-b", []paneltest.Hop{
		{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "draining"},
		hops[1],
	})
	poll()
	if got := targets(); got != "direct=UP,edge:edge-b=UP" {
		t.Fatalf("targets after edge-a left = %s", got)
	}
	poll()
	if evs := stub.Events()[sent:]; len(evs) != 0 {
		t.Fatalf("a hop leaving produced events: %+v", evs)
	}
}
