// Package app wires together everything a running mon-server process needs
// (architecture brief §2: "wiring: New(cfg, deps) → Run(ctx) with listener +
// jobs"). This step only builds the HTTPS listener and the api.Server it
// serves; every later step (registry polling, the state machine's periodic
// jobs, admin sessions) adds its piece to New and to the handlers it wires
// onto Server().V1 / Server().Admin, without changing this package's shape.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/admin"
	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx"
)

// ShutdownGrace is how long Run (and cmd/mon-server, which builds its own
// shutdown context from this same constant so a second SIGINT/SIGTERM can
// be handled outside it — see cli.go's runRun) waits for in-flight handlers
// to finish once asked to stop, before giving up (spec §2: "graceful
// shutdown: дождаться текущих обработчиков"); SQLite writes are already
// durable by the time a handler returns, so this only needs to cover
// request latency, not any buffered-but-unwritten state.
const ShutdownGrace = 10 * time.Second

// readTimeout bounds how long the public listener will wait for a client to
// finish sending an entire request (headers already bounded separately by
// ReadHeaderTimeout below): a client that sends headers and then stalls the
// body indefinitely must not tie up a goroutine forever.
const readTimeout = 30 * time.Second

// writeTimeout bounds how long the public listener will wait while writing
// a response. 60s is generous for any handler this step or the next few
// steps add, and is deliberately long enough to cover a future heartbeat
// handler's 20s probe budget (spec §5: budgetMs default 20000) plus margin,
// so that step doesn't also need to touch this timeout.
const writeTimeout = 60 * time.Second

// offlineSweep is how often the mon-client liveness job runs (spec §7.3:
// "проверяет job раз в 20 с"). It is deliberately much shorter than the
// silence it detects (clientOfflineAfter x intervalMs, three minutes by
// default): the tick only bounds how late an OFFLINE verdict is, never how
// early.
const offlineSweep = 20 * time.Second

// defaultHTTPSPort is the port probeURL assumes when cfg.Listen names none
// — the port an https:// URL leaves implicit.
const defaultHTTPSPort = "443"

// retentionInterval is how often the hourly cleanup job runs (spec §3:
// "Ретеншн (job раз в час)"; issue #13). An hour is short next to every
// window it prunes against (24h/7d), so the job never lets a backlog grow
// large enough for its own batching (store.retentionBatch) to matter much.
const retentionInterval = time.Hour

// retentionFirstRun is how long Start waits before the very first
// retention pass, rather than running it immediately at boot. A fresh
// process has nothing to clean up yet — every table it prunes only grows
// rows over hours or days — so running immediately would only cost a few
// idle SELECTs during the busiest moment of a cold start (TLS handshake,
// first panel poll). Waiting a minute lets that settle first; it is not
// spec-mandated, just a boot-time courtesy, and does not affect when the
// job first has anything to actually delete.
const retentionFirstRun = time.Minute

// Deps are every collaborator App needs, injected rather than constructed
// internally so tests can pass a temp-file store, a Fake clock and a
// tg.Recorder instead of the real things (architecture brief §4: "no global
// mutable state ... dependencies are injected via constructors").
type Deps struct {
	Cfg      *config.Config
	Store    *store.Store
	Clock    clock.Clock
	Notifier tg.Notifier
}

// App is a fully wired mon-server process: the gin engine, the TLS config
// it serves, the http.Server that ties them to a listener, and (in
// "acme-ip" mode) the tlsx.Manager that owns certmagic's lifecycle. Its
// fields are unexported because the only supported way to reach the engine
// from outside is Server(), which later steps' tests use to register
// handlers and this step's own tests use to register a probe route.
type App struct {
	deps Deps

	server *api.Server
	http   *http.Server
	mgr    *tlsx.Manager

	// registry is step 4's registration desk and mon-client directory,
	// exposed through Registry() so later steps can wire their hooks.
	registry *registry.Registry

	// engine is step 6's heartbeat + state machine, exposed through
	// State() so step 7's buckets and step 8's probe handler can reach the
	// same instance.
	engine *state.Engine

	// configs is step 5's per-mon-client config builder, exposed through
	// Configs() so step 10's Settings Save can call RebuildAll when a probe
	// parameter or realHost changes (spec §9.4).
	configs *registry.ConfigBuilder

	// ctx/cancel is App's own lifetime context, independent of whatever
	// signal-driven ctx a caller passes to Run: it exists purely so
	// Shutdown can cancel mgr's in-flight certmagic retries (ManageAsync
	// spawns goroutines that watch this ctx) without needing the caller's
	// ctx, which by the time Shutdown runs is already Done.
	ctx    context.Context
	cancel context.CancelFunc

	// ln is the listener bound by Start, kept so Run can detect the
	// accept loop dying out from under it (e.g. the fd being closed by
	// something other than Shutdown) instead of parking forever on a
	// server that has stopped serving. Only Start (and, transitively,
	// Run, which always calls Start itself) ever writes it; readers other
	// than those two must go through lnCh below rather than reading this
	// field directly, since it is otherwise unsynchronized.
	ln net.Listener
	// lnCh publishes ln once Start has bound it: buffered so Start never
	// blocks sending to it, and safe for a concurrent reader (namely this
	// package's own tests, which call Run in a goroutine and need to reach
	// in and close the listener out from under it) to receive from without
	// racing Start's write to ln.
	lnCh chan net.Listener
	// serveErrCh receives ServeTLS's terminal error exactly once. It is
	// buffered so the serving goroutine never blocks sending to it even
	// when nothing is listening (the common case: Shutdown was the cause,
	// and Run has already moved on to its own shutdown sequence).
	serveErrCh chan error

	poller *panel.Poller

	// pollCancel stops the poll loop; pollWG is how Shutdown joins it, so
	// that a process (or a -race test) never outlives its own goroutine.
	// pollStopped is only there for tests to observe the join.
	pollCancel  context.CancelFunc
	pollWG      sync.WaitGroup
	pollStopped atomic.Bool

	// offlineCancel/offlineWG are the same pair for the 20s mon-client
	// liveness job (spec §7.3): a job that writes to the database must be
	// joined by Shutdown for the same reason the poll loop is.
	offlineCancel  context.CancelFunc
	offlineWG      sync.WaitGroup
	offlineStopped atomic.Bool

	// retentionCancel/retentionWG are the same pair again for the hourly
	// retention job (spec §3, issue #13): it too writes to (deletes from)
	// the database, so Shutdown must join it before the process considers
	// itself stopped, exactly like the poller and the offline sweep.
	retentionCancel  context.CancelFunc
	retentionWG      sync.WaitGroup
	retentionStopped atomic.Bool
}

// New builds an App from cfg and deps: the TLS config and (for "acme-ip") a
// tlsx.Manager (internal/tlsx, per cfg.Cfg.TLS.Mode), and the gin engine
// (internal/api), joined by an http.Server with the timeouts a public
// listener needs against slow or hostile clients. New has no network side
// effects at all — tlsx.Build is pure — though "acme-ip" mode does start a
// certmagic cache maintenance goroutine as a side effect of constructing
// its Manager (no network I/O, just in-process bookkeeping). Opening the
// listening socket and asking the Manager to actually obtain a certificate
// are both Start's job, not New's: see Start and tlsx.Manager.Manage for
// why that split matters (spec §2: cold boot must not block on ACME).
func New(d Deps) (*App, error) {
	return newApp(d, readTimeout, writeTimeout)
}

// newApp is New's real body, parameterised over the read/write timeouts so
// this package's own tests can install a short read timeout and prove a
// client that stalls mid-body gets disconnected, without sleeping for the
// full 30s production value. New is the only exported entry point; this
// stays unexported.
func newApp(d Deps, readTimeout, writeTimeout time.Duration) (*App, error) {
	if d.Cfg == nil {
		return nil, errors.New("app: nil Cfg")
	}

	tlsCfg, mgr, err := tlsx.Build(d.Cfg.TLS, d.Cfg.DataDir, d.Cfg.PublicIP)
	if err != nil {
		return nil, fmt.Errorf("app: tls: %w", err)
	}

	srv := api.New()

	// The poll cycle needs nothing but the store, the clock and the
	// notifier to start: it reads the panel URL and token from settings
	// every minute, so a mon-server that has not been configured yet comes
	// up and starts polling the moment an operator fills the settings page
	// in (spec §4). Snapshot/Configs/Inbounds/Stats stay nil until the
	// steps that implement them wire themselves in through Poller().
	poller := panel.NewPoller(panel.PollerDeps{
		Store:    d.Store,
		Clock:    d.Clock,
		Notifier: d.Notifier,
	})

	// Step 4's registration desk: mounted here (not inside api.New) because
	// it needs the store and clock this function already has in hand, and
	// because api.New must stay usable on its own in api's own tests
	// without a store.
	reg := registry.New(d.Store, d.Clock)
	api.RegisterRoutes(srv.V1, reg)

	// Step 5's config builder: it reads the panel material off the poller
	// and hands finished documents to GET /v1/config (spec §5). The two
	// directions are wired here rather than in either package because each
	// needs the other — the poller rebuilds configs on a material change,
	// the builder reads the poller's material — and internal/app is the one
	// place that may know about both.
	configs := registry.NewConfigBuilder(d.Store, d.Clock, poller, probeURL(d.Cfg))
	poller.SetConfigs(configs)
	poller.SetSnapshot(reg.SnapshotSource())
	// Step 6's state engine: it answers heartbeats, owns the target state
	// machine and asks the poller who should send a transition to Telegram
	// (spec §4.1). The poller hands it the panel's inbound list so a
	// disabled or vanished inbound pauses its targets (spec §4 step 3), and
	// the registry tells it when an administrator disables a mon-client
	// (spec §6).
	//
	// Step 7's 5-minute buckets sit on both sides of the same seam: the
	// engine hands them every accepted cycle (spec §7.4) and the poller
	// flushes the closed ones to POST /stats at the end of each cycle (§4
	// step 4). They are built here, before the engine, because the engine
	// takes them as a dependency.
	buckets := state.NewBuckets(d.Store, d.Clock)
	engine := state.New(state.Deps{
		Store:     d.Store,
		Clock:     d.Clock,
		Notifier:  d.Notifier,
		PanelDown: poller.PanelDown,
		Configs:   configs,
		Stats:     buckets,
	})
	poller.SetInbounds(engine)
	poller.SetPathSync(engine)
	poller.SetStats(buckets)
	// The panel asks for a state resync in its POST /stats answer (decision
	// SBKubric/sane-3x-ui#151); the buckets read the answer, the engine
	// files the events.
	buckets.SetResyncer(engine)
	reg.SetHooks(registry.Hooks{
		PathsChanged: configs.Rebuild,
		Approved:     configs.Rebuild,
		Disabled:     engine.MonClientDisabled,
		// Decision #51 §2: a revoke goes through the state machine — the
		// mon_client OFFLINE event and the targets' move to UNKNOWN share
		// the revoke's transaction.
		Revoked: engine.MonClientRevoked,
	})
	api.ConfigRoutes(srv.V1, reg, configs)
	api.HeartbeatRoutes(srv.V1, reg, engine)

	// Step 8's tunnel probe (spec §7.5, protocol §5.2): it shares the same
	// config builder as GET /v1/config, since "is this target one I handed
	// out" is exactly ConfigBuilder.TargetKeys.
	api.ProbeRoutes(srv.V1, reg, configs, d.Store)

	// Step 10's admin UI: the four surfaces of spec §9 plus /admin/api/*,
	// mounted on the group api.New already made for them. It gets the same
	// registry, config builder and poller the rest of the process uses —
	// the UI is a client of mon-server's domain, never a second copy of it
	// — and its own Telegram client for the Settings page's "Send test",
	// which sends with the credentials typed into the form rather than the
	// saved ones (spec §9.4).
	admin.New(admin.Deps{
		Store:    d.Store,
		Clock:    d.Clock,
		Registry: reg,
		Configs:  configs,
		Poller:   poller,
		Cfg:      d.Cfg,
		Telegram: tg.NewHTTP(nil, ""),
	}).Mount(srv.Admin)

	httpSrv := &http.Server{
		Handler:   srv.Engine,
		TLSConfig: tlsCfg,
		// A client that dawdles sending headers ties up a goroutine
		// indefinitely without this; 10s is generous for any real
		// mon-client or admin browser on a working network.
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds the rest of the request (the body) once headers are in;
		// see the readTimeout doc comment.
		ReadTimeout: readTimeout,
		// Bounds writing the response; see the writeTimeout doc comment.
		WriteTimeout: writeTimeout,
		// Keep-alives beyond this are pure resource cost with connections
		// nobody's using; mon-clients heartbeat once a minute over new
		// connections, not long-lived ones, so 120s only bounds idle admin
		// UI connections.
		IdleTimeout: 120 * time.Second,
		ErrorLog:    slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &App{
		deps:       d,
		server:     srv,
		http:       httpSrv,
		mgr:        mgr,
		poller:     poller,
		engine:     engine,
		registry:   reg,
		configs:    configs,
		ctx:        ctx,
		cancel:     cancel,
		lnCh:       make(chan net.Listener, 1),
		serveErrCh: make(chan error, 1),
	}, nil
}

// Start opens the listener on cfg.Listen ("127.0.0.1:0" works in tests, and
// resolves the actual ephemeral port so the test can dial it), asks mgr to
// start managing a certificate (a no-op in "files" mode: mgr is nil, and
// every Manager method tolerates that), and begins serving TLS in a
// background goroutine, returning the bound address.
//
// mgr.Manage is called only now — after the socket is bound — and it is
// asynchronous (tlsx.Manager.Manage uses ManageAsync, not ManageSync): it
// queues certmagic's work and returns immediately, so Start does not block
// on Let's Encrypt being reachable. The listener starts accepting
// connections right away; any handshake that lands before the first
// certificate issuance completes will fail, which is the correct trade-off
// against a supervisor that restart-loops a process that blocked cold boot
// on ACME (spec §2).
//
// Start returns as soon as the socket is open and mgr.Manage has been
// queued — it does not wait for the serve goroutine, since
// http.Server.Serve* blocks until Shutdown.
func (a *App) Start() (addr string, err error) {
	ln, err := net.Listen("tcp", a.deps.Cfg.Listen)
	if err != nil {
		return "", fmt.Errorf("app: listen %s: %w", a.deps.Cfg.Listen, err)
	}
	a.ln = ln
	a.lnCh <- ln
	addr = ln.Addr().String()

	if err := a.mgr.Manage(a.ctx); err != nil {
		_ = ln.Close()
		return "", fmt.Errorf("app: manage tls: %w", err)
	}

	pollCtx, cancel := context.WithCancel(context.Background())
	a.pollCancel = cancel
	a.pollWG.Add(1)
	go func() {
		defer a.pollWG.Done()
		defer a.pollStopped.Store(true)
		a.poller.Run(pollCtx)
	}()

	offlineCtx, offlineCancel := context.WithCancel(context.Background())
	a.offlineCancel = offlineCancel
	a.offlineWG.Add(1)
	go func() {
		defer a.offlineWG.Done()
		defer a.offlineStopped.Store(true)
		a.runOfflineSweep(offlineCtx)
	}()

	retentionCtx, retentionCancel := context.WithCancel(context.Background())
	a.retentionCancel = retentionCancel
	a.retentionWG.Add(1)
	go func() {
		defer a.retentionWG.Done()
		defer a.retentionStopped.Store(true)
		a.runRetention(retentionCtx)
	}()

	go func() {
		// cert/key args are empty because TLSConfig already carries the
		// certificate (via Certificates for "files", via GetCertificate for
		// "acme-ip") — ServeTLS requires non-empty paths only when it has
		// to load a cert itself.
		serveErr := a.http.ServeTLS(ln, "", "")
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("mon-server: serve", "err", serveErr)
		}
		a.serveErrCh <- serveErr
	}()

	return addr, nil
}

// runOfflineSweep runs the mon-client liveness job until ctx is cancelled
// (spec §7.3). A failed sweep is logged rather than fatal: the next tick
// re-evaluates every mon-client from the database, so a transient SQLite
// error costs at most one tick's latency on an OFFLINE verdict.
//
// The job does not start until the listener can complete a TLS handshake
// (mgr.Ready: at once in "files" mode, once the ACME certificate is cached
// in "acme-ip" mode). That moment is serverReadyAt, and every sweep counts
// a mon-client's silence from no earlier than it (decision #84): a
// heartbeat mon-server was not there to receive is not a missed one.
func (a *App) runOfflineSweep(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-a.mgr.Ready():
	}
	readyAt := a.engine.ServerReady(ctx)

	t := time.NewTicker(offlineSweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.engine.MarkOffline(ctx, readyAt); err != nil {
				slog.Warn("app: marking silent mon-clients offline failed", "err", err)
			}
		}
	}
}

// runRetention runs the hourly cleanup job (spec §3, issue #13) until ctx is
// cancelled: a short delay (retentionFirstRun) before the first pass, since
// a fresh process has nothing yet to clean up, then store.Store.Retention
// every retentionInterval. A failed pass is logged rather than fatal — like
// the offline sweep, the next tick tries again from scratch, so a
// transient SQLite error costs at most one hour's delay in reclaiming
// space, never a stuck process.
func (a *App) runRetention(ctx context.Context) {
	timer := time.NewTimer(retentionFirstRun)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			a.runRetentionOnce(ctx)
			timer.Reset(retentionInterval)
		}
	}
}

// runRetentionOnce runs and logs a single retention pass. It only logs at
// Info when the report says something was actually deleted (RetentionReport.
// Total() > 0): an hourly "deleted nothing" line on every install, most of
// which spend most hours with nothing to prune, would just be noise.
func (a *App) runRetentionOnce(ctx context.Context) {
	report, err := a.deps.Store.Retention(ctx)
	if err != nil {
		slog.Warn("app: retention pass failed", "err", err)
		return
	}
	if report.Total() > 0 {
		slog.Info("app: retention pass",
			"events", report.Events,
			"stats", report.Stats,
			"probeSeen", report.ProbeSeen,
			"requests", report.Requests,
			"sessions", report.Sessions,
			"loginAttempts", report.LoginAttempts,
		)
	}
}

// Shutdown stops the listener from accepting new connections, waits for
// handlers already in flight to finish, up to ctx's deadline (spec §2:
// "graceful shutdown: дождаться текущих обработчиков"), and joins the panel
// poll loop, the offline sweep and the hourly retention job (spec §3).
// Buffers in SQLite are already durable by the time a handler
// returns, so there is nothing else for shutdown to flush; the join is
// about not leaving a goroutine writing to the database after the process
// believes it has stopped. After the HTTP server has finished shutting
// down, it cancels App's own lifetime context (stopping any in-flight
// certmagic retries mgr.Manage queued) and stops mgr's cache maintenance
// goroutine, so a full Shutdown leaves nothing running under -race. It is
// safe to call twice, which is what lets a test register it in t.Cleanup
// and still call it explicitly.
//
// Joining the poll loop is itself bounded by ctx: the poller's own
// pollCycleDeadline keeps one cycle from running forever, but that deadline
// (minutes) can still be far longer than the caller's shutdown ctx
// (cmd/mon-server gives it a fixed grace period). Waiting unboundedly here
// would mean a single hung cycle can keep the whole process from ever
// exiting. If ctx expires first, Shutdown returns anyway and logs that the
// poller was abandoned; the goroutine finishes on its own once the cycle it
// is in actually returns; it does not stay stuck, its cleanup is only late.
func (a *App) Shutdown(ctx context.Context) error {
	if a.pollCancel != nil {
		a.pollCancel()
	}
	if a.offlineCancel != nil {
		a.offlineCancel()
	}
	if a.retentionCancel != nil {
		a.retentionCancel()
	}
	err := a.http.Shutdown(ctx)
	a.cancel()
	a.mgr.Stop()

	joined := make(chan struct{})
	go func() {
		a.pollWG.Wait()
		a.offlineWG.Wait()
		a.retentionWG.Wait()
		close(joined)
	}()
	select {
	case <-joined:
	case <-ctx.Done():
		slog.Warn("app: shutdown context expired before the background jobs stopped; abandoning them")
	}
	return err
}

// Wait blocks until either ctx is cancelled (normally by the caller's
// signal handling — see cmd/mon-server/cli.go) or the accept loop itself
// dies unexpectedly (e.g. its listener fd closed out from under it by
// something other than Shutdown). It returns nil in the former case and the
// accept loop's error in the latter. Wait does not shut anything down
// itself — it only tells the caller it's time to — so cmd/mon-server can
// call it separately from Shutdown and do something (stop relaying OS
// signals, per signal.NotifyContext's documented pattern) in between; Run
// below is the version that does both for callers that don't need that.
func (a *App) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		// Normal path: a signal (or the caller's own cancellation) asked
		// us to stop.
		return nil
	case serveErr := <-a.serveErrCh:
		// ServeTLS returned on its own, before anyone called Shutdown.
		// http.ErrServerClosed would mean Shutdown already ran, which
		// cannot happen on this branch (we haven't called it yet) —
		// treat any other error as the accept loop having died.
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("mon-server: accept loop stopped unexpectedly", "err", serveErr)
			return serveErr
		}
		return nil
	}
}

// Run starts the listener, blocks via Wait until either ctx is cancelled or
// the accept loop dies unexpectedly, and then shuts down with a fixed grace
// period (ShutdownGrace). Without Wait's second case, a dead accept loop
// would leave Run parked on <-ctx.Done() forever, serving nothing and never
// telling anyone. It is the one call a caller needs to run the whole
// service once App is built and does not need to intervene between the
// wait and the shutdown; cmd/mon-server's runRun calls Start, Wait and
// Shutdown separately instead, so it can call signal.NotifyContext's stop
// func between Wait and Shutdown (see its doc comment for why).
func (a *App) Run(ctx context.Context) error {
	addr, err := a.Start()
	if err != nil {
		return err
	}
	slog.Info("listening", "addr", addr, "tls", a.deps.Cfg.TLS.Mode)

	runErr := a.Wait(ctx)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownGrace)
	defer cancel()
	if shutErr := a.Shutdown(shutdownCtx); shutErr != nil && runErr == nil {
		runErr = shutErr
	}
	slog.Info("shutdown complete")
	return runErr
}

// Poller exposes the panel poll loop so later steps can wire their
// collaborators into it — the registry as the snapshot source and config
// builder (steps 4 and 5), the state engine as the inbound sink and stats
// flusher (steps 6 and 7) — and so the state machine can ask PanelDown()
// who should send a transition to Telegram (spec §4.1).
func (a *App) Poller() *panel.Poller {
	return a.poller
}

// Server exposes the underlying api.Server so later steps' tests (and this
// step's own graceful-shutdown test) can register handlers on Server().V1 /
// Server().Admin, or a plain route on Server().Engine, without App exposing
// its whole internal http.Server.
func (a *App) Server() *api.Server {
	return a.server
}

// probeURL is the address mon-clients send tunnel probes to (spec §5:
// "https://<publicIp>:<port>/v1/probe"). It comes from bootstrap config,
// not settings: it names this process's own listener, which is fixed at
// start-up. A Listen with no port at all (or one this process could not
// parse) falls back to 443, the port a public HTTPS URL omits — better a
// config document a mon-client can at least try than one with an empty
// port in it.
func probeURL(cfg *config.Config) string {
	port := defaultHTTPSPort
	if _, p, err := net.SplitHostPort(cfg.Listen); err == nil && p != "" {
		port = p
	}
	return "https://" + net.JoinHostPort(cfg.PublicIP, port) + "/v1/probe"
}

// Configs exposes step 5's config builder so step 10's Settings Save can
// rebuild every mon-client's document when a probe parameter or realHost
// changes (spec §9.4), and so tests can reach the document a mon-client
// would be served.
func (a *App) Configs() *registry.ConfigBuilder {
	return a.configs
}

// State exposes step 6's engine so step 7 can hand it the stats buckets,
// step 8's probe handler can share it, and tests can drive a heartbeat
// without going through the listener.
func (a *App) State() *state.Engine {
	return a.engine
}

// Registry exposes the registration desk / mon-client directory so later
// steps (the state engine, the admin UI) can call into it — Approve,
// Revoke, SetHooks and the rest of internal/registry's exported surface —
// without App growing a method per registry operation.
func (a *App) Registry() *registry.Registry {
	return a.registry
}
