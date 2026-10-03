package panel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

const (
	// pollInterval is the panel poll period (spec §4: "Раз в минуту (panel
	// poll)"). It is also the PANEL_DOWN detector's period: while the panel
	// is unreachable the cycle keeps running and GET /state is what notices
	// it came back (spec §4.1).
	pollInterval = 60 * time.Second

	// maxEventsPerBatch is the contract's event batch limit (§3, spec §4
	// step 4: "батчами ≤ 1000"). The outbox is drained in batches of this
	// size, oldest ts first.
	maxEventsPerBatch = 1000

	// maxMonClientsSnapshot is the contract's cap on one POST /probe/ensure
	// body (§3: "monClients ≤ 200"). The snapshot only ever grows with the
	// registry, so once it passes this the panel would answer every future
	// ensure with a non-retryable 413 forever (PLAUSIBLE finding) — on a
	// fresh panel that means the probe subId is never allocated and
	// monitoring never starts. mon-server truncates rather than let that
	// happen; which entries are dropped is a registry-sizing problem for the
	// operator, logged so it is visible.
	maxMonClientsSnapshot = 200

	// outboxMaxAge is how long an *already-notified* unsent event is worth
	// keeping while the panel is down (spec §4.1: "ограничение 24 ч — старше
	// отбрасываются с логом"). The 24 h buffer exists because a
	// notified=true event's premise is that mon-server has already alerted
	// "via mon-server" (§4.1, §8) — the panel replaying it into its feed is
	// a nice-to-have, so letting it expire is cheap. A notified=false event
	// (queued in normal PANEL_UP operation) has no such premise: nobody has
	// alerted for it yet, and the panel is the only place that transition
	// will ever be recorded, so it must never be pruned by age (PLAUSIBLE
	// finding: pruning it loses the alert forever, reachable via POST
	// /events 5xx-ing for a day while GET /state keeps resetting the
	// PANEL_DOWN failure run).
	outboxMaxAge = 24 * time.Hour

	// pollCycleDeadline bounds one whole Poll cycle. client.go's
	// requestTimeout only bounds a single HTTP round trip; a cycle touches
	// several endpoints (state, ensure, a probe/configs per path, events,
	// stats) and each retries independently to exhaustion (spec §4: up to
	// three retries with 1→2→4s backoff), so a persistently failing panel
	// can stretch one cycle to a few minutes, not the ~10s a reader of
	// requestTimeout's old comment would expect. Without an outer bound nothing
	// stops a pathological cycle from running indefinitely and leaving
	// Poller.Run unable to ever return promptly for shutdown. The deadline is
	// generous compared to that realistic worst case so it never cuts off a
	// cycle that is merely slow.
	pollCycleDeadline = 5 * time.Minute

	// The reasons mon-server stamps on its own panel events (spec §4.1),
	// from the contract's diagnostic vocabulary (§4.6).
	reasonConnRefused = "conn_refused"
	reasonHTTPTimeout = "http_timeout"
	reasonHTTP5xx     = "http_5xx"
	reasonRecovered   = "recovered"

	// The panel event's kind and states (contract §4.6). A panel event
	// carries neither monClientId nor inboundId and is always notified:
	// mon-server has already sent the Telegram message itself, and the
	// panel only writes it to the feed.
	eventKindPanel = "panel"
	statePanelUp   = "PANEL_UP"
	statePanelDown = "PANEL_DOWN"

	// The exact Telegram texts spec §8 fixes for the messages mon-server
	// sends on its own behalf.
	msgPanelRejects     = "panel rejects monitoring token or monitoring is disabled"
	msgPanelUnreachable = "panel unreachable"
	msgPanelBackFmt     = "panel back, %d events resent"

	// msgPanelBadBody is what mon-server sends when a 200 answers with a
	// body that is not contract JSON (PLAUSIBLE finding): most often a proxy
	// or captive portal sitting in front of the configured panelUrl, not the
	// panel itself.
	msgPanelBadBody = "panel returned a non-contract response (wrong panelUrl or a proxy in front of it?)"

	// codeXrayUnavailable is the panel's answer when the probe set could not
	// be completed because xray is not running (contract §4.3). It is the
	// one 5xx that does not mean "the panel is unreachable": the panel
	// answered, and the next ensure finishes the job (spec §4 step 2).
	codeXrayUnavailable = "xray_unavailable"
)

// SnapshotSource supplies the mon-client registry snapshot POST
// /probe/ensure replaces the panel's cache with (spec §4 step 2), and files
// the panel's answer to it: the pairs of those mon-clients that got no AWG
// probe peer, with the reasons (contract 3 §4.3), which the admin UI shows
// (spec §9.3). internal/registry implements it; the poller treats a nil
// source as an empty registry, so a mon-server with no mon-clients yet still
// ensures the probe set.
type SnapshotSource interface {
	Snapshot(ctx context.Context) ([]MonClientSnapshot, error)
	// SaveUnallocated replaces every mon-client's unallocated pairs with
	// the ones list names (an empty list clears them all). It is called
	// after every successful ensure.
	SaveUnallocated(ctx context.Context, list []Unallocated) error
}

// ConfigBuilder rebuilds every mon-client's config document (spec §5). The
// poller calls it exactly once per material change — a new panel revision
// with configs successfully re-read — and never on an unchanged revision,
// because a rebuild bumps config revisions and makes every mon-client
// re-fetch.
type ConfigBuilder interface {
	RebuildAll(ctx context.Context) error
}

// InboundSync is told the panel's current inbound list on every poll so the
// state machine can pause targets whose inbound was disabled and retire
// targets whose inbound vanished (spec §4 step 3). internal/state
// implements it; what "vanished" means is its decision, not the poller's —
// the poller only reports what GET /state said.
type InboundSync interface {
	SyncInbounds(ctx context.Context, inbounds []Inbound) error
}

// PathSync is told the panel's probed path set whenever a new material is
// accepted (spec §5.1): the targets of a path outside it — a hop that was
// removed, renamed or left joined/legacy, or proxy once the chain has a
// probed hop — are removed without events. internal/state implements it.
type PathSync interface {
	SyncPaths(ctx context.Context, served []string) error
}

// StatsFlusher sends the closed stats buckets at the end of a cycle (spec §4
// step 4). It takes the Client rather than owning one so that there is
// exactly one place — this package — that knows how to reach the panel and
// how to retry.
type StatsFlusher interface {
	Flush(ctx context.Context, c Client) error
}

// Material is everything one panel revision gave mon-server: the revision
// itself, the override and the chain that were in force, the probe set's
// subId and the probe items per path. Step 5 builds each mon-client's
// config document out of it, which is why it is a value: a builder gets a
// snapshot that cannot change under it mid-build (Hops is never written
// after the material is made).
type Material struct {
	Revision string
	// Host is the realHost the direct items were fetched for
	// (?host=, spec §4 step 3). The panel renders the direct links with it
	// but it is not part of the panel's revision, so a material is only
	// current while both the revision and the host still match (decision
	// #51 §4).
	Host       string
	Override   Override
	Chain      *Chain
	ProbeSubID string
	Proxy      []ProbeItem
	Direct     []ProbeItem
	// Hops holds the items of every probed hop by its path, edge:<name> or
	// inner:<name> (spec §5.1); empty on a panel without a chain.
	Hops map[string][]ProbeItem
}

// Chained reports whether the panel has probed hops (spec §5.1): then the
// paths are direct and one per hop, and proxy is not a path at all.
func (m Material) Chained() bool { return len(m.Chain.ProbedHops()) > 0 }

// HopPaths are the probed hops' paths in the panel's order (inner ones from
// the panel outwards, then the edges by name).
func (m Material) HopPaths() []string {
	hops := m.Chain.ProbedHops()
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		out = append(out, h.Path())
	}
	return out
}

// Served is the panel's probed path set (spec §5.1, contract §3): direct
// and a path per probed hop, or — without one — direct and proxy. Proxy is
// in the set with the override off too: its targets are then PAUSED
// override_disabled, not gone, because the path itself still exists.
func (m Material) Served() []string {
	if m.Chained() {
		return append([]string{store.PathDirect}, m.HopPaths()...)
	}
	return []string{store.PathDirect, store.PathProxy}
}

// Items is the material of one path. The proxy path has items only on a
// panel without a chain and with the override on (spec §5.1): otherwise
// there is no proxy front to render configs for, and the poller will not
// have fetched any — answering nil here as well keeps a mon-client that asks
// for proxy from silently getting another path's material.
func (m Material) Items(path string) []ProbeItem {
	switch path {
	case store.PathDirect:
		return m.Direct
	case store.PathProxy:
		if m.Chained() || !m.Override.Enabled {
			return nil
		}
		return m.Proxy
	default:
		return m.Hops[path]
	}
}

// PollerDeps are the Poller's collaborators. Everything except Store and
// Clock is optional: the later steps that implement Snapshot, Configs,
// Inbounds and Stats wire themselves in as they land, and until then the
// poller runs the rest of the cycle rather than refusing to start.
type PollerDeps struct {
	Store    *store.Store
	Clock    clock.Clock
	Notifier tg.Notifier

	// Client, when set, is used for every cycle regardless of settings —
	// the injection point for tests driving a paneltest.Stub. In production
	// it is nil and the poller builds its own client from settings.
	Client Client

	Snapshot SnapshotSource
	Configs  ConfigBuilder
	Inbounds InboundSync
	Paths    PathSync
	Stats    StatsFlusher

	// NewClient builds the client for a (panelUrl, monToken, panelCa)
	// triple; rootCAs is the parsed panelCa, nil for the system pool. It
	// defaults to NewHTTPClient with WithRootCAs; a test overrides it to
	// point a real HTTPClient at a stub, or to inject a short timeout.
	NewClient func(baseURL, token string, rootCAs *x509.CertPool) Client
}

// Poller runs the once-a-minute cycle of spec §4 and owns the PANEL_DOWN
// mode of §4.1. One process has exactly one, started by internal/app.
type Poller struct {
	store    *store.Store
	clk      clock.Clock
	notifier tg.Notifier

	snapshot  SnapshotSource
	configs   ConfigBuilder
	inbounds  InboundSync
	paths     PathSync
	stats     StatsFlusher
	fixed     Client
	newClient func(baseURL, token string, rootCAs *x509.CertPool) Client

	mu          sync.Mutex
	client      Client
	clientURL   string
	clientToken string
	clientCA    string

	// unknownAuthority is whether the last panel request that failed
	// without an answer failed on an untrusted certificate (decision #52
	// §1) — the Settings status line then says so and points at panelCa.
	// Any success clears it; so does any other kind of failure, which then
	// is the more current story.
	unknownAuthority bool

	material     Material
	haveMaterial bool
	// chain is the chain of the last GET /state from a panel on the
	// contract, read on every poll rather than with the material: the
	// hops' nextHopCheck changes without moving the panel's revision
	// (decision #100), and the diagnostic sweep reports it as it stands.
	chain *Chain
	// materialStale is RefreshMaterial's invalidation of the cached
	// material (decision #51 §4): set when Settings changes realHost or
	// panelUrl, cleared only when a fresh material has been accepted, so a
	// refresh the panel could not answer is finished by the next poll.
	materialStale bool

	// down, failures, rejected and pendingRecovery are deliberately
	// in-memory only: a restart starts "up" and re-detects the panel on its
	// first cycle, which costs at most one minute and one duplicate
	// PANEL_DOWN event (the panel deduplicates events by id, and a fresh
	// PANEL_DOWN after a restart is honest — this process has not in fact
	// reached the panel yet). Persisting it would buy nothing and add a
	// state that could disagree with reality after a long shutdown.
	down            bool
	failures        int
	rejected        bool
	pendingRecovery bool

	// recoverySent is the running total of outbox rows the panel has
	// accepted since pendingRecovery was set, accumulated across as many
	// cycles as the drain takes (CONFIRMED finding: a retryable PostEvents
	// failure mid-drain returns before finishRecovery while pendingRecovery
	// stays set, so without this the next cycle's "panel back, N events
	// resent" would only count its own batches, not the whole recovery).
	recoverySent int

	// badBodyNotified latches the "non-contract response" message (spec §4,
	// PLAUSIBLE finding) to once per spell, the same way rejected does for a
	// bare 404. markUp clears it, so a later bad body after a good cycle
	// notifies again.
	badBodyNotified bool

	unconfiguredLogged bool

	// contractErr is the refusal of the last GET /state that answered with
	// a contract other than RequiredContract (decisions #80 п. 9, #61 п. 5),
	// nil once a matching panel answers. It is what the Settings status line
	// shows, and it latches the WARN log to once per spell.
	contractErr error

	// running guards Run against being started twice: a second concurrent
	// (or accidental sequential) call would otherwise drive two overlapping
	// poll loops against the same store and client state.
	running atomic.Bool
}

// NewPoller wires a Poller from its dependencies, filling in the defaults
// that let a partially built mon-server still poll: a Nop notifier and the
// real HTTP client factory.
func NewPoller(d PollerDeps) *Poller {
	p := &Poller{
		store:     d.Store,
		clk:       d.Clock,
		notifier:  d.Notifier,
		snapshot:  d.Snapshot,
		configs:   d.Configs,
		inbounds:  d.Inbounds,
		paths:     d.Paths,
		stats:     d.Stats,
		fixed:     d.Client,
		newClient: d.NewClient,
	}
	if p.clk == nil {
		p.clk = clock.Real{}
	}
	if p.notifier == nil {
		p.notifier = tg.Nop{}
	}
	if p.newClient == nil {
		p.newClient = func(baseURL, token string, rootCAs *x509.CertPool) Client {
			return NewHTTPClient(baseURL, token, p.clk, WithRootCAs(rootCAs))
		}
	}
	return p
}

// SetSnapshot sets the registry snapshot source. It exists — as do
// SetConfigs, SetInbounds and SetStats — because the collaborators later
// steps add are constructed after the Poller is (the registry needs the
// poller's material, the state engine needs to ask PanelDown), so they
// cannot all be passed to NewPoller. Call them during wiring, before Run.
func (p *Poller) SetSnapshot(s SnapshotSource) { p.mu.Lock(); p.snapshot = s; p.mu.Unlock() }

// SetConfigs sets the config builder called on every material change.
func (p *Poller) SetConfigs(c ConfigBuilder) { p.mu.Lock(); p.configs = c; p.mu.Unlock() }

// SetInbounds sets the sink for the panel's inbound list.
func (p *Poller) SetInbounds(i InboundSync) { p.mu.Lock(); p.inbounds = i; p.mu.Unlock() }

// SetPathSync sets the sink told the probed path set on every material
// change.
func (p *Poller) SetPathSync(s PathSync) { p.mu.Lock(); p.paths = s; p.mu.Unlock() }

// SetStats sets the stats flusher run at the end of each cycle.
func (p *Poller) SetStats(s StatsFlusher) { p.mu.Lock(); p.stats = s; p.mu.Unlock() }

// PanelDown reports whether mon-server currently considers the panel
// unreachable (spec §4.1). The state machine asks it to decide who sends a
// transition to Telegram: the panel normally, mon-server itself "via
// mon-server" while this is true.
func (p *Poller) PanelDown() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down
}

// UnknownAuthority reports whether the panel's certificate was untrusted on
// the last request that could not reach it (decision #52 §1): the admin UI's
// status line then names the cause and the panelCa setting that cures it,
// instead of a bare "unreachable".
func (p *Poller) UnknownAuthority() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unknownAuthority
}

// ContractError is the refusal message while the panel speaks a contract
// other than RequiredContract (decisions #80 п. 9, #61 п. 5), "" otherwise. The admin
// UI's status line shows it: the poll cycle keeps running but builds no
// targets, and nothing else on the page would explain why.
func (p *Poller) ContractError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.contractErr == nil {
		return ""
	}
	return p.contractErr.Error()
}

// Material returns the last probe material accepted from the panel and
// whether there is any yet. Step 5 builds client configs from it; a false
// second return means no revision has been successfully read since start-up,
// and there is nothing to build from.
func (p *Poller) Material() (Material, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.material, p.haveMaterial
}

// LatestChain is the chain the last GET /state reported, nil before one or
// on a panel without a chain. Unlike Material's, it is refreshed on every
// poll, so the hops' host reachability checks of their next hops
// (Hop.NextHopCheck, decision #100) are as fresh as the panel's. The value
// is never written after it is stored, so a caller may read it freely.
func (p *Poller) LatestChain() *Chain {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.chain
}

// Run drives the cycle every minute until ctx is cancelled, starting with
// one cycle immediately so that a fresh process has panel material without
// waiting a minute for it (contract §7: start is the same cycle as the
// steady state). One process has exactly one Poller and is meant to call
// Run exactly once; a second concurrent call is rejected rather than
// starting a second loop against the same state, because a verifier could
// not otherwise rule out two loops racing on the store and the client cache
// if Start were ever accidentally invoked twice.
//
// Each cycle runs under its own pollCycleDeadline on top of ctx, so a panel
// that answers just slowly enough to keep every retry alive cannot keep this
// call from ever reaching a point where ctx cancellation is checked again —
// see pollCycleDeadline's comment for why a cycle can otherwise run for
// minutes.
func (p *Poller) Run(ctx context.Context) {
	if !p.running.CompareAndSwap(false, true) {
		slog.Error("panel: Run called while a poll loop is already running; ignoring the second call")
		return
	}
	defer p.running.Store(false)

	t := time.NewTicker(pollInterval)
	defer t.Stop()

	for {
		cycleCtx, cancel := context.WithTimeout(ctx, pollCycleDeadline)
		err := p.Poll(cycleCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("panel: poll cycle failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll runs exactly one cycle of spec §4: read state, ensure the probe set,
// re-read configs if the revision moved, then drain the outbox. It reports
// the first error it hit; a later step's failure does not stop the earlier
// ones, because flushing the outbox is worth doing even on a cycle where
// the probe set could not be ensured.
func (p *Poller) Poll(ctx context.Context) error {
	set, err := p.store.LoadSettings()
	if err != nil {
		return fmt.Errorf("panel: load settings: %w", err)
	}
	if set.PanelURL == "" || set.MonToken == "" {
		// Not a failure: a freshly installed mon-server has no panel
		// configured until an operator fills in the settings page (§9.4).
		p.logUnconfigured()
		return nil
	}
	p.clearUnconfigured()
	cl, err := p.clientFor(set)
	if err != nil {
		// Only a hand-edited database gets here (Save validates panelCa).
		// Not a panel failure, so no PANEL_DOWN: nothing was sent.
		return err
	}

	// Step 1: GET /state.
	st, err := cl.State(ctx)
	if err := p.observe(ctx, set, err); err != nil {
		if errors.Is(err, ErrNotFound) {
			// Contract §2: the panel is up and answering — it is refusing
			// us. That is an operator problem (spec §8), not an outage, so
			// no PANEL_DOWN.
			p.notifyRejected(ctx)
			return err
		}
		if errors.Is(err, ErrBadBody) {
			// PLAUSIBLE finding: something answered 200 with a body that is
			// not the contract's JSON — a proxy or captive portal in front
			// of the configured panelUrl, most likely. observe already sent
			// the one-per-spell alert; this is neither the panel refusing us
			// nor it being unreachable, so no PANEL_DOWN and no 24h prune.
			return err
		}
		// The panel is unreachable; the cycle cannot continue, but the 24 h
		// outbox rule still has to be applied (spec §4.1).
		if perr := p.Prune(ctx); perr != nil {
			slog.Warn("panel: pruning the outbox failed", "err", perr)
		}
		return err
	}

	var firstErr error
	fail := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Decisions #80 п. 9, #61 п. 5: the contract must match exactly. An
	// older panel has no chain (or one shared AWG probe peer that the paths
	// and mon-clients steal from each other), a newer one rules this build
	// does not know. Nothing is ensured, synced or read from it, so no
	// target is built; the outbox is still drained, since events and stats
	// have not changed shape.
	if err := p.noteContract(st); err != nil {
		fail(err)
		fail(p.flush(ctx, set, cl))
		return firstErr
	}

	// Step 2: POST /probe/ensure with the full registry snapshot.
	subID := ""
	if st.Probe.SubId != nil {
		subID = *st.Probe.SubId
	}
	// The ensure's own answer carries the revision, and it can differ from
	// the one /state just reported: the first ensure of a fresh panel
	// allocates the probe subId, which is part of the revision document
	// (contract §4.2, §4.3). From here on the ensure's revision is the
	// current one, and it is what /probe/configs answers must match.
	revision := st.Revision
	res, err := cl.ProbeEnsure(ctx, p.snapshotOrEmpty(ctx))
	if err := p.observe(ctx, set, err); err != nil {
		if isXrayUnavailable(err) {
			// Contract §4.3: the set is partially created and the next
			// ensure finishes it. Nothing to do but come back in a minute.
			slog.Info("panel: probe set incomplete, xray unavailable", "err", err)
		} else {
			fail(err)
		}
	} else {
		if res.SubId != "" {
			subID = res.SubId
		}
		if res.Revision != "" {
			revision = res.Revision
		}
		p.saveUnallocated(ctx, res.Unallocated)
	}

	p.applyState(ctx, st, revision)

	// Step 3: re-read the probe material if the revision moved.
	fail(p.refreshMaterial(ctx, set, cl, st, revision, subID))

	// Step 4: drain the outbox, then the stats buckets.
	fail(p.flush(ctx, set, cl))

	return firstErr
}

// saveUnallocated files ensure's unallocated pairs with the registry
// (decisions #80 п. 10, #61 п. 12): those pairs get no AWG item, their AWG
// targets go PAUSED no_probe_link through the config builder, and the
// admin UI shows why. A non-empty list is also a WARN, since it means
// monitoring the operator asked for is not happening.
func (p *Poller) saveUnallocated(ctx context.Context, list []Unallocated) {
	if len(list) > 0 {
		slog.Warn("panel: no AWG probe peer for some mon-client × path pairs (pool_exhausted: the AWG address pool is full; limit: past the panel's monProbePeerLimit)",
			"unallocated", list)
	}
	p.mu.Lock()
	src := p.snapshot
	p.mu.Unlock()
	if src == nil {
		return
	}
	if err := src.SaveUnallocated(ctx, list); err != nil {
		slog.Warn("panel: saving the unallocated probe peers failed", "err", err)
	}
}

// applyState records everything GET /state told us that outlives the cycle:
// the inbound list in panel_inbounds (spec §3) stamped with the revision it
// was seen at, and the same list handed to the state machine. Neither
// failure aborts the cycle — the panel is reachable, which is the part the
// rest of the cycle depends on.
func (p *Poller) applyState(ctx context.Context, st *State, revision string) {
	if err := p.savePanelInbounds(ctx, st, revision); err != nil {
		slog.Warn("panel: saving panel_inbounds failed", "err", err)
	}
	p.mu.Lock()
	sync := p.inbounds
	p.chain = st.Chain
	p.mu.Unlock()
	if sync == nil {
		return
	}
	if err := sync.SyncInbounds(ctx, st.Inbounds); err != nil {
		slog.Warn("panel: syncing inbounds into the state machine failed", "err", err)
	}
}

// savePanelInbounds upserts the inbound list by (inbound_kind, inbound_id),
// stamping seen_revision so a later step can tell which inbounds belong to
// the current revision and which are left over from an older one. Rows are
// never deleted here: deciding what a disappeared inbound means for its
// targets is the state machine's job (spec §4 step 3).
func (p *Poller) savePanelInbounds(ctx context.Context, st *State, revision string) error {
	if len(st.Inbounds) == 0 {
		return nil
	}
	rows := make([]store.PanelInbound, 0, len(st.Inbounds))
	for _, in := range st.Inbounds {
		rows = append(rows, store.PanelInbound{
			InboundKind:  in.Kind,
			InboundId:    in.InboundId,
			Protocol:     in.Protocol,
			Port:         in.Port,
			Remark:       in.Remark,
			Enable:       in.Enable,
			SeenRevision: revision,
		})
	}
	return p.store.DB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "inbound_kind"}, {Name: "inbound_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"protocol", "port", "remark", "enable", "seen_revision"}),
	}).Create(&rows).Error
}

// snapshotOrEmpty asks the registry for the mon-client snapshot, degrading
// to an empty one if there is no registry yet or it fails: ensure's other
// job — creating the probe accounts — matters even on a cycle where the
// registry cannot be read, and the panel's cache is replaced wholesale
// anyway on the next successful one. The result is capped at the contract's
// maxMonClientsSnapshot (§3): sending more would trip a permanent 413 on
// every future ensure, since the snapshot only grows (PLAUSIBLE finding).
func (p *Poller) snapshotOrEmpty(ctx context.Context) []MonClientSnapshot {
	p.mu.Lock()
	src := p.snapshot
	p.mu.Unlock()
	if src == nil {
		return nil
	}
	snap, err := src.Snapshot(ctx)
	if err != nil {
		slog.Warn("panel: reading the mon-client registry failed", "err", err)
		return nil
	}
	if len(snap) > maxMonClientsSnapshot {
		slog.Warn("panel: mon-client snapshot exceeds the contract's limit, truncating",
			"total", len(snap), "limit", maxMonClientsSnapshot, "dropped", len(snap)-maxMonClientsSnapshot)
		snap = snap[:maxMonClientsSnapshot]
	}
	return snap
}

// refreshMaterial implements spec §4 step 3: on a new revision (or on a
// fresh process with no material at all) re-read the probe configs for the
// direct path and for every other path the panel serves (spec §5.1): each
// probed hop of the chain by ?hop=, or — without a chain — the proxy path
// when the override is on. An answer whose revision does not match the
// cycle's current one, or a hop the panel no longer renders (409
// unknown_hop / hop_not_joined), belongs to a configuration mon-server has
// already moved past, so every answer is discarded and the old material
// kept until the next cycle.
func (p *Poller) refreshMaterial(ctx context.Context, set *store.Settings, cl Client, st *State, revision, subID string) error {
	_, err := p.readMaterial(ctx, set, cl, st, revision, subID)
	return err
}

// readMaterial is refreshMaterial reporting whether it accepted a new
// material (and so rebuilt the configs). The material is re-read when there
// is none, when the panel's revision moved, when realHost is no longer the
// host the direct items were fetched for — the panel renders the direct
// links with it, yet it is not part of the revision — and when
// RefreshMaterial invalidated it (decision #51 §4).
func (p *Poller) readMaterial(ctx context.Context, set *store.Settings, cl Client, st *State, revision, subID string) (bool, error) {
	host := realHost(set)

	p.mu.Lock()
	fresh := !p.haveMaterial || p.material.Revision != revision || p.material.Host != host || p.materialStale
	p.mu.Unlock()
	if !fresh {
		return false, nil
	}

	if host == "" {
		slog.Warn("panel: no realHost and no host in panelUrl, skipping probe configs")
		return false, nil
	}

	mat := Material{
		Revision:   revision,
		Host:       host,
		Override:   st.Override,
		Chain:      st.Chain,
		ProbeSubID: subID,
	}
	// foreign collects the revision of every answer that is not the cycle's:
	// one is enough to discard them all.
	foreign := map[string]string{}

	direct, err := cl.ProbeConfigs(ctx, host)
	if err := p.observe(ctx, set, err); err != nil {
		return false, err
	}
	mat.Direct = direct.Items
	if direct.Revision != revision {
		foreign[store.PathDirect] = direct.Revision
	}

	switch hops := st.Chain.ProbedHops(); {
	case len(hops) > 0:
		// Spec §5.1: with probed hops, proxy is not a path — edge:<active>
		// replaces it — and every probed hop is read by name.
		mat.Hops = make(map[string][]ProbeItem, len(hops))
		for _, h := range hops {
			pc, err := cl.HopConfigs(ctx, h.Name)
			if err := p.observe(ctx, set, err); err != nil {
				if IsHopConflict(err) {
					slog.Warn("panel: the chain changed while its probe configs were read, discarding them until the next cycle",
						"hop", h.Name, "err", err)
					return false, nil
				}
				return false, err
			}
			mat.Hops[h.Path()] = pc.Items
			if pc.Revision != revision {
				foreign[h.Path()] = pc.Revision
			}
		}
	case st.Override.Enabled:
		proxy, err := cl.ProbeConfigs(ctx, "")
		if err := p.observe(ctx, set, err); err != nil {
			return false, err
		}
		mat.Proxy = proxy.Items
		if proxy.Revision != revision {
			foreign[store.PathProxy] = proxy.Revision
		}
	}

	if len(foreign) > 0 {
		slog.Warn("panel: discarding probe configs from a foreign revision",
			"current", revision, "foreign", foreign)
		return false, nil
	}

	p.mu.Lock()
	p.material = mat
	p.haveMaterial = true
	p.materialStale = false
	builder := p.configs
	paths := p.paths
	p.mu.Unlock()

	slog.Info("panel: new probe material",
		"revision", revision, "host", host, "direct", len(mat.Direct), "proxy", len(mat.Proxy),
		"hops", len(mat.Hops), "activeEdge", st.Chain.Active(), "override", st.Override.Enabled)

	if builder != nil {
		if err := builder.RebuildAll(ctx); err != nil {
			return true, fmt.Errorf("panel: rebuilding mon-client configs: %w", err)
		}
	}
	// After the rebuild, so no document still names a path whose targets
	// are being removed.
	if paths != nil {
		if err := paths.SyncPaths(ctx, mat.Served()); err != nil {
			return true, fmt.Errorf("panel: removing the targets of paths the panel no longer serves: %w", err)
		}
	}
	return true, nil
}

// ErrContractMismatch marks CheckContract's refusal, for a caller that
// needs to tell it apart from a panel that could not be reached.
var ErrContractMismatch = errors.New("panel: monitoring contract mismatch")

// contractError is CheckContract's refusal. Its text is what the logs, the
// poll cycle's error and the admin UI all show (spec §4 step 1, §9.4), so
// it names both versions and the cure: the side that is behind is the one
// to update.
type contractError struct{ got int }

func (e contractError) Error() string {
	cure := "update the panel"
	if e.got > RequiredContract {
		cure = "update mon-server"
	}
	return fmt.Sprintf("panel speaks monitoring contract %d, mon-server needs %d — %s", e.got, RequiredContract, cure)
}

func (e contractError) Is(target error) bool { return target == ErrContractMismatch }

// CheckContract refuses a GET /state from a panel on any contract but
// RequiredContract, older or newer (decisions #80 п. 9, #61 п. 5: an exact
// match; the panel and mon-server are updated together). A missing field is
// contract 1: the field has been there since the first contract, so its
// absence cannot mean anything newer.
func CheckContract(st *State) error {
	if st.Contract == RequiredContract {
		return nil
	}
	got := st.Contract
	if got < 1 {
		got = 1
	}
	return contractError{got: got}
}

// ErrMaterialNotRefreshed is RefreshMaterial's answer when the panel
// answered but no new material could be accepted (its configs came back
// stamped with another revision, or there is no host to ask for): the
// invalidation stays, and the next poll finishes the job.
var ErrMaterialNotRefreshed = errors.New("panel: probe material not refreshed, the next poll retries")

// ErrPanelNotConfigured is RefreshMaterial's answer before the panel URL
// and token are set: there is no panel to read material from, which is not
// a failure but also not a rebuild.
var ErrPanelNotConfigured = errors.New("panel: panel URL or monitoring token not set")

// RefreshMaterial is decision #51 §4, for Settings Save after realHost or
// panelUrl changed: it invalidates the cached probe material and re-reads
// it right away — GET /state, then GET /probe/configs for each path — and,
// once accepted, rebuilds every mon-client's config (the links are part of
// the config document, so the config revisions change). It uses the saved
// settings, so the caller saves first.
//
// A failure leaves the material invalidated: the ordinary poll re-reads it
// on its next cycle. Running alongside Run's own cycle is harmless — both
// would at worst read the same material and rebuild twice.
func (p *Poller) RefreshMaterial(ctx context.Context) error {
	p.mu.Lock()
	p.materialStale = true
	p.mu.Unlock()

	set, err := p.store.LoadSettings()
	if err != nil {
		return fmt.Errorf("panel: load settings: %w", err)
	}
	if set.PanelURL == "" || set.MonToken == "" {
		return ErrPanelNotConfigured
	}
	cl, err := p.clientFor(set)
	if err != nil {
		return err
	}
	st, err := cl.State(ctx)
	if err := p.observe(ctx, set, err); err != nil {
		return err
	}
	if err := p.noteContract(st); err != nil {
		return err
	}
	subID := ""
	if st.Probe.SubId != nil {
		subID = *st.Probe.SubId
	}
	accepted, err := p.readMaterial(ctx, set, cl, st, st.Revision, subID)
	if err != nil {
		return err
	}
	if !accepted {
		return ErrMaterialNotRefreshed
	}
	return nil
}

// flush drains the outbox to POST /events in ts order, in batches of at most
// maxEventsPerBatch (spec §4 step 4), and then hands the stats buckets to
// the stats flusher. It is also where the PANEL_DOWN buffer's 24 h limit is
// applied and where the "panel back" message is sent, because both are about
// events that have been waiting.
func (p *Poller) flush(ctx context.Context, set *store.Settings, cl Client) error {
	if err := p.Prune(ctx); err != nil {
		slog.Warn("panel: pruning the outbox failed", "err", err)
	}

	for {
		var rows []store.EventOutbox
		err := p.store.DB.WithContext(ctx).
			Where("sent_at IS NULL").
			Order("ts, id").
			Limit(maxEventsPerBatch).
			Find(&rows).Error
		if err != nil {
			return fmt.Errorf("panel: reading the outbox: %w", err)
		}
		if len(rows) == 0 {
			break
		}

		events, ids, dropped := decodeBatch(rows)
		if len(dropped) > 0 {
			slog.Warn("panel: dropping unreadable outbox rows", "ids", dropped)
			if err := p.markDropped(ctx, dropped); err != nil {
				return err
			}
		}
		if len(events) == 0 {
			continue
		}

		res, err := cl.PostEvents(ctx, events)
		if err := p.observe(ctx, set, err); err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) && !apiErr.Retryable() {
				// Contract §3 / spec §4: a 4xx is the panel rejecting the
				// batch itself, and resending it would fail identically
				// every minute forever. Drop it — marked dropped, so the
				// queue cannot wedge behind it — but name the ids, because
				// those transitions are now lost. Since decision #50 the
				// panel answers invalid elements one by one, so this is
				// left for a body it cannot read at all.
				slog.Warn("panel: dropping event batch the panel rejected",
					"status", apiErr.Status, "code", apiErr.Code, "message", apiErr.Message,
					"count", len(ids), "ids", firstIDs(ids))
				if err := p.markDropped(ctx, ids); err != nil {
					return err
				}
				continue
			}
			return err
		}

		// Decision #50: the panel answers element by element. Only what it
		// accepted is sent; what it rejected would be rejected again on
		// every resend, so it is logged with the panel's reason and
		// dropped. An empty answer (an older panel) rejects nothing.
		rejected := Rejections(len(ids), res.Rejected, ids)
		sent := make([]string, 0, len(ids))
		var refused []string
		for i, id := range ids {
			r, ok := rejected[i]
			if !ok {
				sent = append(sent, id)
				continue
			}
			slog.Warn("panel: dropping event the panel rejected",
				"id", id, "kind", events[i].Kind, "from", events[i].From, "to", events[i].To,
				"error", r.Error)
			refused = append(refused, id)
		}
		if res.Duplicates > 0 || len(res.Ignored) > 0 {
			slog.Info("panel: events accepted with remarks",
				"accepted", res.Accepted, "duplicates", res.Duplicates, "ignored", len(res.Ignored))
		}
		if err := p.markSent(ctx, sent); err != nil {
			return err
		}
		if err := p.markDropped(ctx, refused); err != nil {
			return err
		}
		p.addRecoverySent(len(sent))
	}

	p.finishRecovery(ctx)

	p.mu.Lock()
	flusher := p.stats
	p.mu.Unlock()
	if flusher != nil {
		if err := flusher.Flush(ctx, cl); err != nil {
			return fmt.Errorf("panel: flushing stats: %w", err)
		}
	}
	return nil
}

// Prune drops unsent, already-notified events older than 24 h (spec §4.1).
// It runs at every flush and on every cycle that cannot reach the panel at
// all, so the PANEL_DOWN buffer is bounded by time whether or not the flush
// is reachable.
//
// notified = true is deliberate, not incidental (PLAUSIBLE finding this
// fixes): the 24 h allowance exists because such an event's alert has
// already gone out "via mon-server" (§4.1, §8) and replaying it into the
// panel's feed past that point is a nice-to-have mon-server can afford to
// drop. A notified = false event — everything queued during ordinary
// PANEL_UP operation, waiting for the panel itself to deliver the Telegram
// message — has no such backstop: the panel is the only place that alert
// will ever be sent from, so ageing it out here would lose it silently
// forever (reachable via POST /events failing with 5xx for a day while GET
// /state keeps succeeding and resetting the PANEL_DOWN failure run). Those
// rows are left for the outbox to keep retrying indefinitely.
func (p *Poller) Prune(ctx context.Context) error {
	cutoff := clock.Ms(p.clk.Now().Add(-outboxMaxAge))
	res := p.store.DB.WithContext(ctx).
		Where("sent_at IS NULL AND notified = ? AND ts < ?", true, cutoff).
		Delete(&store.EventOutbox{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		slog.Warn("panel: dropped notified outbox events older than the 24h buffer limit",
			"count", res.RowsAffected, "cutoff", cutoff)
	}
	return nil
}

// markSent stamps sent_at on the events the panel has accepted, which is
// what takes them out of every later flush.
func (p *Poller) markSent(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := clock.Ms(p.clk.Now())
	return p.store.DB.WithContext(ctx).
		Model(&store.EventOutbox{}).
		Where("id IN ?", ids).
		Update("sent_at", now).Error
}

// markDropped takes events out of the queue without their having reached
// the panel: sent_at is stamped like markSent's, so no later flush offers
// them again and retention ages them out, and dropped records that they
// were given up on rather than delivered.
func (p *Poller) markDropped(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := clock.Ms(p.clk.Now())
	return p.store.DB.WithContext(ctx).
		Model(&store.EventOutbox{}).
		Where("id IN ?", ids).
		Updates(map[string]any{"sent_at": now, "dropped": true}).Error
}

// decodeBatch turns outbox rows into wire events, separating out rows whose
// payload will not parse. Those can only come from a corrupted database, and
// keeping them would block the queue behind a row that can never be sent.
func decodeBatch(rows []store.EventOutbox) (events []store.EventPayload, ids, dropped []string) {
	for _, row := range rows {
		var ev store.EventPayload
		if err := json.Unmarshal([]byte(row.Payload), &ev); err != nil {
			dropped = append(dropped, row.Id)
			continue
		}
		events = append(events, ev)
		ids = append(ids, row.Id)
	}
	return events, ids, dropped
}

// firstIDs is the prefix of a batch's ids worth naming in a log line: a
// rejected batch can hold a thousand of them, and a log line that long is
// unreadable, while the first few plus the count are enough to find the rest
// in events_outbox.
func firstIDs(ids []string) []string {
	const max = 20
	if len(ids) <= max {
		return ids
	}
	return ids[:max]
}

// observe is the single place the PANEL_DOWN accounting of spec §4.1 sees
// the result of a panel request, whichever endpoint it was. It returns err
// unchanged so a caller can write `if err := p.observe(ctx, set, err); err
// != nil` and keep its own control flow.
//
// Only a request that failed without the panel answering counts toward
// PANEL_DOWN: a transport failure, a timeout or a 5xx. A 4xx, a bare 404,
// the xray_unavailable 503 and a 200 with a non-contract body (ErrBadBody,
// PLAUSIBLE finding) all prove *something* answered and are neutral — they
// neither trip the mode nor clear a failure run. A bad body gets its own
// once-per-spell alert here, because unlike the others it is never expected
// and an operator needs to know the panelUrl or a proxy ahead of it is
// wrong.
func (p *Poller) observe(ctx context.Context, set *store.Settings, err error) error {
	p.noteUnknownAuthority(err)
	if err == nil {
		if p.markUp() {
			p.onPanelUp()
		}
		return nil
	}
	if errors.Is(err, ErrBadBody) {
		p.notifyBadBody(ctx)
		return err
	}
	reason, counts := failureReason(err)
	if !counts {
		return err
	}
	if p.markDown(set.PanelDownAfter) {
		p.onPanelDown(ctx, reason)
	}
	return err
}

// noteUnknownAuthority records whether err, the latest request's outcome,
// was an untrusted panel certificate. Answers from the panel (a 404, a 4xx,
// a bad body) prove TLS worked, so they clear it just like a success.
func (p *Poller) noteUnknownAuthority(err error) {
	p.mu.Lock()
	p.unknownAuthority = IsUnknownAuthority(err)
	p.mu.Unlock()
}

// markUp resets the failure run and reports whether this success was the
// transition back from PANEL_DOWN.
func (p *Poller) markUp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures = 0
	p.rejected = false
	p.badBodyNotified = false
	if !p.down {
		return false
	}
	p.down = false
	p.pendingRecovery = true
	return true
}

// markDown counts one failed request and reports whether it was the one that
// tripped PANEL_DOWN (spec §4.1: "3 неудачных подряд запроса", the
// panelDownAfter setting of §9.4).
func (p *Poller) markDown(after int) bool {
	if after < 1 {
		after = 1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	if p.down || p.failures < after {
		return false
	}
	p.down = true
	return true
}

// onPanelDown records the transition the way spec §4.1 requires: an event in
// the outbox — which by definition cannot be delivered yet, and is what gets
// resent on recovery — plus the one Telegram message mon-server sends on its
// own behalf (§8).
func (p *Poller) onPanelDown(ctx context.Context, reason string) {
	slog.Warn("panel: entering PANEL_DOWN", "reason", reason)
	if err := p.enqueuePanelEvent(statePanelUp, statePanelDown, reason); err != nil {
		slog.Error("panel: queueing the PANEL_DOWN event failed", "err", err)
	}
	p.notify(ctx, msgPanelUnreachable)
}

// onPanelUp queues the PANEL_UP event as soon as a request succeeds again.
// The "panel back" message waits for finishRecovery, because its text counts
// the events that were actually resent and nothing has been resent yet.
func (p *Poller) onPanelUp() {
	slog.Info("panel: back, leaving PANEL_DOWN")
	if err := p.enqueuePanelEvent(statePanelDown, statePanelUp, reasonRecovered); err != nil {
		slog.Error("panel: queueing the PANEL_UP event failed", "err", err)
	}
}

// addRecoverySent adds n to the running "panel back" counter, but only
// while a recovery is actually pending — a batch sent during ordinary
// PANEL_UP operation must not count toward a message that will never be
// sent. Called once per batch the panel accepted, so a mid-drain failure
// that returns flush before finishRecovery runs leaves the total intact for
// whichever later cycle finishes draining (CONFIRMED finding).
func (p *Poller) addRecoverySent(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pendingRecovery {
		p.recoverySent += n
	}
}

// finishRecovery sends the "panel back, N events resent" message (spec §4.1,
// §8) once the outbox has actually been drained. N is recoverySent, the
// running total of every outbox row the panel accepted since pendingRecovery
// was first set — mon-server's own PANEL_DOWN and PANEL_UP events included —
// accumulated across as many cycles as the drain took, not just the cycle
// that happens to finish it (CONFIRMED finding: a retryable failure
// mid-drain in an earlier cycle must not shrink what gets reported once the
// queue finally empties).
func (p *Poller) finishRecovery(ctx context.Context) {
	p.mu.Lock()
	pending := p.pendingRecovery
	sent := p.recoverySent
	p.pendingRecovery = false
	p.recoverySent = 0
	p.mu.Unlock()
	if !pending {
		return
	}
	p.notify(ctx, fmt.Sprintf(msgPanelBackFmt, sent))
}

// notifyRejected sends spec §8's message for a bare 404, once per spell of
// being rejected rather than once a minute for as long as it lasts — an
// operator who has not fixed the token yet does not need the reminder every
// minute. Any successful request clears the flag, so a second spell alerts
// again.
func (p *Poller) notifyRejected(ctx context.Context) {
	p.mu.Lock()
	already := p.rejected
	p.rejected = true
	p.mu.Unlock()
	if already {
		return
	}
	slog.Warn("panel: monitoring token rejected or monitoring disabled")
	p.notify(ctx, msgPanelRejects)
}

// notifyBadBody sends the "non-contract response" message (PLAUSIBLE
// finding) once per spell of a 200 whose body will not parse as contract
// JSON, the same once-per-spell shape as notifyRejected: an operator who has
// not fixed the panelUrl or the proxy in front of it yet does not need the
// reminder every minute. markUp clears the flag on the next good body, so a
// later spell alerts again.
func (p *Poller) notifyBadBody(ctx context.Context) {
	p.mu.Lock()
	already := p.badBodyNotified
	p.badBodyNotified = true
	p.mu.Unlock()
	if already {
		return
	}
	slog.Warn("panel: response body is not valid contract JSON")
	p.notify(ctx, msgPanelBadBody)
}

// notify sends one Telegram message, logging rather than propagating a
// delivery failure: a broken bot token must not stop the poll cycle.
func (p *Poller) notify(ctx context.Context, text string) {
	if err := p.notifier.Send(ctx, text); err != nil {
		slog.Warn("panel: telegram send failed", "text", text, "err", err)
	}
}

// enqueuePanelEvent writes one kind:"panel" event to the outbox (contract
// §4.6). It is always notified=true: mon-server has already sent the
// Telegram message itself, so the panel must only file it in the feed.
func (p *Poller) enqueuePanelEvent(from, to, reason string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("panel: event id: %w", err)
	}
	return p.store.EnqueueEvent(store.EventPayload{
		ID:       id.String(),
		Ts:       clock.Ms(p.clk.Now()),
		Kind:     eventKindPanel,
		From:     from,
		To:       to,
		Reason:   reason,
		Notified: true,
	})
}

// clientFor returns the client for the current settings, rebuilding it when
// the panel URL, the token or panelCa has changed — an operator can edit any
// of them on the settings page (§9.4) without restarting mon-server. A
// client injected through PollerDeps.Client is used as-is and never
// rebuilt. A panelCa that does not parse is an error rather than a silent
// fall-back to the system pool: the operator asked for a specific trust.
func (p *Poller) clientFor(set *store.Settings) (Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fixed != nil {
		return p.fixed, nil
	}
	if p.client == nil || p.clientURL != set.PanelURL || p.clientToken != set.MonToken || p.clientCA != set.PanelCA {
		roots, err := ParseCA(set.PanelCA)
		if err != nil {
			return nil, fmt.Errorf("panel: settings: %w", err)
		}
		p.client = p.newClient(set.PanelURL, set.MonToken, roots)
		p.clientURL, p.clientToken, p.clientCA = set.PanelURL, set.MonToken, set.PanelCA
		slog.Info("panel: client built", "url", set.PanelURL, "panelCa", roots != nil)
	}
	return p.client, nil
}

// noteContract records whether st comes from a panel speaking the
// contract, logging a refusal once per spell (the poll cycle's own error
// repeats it every minute) and the recovery once.
func (p *Poller) noteContract(st *State) error {
	err := CheckContract(st)
	p.mu.Lock()
	was := p.contractErr
	p.contractErr = err
	p.mu.Unlock()
	switch {
	case err != nil && was == nil:
		slog.Warn("panel: refusing the panel's monitoring contract, no targets are built", "err", err,
			"contract", st.Contract, "panelVersion", st.PanelVersion)
	case err == nil && was != nil:
		slog.Info("panel: the panel speaks a supported monitoring contract again", "contract", st.Contract)
	}
	return err
}

// logUnconfigured says once, not every minute, that there is no panel to
// poll. The flag is cleared as soon as settings are filled in, so a later
// unconfiguring logs again.
func (p *Poller) logUnconfigured() {
	p.mu.Lock()
	already := p.unconfiguredLogged
	p.unconfiguredLogged = true
	p.mu.Unlock()
	if !already {
		slog.Info("panel: not configured yet, skipping the poll cycle (settings panelUrl/monToken)")
	}
}

func (p *Poller) clearUnconfigured() {
	p.mu.Lock()
	p.unconfiguredLogged = false
	p.mu.Unlock()
}

// failureReason maps an error to the PANEL_DOWN reason it should be recorded
// with (spec §4.1) and whether it counts as a panel failure at all.
func failureReason(err error) (string, bool) {
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrBadBody) {
		return "", false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.Code == codeXrayUnavailable || !apiErr.Retryable() {
			return "", false
		}
		return reasonHTTP5xx, true
	}
	var ne *netError
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return reasonHTTPTimeout, true
		}
		return reasonConnRefused, true
	}
	// Anything else is mon-server's own bug (a body it could not marshal),
	// not evidence about the panel.
	return "", false
}

// isXrayUnavailable reports the one 5xx that means "the panel is fine, xray
// is not" (contract §4.3).
func isXrayUnavailable(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == codeXrayUnavailable
}

// realHost is the address the direct path probes (§9.4: the realHost
// setting, "по умолчанию host из panelUrl"). Falling back to the panel URL's
// own host is right by construction: that is the address mon-server already
// reaches the panel at, which is exactly what "direct" means.
func realHost(set *store.Settings) string {
	return DirectHost(set.RealHost, set.PanelURL)
}

// DirectHost is realHost for values that are not (yet) saved settings — the
// Settings page's Check, which reads the probe material for what is typed
// (decision #51 §4): the realHost when there is one, the panel URL's host
// otherwise, "" when neither gives a host.
func DirectHost(realHost, panelURL string) string {
	if realHost != "" {
		return realHost
	}
	u, err := url.Parse(panelURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
