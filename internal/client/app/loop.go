// Package app is mon-client's run loop: the thing that turns a registered
// box into a mon-client (spec §4–§6). It fetches the config document,
// hands it to an Applier, and then, once per interval, probes every target
// in parallel, buffers the cycle and delivers the buffer in one heartbeat.
//
// Everything it does not own itself arrives through Deps, so the loop can
// be driven a single iteration at a time (Loop.Once) against the protocol
// stub with a fake clock and an injected sleeper — a loop whose tests had
// to wait out a 60-second interval would never be run.
package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/heartbeat"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/hostcheck"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Spec §5's probe defaults, in the units the config document carries them
// (protocol §4.2). They are what a mon-client runs on before it has ever
// seen a document — a 503 config_not_ready on the first boot must still
// produce a running, heartbeating box (spec §4.4) rather than one waiting
// for numbers it may not get for hours. probe.BudgetsFrom applies the same
// defaults to the four probe budgets; these are the two the loop itself
// needs plus the jitter.
const (
	DefaultIntervalMs         = 60_000
	DefaultStartJitterMs      = 5_000
	DefaultHeartbeatTimeoutMs = 10_000
)

// maxConfigError is spec §4.3's bound on the configError text carried in
// every heartbeat ("первая строка ошибки, ≤ 256 символов").
const maxConfigError = 256

// Applier owns everything that happens between two cycles when a revision
// changes (spec §4.3): writing xray.json, testing it, restarting the xray
// child, recording appliedRevision in state.json — and, whatever the
// outcome, saying which probes the next cycle should run.
//
// Step 8 implements it for real; step 7 ships ProvisionalApplier, which
// builds the probes but touches neither xray.json nor the xray child.
// The contract, which step 8 must keep:
//
//   - Apply is called by the loop only between cycles, never while probes
//     are in flight, and may block for as long as a restart takes.
//   - Apply returning nil means the document was applied: the applier has
//     already updated state.File.AppliedRevision and saved it through
//     state.Dir, and Applied now reports the new document with a nil
//     error.
//   - Apply returning an error means the old revision stays in force (spec
//     §4.3): the applier keeps serving the previous document and probes
//     from Applied, and reports the error there as the configError every
//     heartbeat carries until the next successful apply.
//   - Applied is called once per cycle and must be cheap. Its doc may be
//     nil (nothing applied yet — the loop then probes nothing and still
//     heartbeats); its probes map is keyed by target and may be empty; its
//     error is the configError, not a reason to stop.
type Applier interface {
	Apply(ctx context.Context, doc *proto.ConfigDoc) error
	Applied() (doc *proto.ConfigDoc, probes map[proto.TargetKey]probe.Fn, err error)
}

// CycleGuard is an optional extension of Applier for an applier that has
// to know when probes are in flight. Spec §4 step 3 says a revision is
// applied "между циклами: дождаться проб в полёте" — with Once and Apply
// called from one goroutine that is already true, but an applier that
// restarts the xray child every probe dials through cannot rely on its
// caller's goroutine discipline for that. RevisionApplier implements it
// with a read/write lock: every cycle takes the read side, an apply the
// write side.
//
// Once calls the pair around the cycle when the Applier implements it;
// an applier that does not (the tests' fake) is simply not guarded.
type CycleGuard interface {
	BeginCycle()
	EndCycle()
}

// Reviver is an optional extension of Applier for an applier whose probes
// depend on a long-running child process — RevisionApplier and its xray
// child. Once calls Revive before every cycle, after any config apply, so
// a child that died between cycles is restarted (or reported as down)
// before a single probe runs through it (decision #53 п. 4). Revive
// reports through Applied, never by failing the cycle: a dead xray must
// not stop the AWG probes or the heartbeat.
type Reviver interface {
	Revive(ctx context.Context)
}

// Rejecter is an optional extension of Applier for an applier that applies
// a revision target by target (decision #53 п. 3): Rejected lists the
// targets of the applied revision it could not turn into probes, which
// every heartbeat reports as client.rejectedTargets (protocol §5.3). An
// applier that does not implement it rejects nothing.
type Rejecter interface {
	Rejected() []proto.RejectedTarget
}

// Sweeper is an optional extension of Applier for an applier that keeps a
// document's sweepTargets ready (decision #100): SweepProbes hands out the
// probes of those of the given inbound kinds, for a cycle that runs a
// diagnostic sweep. An applier that does not implement it has nothing to
// sweep; the host reachability checks still run.
type Sweeper interface {
	SweepProbes(kinds []string) map[proto.TargetKey]probe.Fn
}

// HostChecker runs the host reachability checks of a diagnostic sweep
// (*hostcheck.Checker).
type HostChecker interface {
	Check(ctx context.Context, hosts []proto.SweepJobHost) []proto.HostCheck
}

// Deps are everything the loop needs and does not build itself. Every
// field that has a sensible production default gets one in NewLoop, so a
// test only overrides the seams it wants to control (Clock, Sleep, Rand).
type Deps struct {
	// API talks to mon-server off-tunnel: GET /v1/config and POST
	// /v1/heartbeat (spec §4, §6).
	API *api.Client
	// State is the state directory. The Applier writes it when it records
	// a new appliedRevision; the loop writes it after each acknowledged
	// heartbeat, to keep the last ackSeq (decision #51 §1).
	State *state.Dir
	// File is the loaded state.json. AppliedRevision is read from it every
	// cycle (it is what the heartbeat's configRevision reports and what a
	// response's revision is compared against) and written by the Applier.
	File *state.File
	// Buffer is cycles.json (spec §6).
	Buffer *heartbeat.Buffer
	// Runner runs one cycle's probes in parallel.
	Runner *probe.Runner
	// Applier converges the box on a config document (see Applier).
	Applier Applier
	// Clock stamps each cycle's ts, computes uptimeMs and places the
	// cycle ticks (Run). Defaults to clock.Real.
	Clock clock.Clock
	// Sleep is the interval wait; the zero value is a cancellable timer.
	// Tests inject one that advances the fake Clock instead, so a full
	// cycle costs no wall-clock time at all.
	Sleep func(ctx context.Context, d time.Duration) error
	// Rand draws the start jitter (spec §5). Defaults to a PCG seeded from
	// crypto/rand — the jitter exists to spread the cycle starts of many
	// boxes, so every box seeding it identically would defeat it.
	Rand *mrand.Rand
	// Log receives the loop's spec §7 lines ("ack 1441", "buffered 3
	// cycles"). Nil means slog.Default().
	Log *slog.Logger
	// Version and XrayVersion fill the heartbeat's client block (protocol
	// §5.3). XrayVersion is a function because the xray child may be
	// restarted under a new binary between heartbeats; nil reports "".
	Version     string
	XrayVersion func() string
	// StartedAt is the process start, for uptimeMs.
	StartedAt time.Time
	// Hosts runs a diagnostic sweep's host reachability checks. Defaults
	// to a hostcheck.Checker on an unprivileged ICMP socket.
	Hosts HostChecker
}

// Loop is one running mon-client. It is not safe for concurrent use: Run
// (or repeated Once) owns it.
type Loop struct {
	d Deps

	// needConfig is "fetch GET /v1/config before the next cycle" — true at
	// start (spec §4.1) and set again whenever a heartbeat answers with a
	// revision other than the applied one (spec §6).
	needConfig bool

	// sweep is the diagnostic sweep run the last heartbeat answer asked
	// for (decision #100), run by the next cycle and then forgotten: every
	// run is asked for on its own.
	sweep *proto.SweepJob
}

// NewLoop returns a Loop over d, filling in every dependency with a
// production default that d left nil.
func NewLoop(d Deps) *Loop {
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	if d.Sleep == nil {
		d.Sleep = defaultSleep
	}
	if d.Rand == nil {
		d.Rand = mrand.New(mrand.NewPCG(seed(), seed()))
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Runner == nil {
		d.Runner = probe.NewRunner(d.Log)
	}
	if d.StartedAt.IsZero() {
		d.StartedAt = d.Clock.Now()
	}
	if d.Hosts == nil {
		d.Hosts = &hostcheck.Checker{}
	}
	if d.Buffer != nil && d.File != nil {
		// Decision #51 §1: a cycles.json that was lost or discarded as
		// corrupt restarts the counter; continue after the last ack
		// mon-server gave instead of at 1.
		d.Buffer.ContinueAfter(d.File.LastAckSeq)
	}
	return &Loop{d: d, needConfig: true}
}

// Run drives the loop until ctx ends (a normal shutdown, reported as nil)
// or mon-server refuses this mon-client outright.
//
// api.ErrTokenRevoked (401) and api.ErrDisabled (403) are returned
// unwrapped: spec §6 gives them two very different answers — clear the
// state file and register again, versus keep the state file and heartbeat
// every 5 minutes — and step 9 owns both. Every other failure (mon-server
// down, a 5xx, a timeout, a config that would not apply) is handled inside
// the loop and never stops the probes (spec §6: "Пробы при этом
// продолжаются").
//
// Cycles start on a fixed grid (spec §5, decision #53 п. 5): the first one
// after the start jitter, every later one intervalMs after the previous
// one's scheduled start, however long that cycle took. A cycle that runs
// past the next tick does not trigger an immediate catch-up cycle — the
// ticks it overran are skipped and the next cycle starts on the next tick
// still ahead.
func (l *Loop) Run(ctx context.Context) error {
	if err := l.d.Sleep(ctx, l.startJitter()); err != nil {
		return nil // ctx ended during the wait: an ordinary shutdown
	}
	start := l.d.Clock.Now()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := l.Once(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			l.log().Error("mon-client stopping", "error", err)
			return err
		}
		next, wait := l.nextStart(start)
		if err := l.d.Sleep(ctx, wait); err != nil {
			return nil
		}
		start = next
	}
}

// Once runs exactly one iteration — fetch the config if it is due, probe
// every target, buffer the cycle, deliver the buffer, act on the answer —
// without any waiting of its own. Run calls it once per interval; a test
// calls it directly, which is why the interval wait lives in Run.
func (l *Loop) Once(ctx context.Context) error {
	if l.needConfig {
		if err := l.fetchAndApply(ctx); err != nil {
			return err
		}
	}
	if r, ok := l.d.Applier.(Reviver); ok {
		r.Revive(ctx)
	}

	doc, results, sweep, ts, rejected, configErr := l.cycle(ctx)
	if _, err := l.d.Buffer.AddCycle(ts, results, sweep); err != nil {
		// The cycle is in the buffer, just not on disk: the heartbeat
		// below still carries it, and only a restart before the next
		// successful save would lose it (spec §6).
		l.log().Error("cycles buffer not persisted", "error", err)
	}

	hb := &proto.HeartbeatRequest{
		MonClientID:    l.d.File.MonClientID,
		ConfigRevision: l.d.File.AppliedRevision,
		Client:         l.clientInfo(configErr, rejected),
		Cycles:         l.d.Buffer.Pending(),
	}

	hctx, cancel := context.WithTimeout(ctx, l.heartbeatTimeout(doc))
	defer cancel()
	resp, err := heartbeat.Send(hctx, l.d.API, hb)
	if err != nil {
		// Spec §6: an unacknowledged cycle stays in the buffer, flagged,
		// and rides along with the next heartbeat. This is also where a
		// 401/403 lands, and those two must reach the caller — but the
		// cycle is marked either way, since it was not delivered.
		if markErr := l.d.Buffer.MarkUnverified(); markErr != nil {
			l.log().Error("cycles buffer not persisted", "error", markErr)
		}
		if errors.Is(err, api.ErrTokenRevoked) || errors.Is(err, api.ErrDisabled) {
			return err
		}
		l.log().Info(fmt.Sprintf("buffered %d cycles", len(l.d.Buffer.Pending())), "error", err)
		return nil
	}

	if err := l.d.Buffer.Ack(resp.AckSeq); err != nil {
		l.log().Error("cycles buffer not persisted", "error", err)
	}
	if resp.Sweep != nil {
		l.log().Info("diagnostic sweep requested for the next cycle", "kinds", resp.Sweep.Kinds, "hosts", len(resp.Sweep.Hosts))
	}
	l.sweep = resp.Sweep
	l.rememberAck(resp.AckSeq)
	// Spec §7's heartbeat line.
	l.log().Info(fmt.Sprintf("ack %d", resp.AckSeq))

	if resp.ConfigRevision != l.d.File.AppliedRevision {
		// Spec §6: a revision change is acted on *after* the current
		// cycle, so the next iteration fetches and applies it before it
		// probes.
		l.log().Info(fmt.Sprintf("config revision changed to %s", resp.ConfigRevision))
		l.needConfig = true
	}
	return nil
}

// rememberAck keeps mon-server's latest ackSeq in state.json (decision #51
// §1), so a box whose cycles.json is lost continues after it (NewLoop). A
// failed write is logged, not fatal: cycles.json still carries the counter,
// and the copy here only matters if that file is lost too.
func (l *Loop) rememberAck(ackSeq int64) {
	if l.d.File == nil || ackSeq <= l.d.File.LastAckSeq {
		return
	}
	l.d.File.LastAckSeq = ackSeq
	if l.d.State == nil {
		return
	}
	if err := l.d.State.Save(l.d.File); err != nil {
		l.log().Error("state not persisted", "error", err)
	}
}

// cycle runs one probe cycle against whatever is applied and returns it
// together with the applied document, the cycle's start timestamp, the
// applied revision's rejected targets and the configError.
//
// It is a method of its own because of the guard around it: while the
// cycle runs, an Applier that is a CycleGuard cannot swap the probe set
// under it (spec §4 step 3). The results are then filtered against that
// same probe set: spec §4 step 3 gives removed targets no grace ("грейса
// нет: результаты по удалённым targets отбрасываются"), and while the
// runner only ever probes what it was handed, a result for a key the
// applied document no longer has must not reach a heartbeat even if some
// future applier hands one back.
//
// A cycle the last heartbeat answer asked a diagnostic sweep of (decision
// #100) also probes the sweep targets of the job's kinds, at the same time
// and under the same budgets, and runs the job's host reachability checks
// alongside; their results go in the cycle's sweep block, not in results.
func (l *Loop) cycle(ctx context.Context) (doc *proto.ConfigDoc, results []proto.Result, sweep *proto.CycleSweep, ts int64, rejected []proto.RejectedTarget, configErr error) {
	if g, ok := l.d.Applier.(CycleGuard); ok {
		g.BeginCycle()
		defer g.EndCycle()
	}
	doc, probes, configErr := l.d.Applier.Applied()
	rejected = l.rejected()
	ts = clock.Ms(l.d.Clock.Now())
	job := l.sweep
	l.sweep = nil
	if job == nil {
		results = l.d.Runner.Cycle(ctx, probes, probe.BudgetsFrom(probeParams(doc)))
		return doc, applied(results, probes), nil, ts, rejected, configErr
	}

	var sweepProbes map[proto.TargetKey]probe.Fn
	if s, ok := l.d.Applier.(Sweeper); ok {
		sweepProbes = s.SweepProbes(job.Kinds)
	}
	all := make(map[proto.TargetKey]probe.Fn, len(probes)+len(sweepProbes))
	for k, fn := range sweepProbes {
		all[k] = fn
	}
	for k, fn := range probes {
		all[k] = fn
	}
	var hosts []proto.HostCheck
	done := make(chan struct{})
	go func() {
		defer close(done)
		hosts = l.d.Hosts.Check(ctx, job.Hosts)
	}()
	everything := l.d.Runner.Cycle(ctx, all, probe.BudgetsFrom(probeParams(doc)))
	<-done

	sweep = &proto.CycleSweep{Kinds: job.Kinds, Results: []proto.Result{}, Hosts: hosts}
	if sweep.Hosts == nil {
		sweep.Hosts = []proto.HostCheck{}
	}
	for _, r := range everything {
		if _, ok := probes[r.TargetKey]; ok {
			results = append(results, r)
		} else if _, ok := sweepProbes[r.TargetKey]; ok {
			sweep.Results = append(sweep.Results, r)
		}
	}
	l.log().Info(fmt.Sprintf("diagnostic sweep: %d tunnel probes, %d host checks", len(sweep.Results), len(sweep.Hosts)))
	return doc, applied(results, probes), sweep, ts, rejected, configErr
}

// rejected is the applier's Rejected, or nothing for an applier that is
// not a Rejecter.
func (l *Loop) rejected() []proto.RejectedTarget {
	if r, ok := l.d.Applier.(Rejecter); ok {
		return r.Rejected()
	}
	return nil
}

// applied drops every result whose target is not in the applied probe set
// (spec §4 step 3). The slice stays non-nil when empty: a cycle with no
// results encodes as [], not null (protocol §5.3).
func applied(results []proto.Result, probes map[proto.TargetKey]probe.Fn) []proto.Result {
	kept := make([]proto.Result, 0, len(results))
	for _, r := range results {
		if _, ok := probes[r.TargetKey]; ok {
			kept = append(kept, r)
		}
	}
	return kept
}

// fetchAndApply performs spec §4.1's GET /v1/config and hands the document
// to the Applier.
//
// A 503 config_not_ready on a box that has applied nothing yet is not a
// failure to retry silently: spec §4.4 says such a box runs empty cycles
// and heartbeats anyway, so an empty document with the spec §5 defaults is
// applied and the fetch stays due for the next iteration. Any other
// failure leaves whatever is applied in force and retries next iteration
// too — 401/403 excepted, which belong to the caller.
func (l *Loop) fetchAndApply(ctx context.Context) error {
	doc, err := l.d.API.Config(ctx)
	if err != nil {
		if errors.Is(err, api.ErrTokenRevoked) || errors.Is(err, api.ErrDisabled) {
			return err
		}
		l.log().Warn("config not fetched", "error", err)
		if applied, _, _ := l.d.Applier.Applied(); applied == nil {
			doc = l.emptyDoc()
			if applyErr := l.d.Applier.Apply(ctx, doc); applyErr != nil {
				l.log().Warn("config not applied", "error", applyErr)
			}
		}
		return nil
	}

	l.needConfig = false
	if err := l.d.Applier.Apply(ctx, doc); err != nil {
		// Spec §4.3: the old revision stays in force and the error is
		// reported as configError on every heartbeat until a later
		// revision applies cleanly; the applier keeps it for us.
		l.log().Warn("config not applied", "error", err)
		return nil
	}
	// The spec §7 line for a successful apply is written by the Applier,
	// which is the only thing that knows what the revision turned into
	// (how many xray- and AWG-targets, and whether the child restarted).
	return nil
}

// emptyDoc is the document a mon-client runs on when mon-server has none
// for it yet (spec §4.4): no targets, spec §5's default timings.
func (l *Loop) emptyDoc() *proto.ConfigDoc {
	return &proto.ConfigDoc{
		MonClientID: l.d.File.MonClientID,
		Probe: proto.ProbeParams{
			IntervalMs:         DefaultIntervalMs,
			BudgetMs:           int64(probe.DefaultBudget / time.Millisecond),
			ConnectMs:          int64(probe.DefaultConnect / time.Millisecond),
			TlsMs:              int64(probe.DefaultTLS / time.Millisecond),
			HeadersMs:          int64(probe.DefaultHeaders / time.Millisecond),
			StartJitterMs:      DefaultStartJitterMs,
			HeartbeatTimeoutMs: DefaultHeartbeatTimeoutMs,
		},
	}
}

// startJitter is how long Run waits before the very first cycle: a random
// share of the applied document's startJitterMs, and the only jitter a
// mon-client ever applies (spec §5).
//
// The jitter exists so that a fleet of boxes restarted together does not
// hit mon-server in lockstep; once the first starts are spread, the fixed
// grid keeps them spread. Waiting a whole interval *plus* jitter before the
// first cycle would instead leave a freshly started box silent for a
// minute, which is exactly the minute an operator watching a new
// registration is looking at.
func (l *Loop) startJitter() time.Duration {
	doc, _, _ := l.d.Applier.Applied()
	jitter := probeParams(doc).StartJitterMs
	if jitter <= 0 {
		return 0
	}
	return time.Duration(l.d.Rand.Int64N(jitter)) * time.Millisecond
}

// nextStart is the tick the cycle after the one scheduled at prev starts
// on, and how long to wait for it from now (decision #53 п. 5).
//
// The tick is prev + intervalMs — the scheduled start, not the moment the
// timer actually fired, so a timer's lateness never accumulates into
// drift. When the cycle ran past that tick, the ticks it overran are
// skipped and the next one still ahead is taken: the period stretches to a
// whole number of intervals instead of a burst of back-to-back cycles. The
// wait is capped at one interval, so a wall clock stepped backwards costs
// at most one late cycle rather than a silence as long as the step.
func (l *Loop) nextStart(prev time.Time) (next time.Time, wait time.Duration) {
	interval := l.interval()
	now := l.d.Clock.Now()
	next = prev.Add(interval)
	if late := now.Sub(next); late > 0 {
		skipped := (late + interval - 1) / interval
		next = next.Add(skipped * interval)
		l.log().Warn(fmt.Sprintf("cycle overran the %s interval, skipping %d tick(s)", interval, skipped))
	}
	wait = next.Sub(now)
	if wait > interval {
		next, wait = now.Add(interval), interval
	}
	return next, wait
}

// interval is the applied document's intervalMs, defaulted like
// everything else in probeParams.
func (l *Loop) interval() time.Duration {
	doc, _, _ := l.d.Applier.Applied()
	interval := probeParams(doc).IntervalMs
	if interval <= 0 {
		interval = DefaultIntervalMs
	}
	return time.Duration(interval) * time.Millisecond
}

// heartbeatTimeout is the deadline one heartbeat runs under (spec §6's
// heartbeatTimeoutMs), defaulted like everything else in probeParams.
func (l *Loop) heartbeatTimeout(doc *proto.ConfigDoc) time.Duration {
	ms := probeParams(doc).HeartbeatTimeoutMs
	if ms <= 0 {
		ms = DefaultHeartbeatTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// ClientInfo reports protocol §5.3's client block for a heartbeat sent
// from outside a cycle — the supervisor's bare heartbeats while this
// mon-client is disabled (spec §6), which carry no cycles but must still
// say which version is running, which xray is installed and whether the
// applied config is broken.
//
// It is the exported half of clientInfo: the configError comes from the
// applier, which is the same place the cycle's own does, so a box that was
// disabled while a revision would not apply keeps reporting that error for
// as long as it is disabled instead of going quiet about it.
func (l *Loop) ClientInfo() proto.ClientInfo {
	_, _, configErr := l.d.Applier.Applied()
	return l.clientInfo(configErr, l.rejected())
}

// clientInfo builds the client block over an already-known configError and
// rejected set — the cycle has both in hand and must report exactly what
// that cycle probed under, not whatever the applier holds a moment later.
func (l *Loop) clientInfo(configErr error, rejected []proto.RejectedTarget) proto.ClientInfo {
	return proto.ClientInfo{
		Version:         l.d.Version,
		XrayVersion:     l.xrayVersion(),
		UptimeMs:        l.uptimeMs(),
		ConfigError:     configErrorText(configErr),
		RejectedTargets: rejected,
	}
}

// uptimeMs is the process' age (protocol §5.3's client.uptimeMs), never
// negative even if the clock moved backwards between two reads.
func (l *Loop) uptimeMs() int64 {
	d := l.d.Clock.Now().Sub(l.d.StartedAt)
	if d < 0 {
		return 0
	}
	return int64(d / time.Millisecond)
}

// xrayVersion reports the xray child's version for the heartbeat, or ""
// when there is no child to ask (an AWG-only box, or one whose xray never
// started).
func (l *Loop) xrayVersion() string {
	if l.d.XrayVersion == nil {
		return ""
	}
	return l.d.XrayVersion()
}

func (l *Loop) log() *slog.Logger { return l.d.Log }

// probeParams is doc.Probe with a nil doc treated as "no document yet" —
// the zero ProbeParams, which every caller then defaults field by field
// (probe.BudgetsFrom does the same for the four probe budgets).
func probeParams(doc *proto.ConfigDoc) proto.ProbeParams {
	if doc == nil {
		return proto.ProbeParams{IntervalMs: DefaultIntervalMs, StartJitterMs: DefaultStartJitterMs, HeartbeatTimeoutMs: DefaultHeartbeatTimeoutMs}
	}
	return doc.Probe
}

// configErrorText renders an Applier's error as protocol §5.3's
// client.configError: its first line, at most 256 characters (spec §4.3).
// A nil error is a nil pointer, which is the null the protocol's example
// shows for a healthy mon-client — distinct from an empty string.
func configErrorText(err error) *string {
	if err == nil {
		return nil
	}
	text := firstLine(err.Error())
	return &text
}

// defaultSleep is Deps.Sleep's production behaviour: an ordinary
// cancellable timer (the same shape register.Run uses).
func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// seed draws one PCG seed word from crypto/rand, falling back to the
// clock-free zero value only if the host's randomness is broken — in which
// case the jitter is degenerate but the loop still runs.
func seed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}
