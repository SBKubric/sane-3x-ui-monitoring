package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/awg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray"
)

// xrayConfigName is the generated config's name in the state directory
// (spec §2: "Рабочие файлы в state-dir: xray.json").
const xrayConfigName = "xray.json"

// prevSuffix marks the copy of xray.json that was in force before the
// current apply. It exists only for the window between "the new config
// replaced the old one on disk" and "the child is running on it": a
// restart that fails must be able to put the box back on the old revision,
// which spec §4 step 3 requires ("остаться на старой ревизии, продолжить
// пробы по старому конфигу") and which is impossible once the file the old
// child ran on has been overwritten.
const prevSuffix = ".prev"

// reviveTimeout bounds one attempt to bring a dead xray child back before a
// cycle (decision #53 п. 4). A child that has not bound its socks ports in
// that time will not do better by being waited on, and the cycle — AWG
// probes and the heartbeat included — must still start close to its tick.
const reviveTimeout = 10 * time.Second

// ApplierDeps are the collaborators RevisionApplier cannot make up for
// itself. It is not called Deps because that name belongs to the loop's
// own dependencies in this package (BRIEF §3.9 writes it as
// NewRevisionApplier(Deps); the type is the same idea under a name that
// does not collide).
type ApplierDeps struct {
	// XrayProber and AWGProber turn a parsed target into one probe (spec
	// §5). Nil means a default prober logging through Log.
	XrayProber *probe.Prober
	AWGProber  *awg.Prober
	// Xray is the child process the generated xray.json is tested and run
	// on (spec §4 step 3). It may be nil — an AWG-only box, or one whose
	// --xray-bin does not exist — and then a document carrying xray-targets
	// cannot be applied and says so as configError.
	Xray *xray.Process
	// Dir is the state directory: xray.json is written next to state.json
	// (spec §2). Required whenever Xray is set.
	Dir *state.Dir
	// File is the loaded state.json, shared with the Loop. The applier is
	// its only writer of AppliedRevision.
	File *state.File
	// Log receives spec §7's revision lines. Nil means slog.Default().
	Log *slog.Logger
}

// RevisionApplier applies a config document the way spec §4 step 3
// prescribes: between two probe cycles, never during one.
//
// One apply is: parse every target on its own (decision #53 п. 3: a link
// that will not become an outbound, a .conf that will not become UAPI and
// an AWG config the device refuses in a trial IpcSet reject that target
// only), write the xray.json generated from the accepted xray-targets,
// gate it on `xray -test`, restart the child and wait for its socks ports,
// then swap the probe set and record appliedRevision. Rejected targets do
// not stop the revision — it applies with the rest, even with none left,
// and Rejected reports them for the heartbeat's client.rejectedTargets.
// Any failure of the revision as a whole (`-test`, the restart, saving
// state.json) leaves the previous revision in force — the same document,
// the same probes, the same rejections, the same running child — and comes
// back as the error the loop reports as client.configError in every
// heartbeat until a later revision applies cleanly (spec §4 step 3).
//
// Applying is exclusive with probing: Apply takes the write side of the
// cycle lock that BeginCycle/EndCycle take the read side of, so a cycle
// already in flight finishes on the old probes before the new ones are
// installed ("дождаться проб в полёте").
type RevisionApplier struct {
	d ApplierDeps

	// cycle serialises applying against probing. Write: one apply. Read:
	// one cycle (see CycleGuard in loop.go).
	cycle sync.RWMutex

	// mu guards everything below, which Applied reads from the loop's
	// goroutine while Apply writes it.
	mu       sync.Mutex
	doc      *proto.ConfigDoc
	probes   map[proto.TargetKey]probe.Fn
	sweep    map[proto.TargetKey]probe.Fn // the applied sweepTargets' probes (decision #100)
	xrayKeys map[proto.TargetKey]bool     // the applied xray-targets, skipped while xray is down
	ports    []int                        // the socks ports of the applied revision, for recovery
	rejected []proto.RejectedTarget       // the applied revision's targets that are not probed
	lastErr  error
	// xrayDown is set while the xray child is dead and a restart before
	// the cycle did not bring it back (decision #53 п. 4). It overrides
	// lastErr as the configError until the child is up again.
	xrayDown error
}

// RevisionApplier is the production Applier, and the loop finds its cycle
// guard and its xray revival through these interfaces only.
var (
	_ Applier    = (*RevisionApplier)(nil)
	_ CycleGuard = (*RevisionApplier)(nil)
	_ Reviver    = (*RevisionApplier)(nil)
	_ Rejecter   = (*RevisionApplier)(nil)
	_ Sweeper    = (*RevisionApplier)(nil)
)

// NewRevisionApplier wires an applier to its probers, its xray child and
// the state file whose appliedRevision it maintains.
func NewRevisionApplier(d ApplierDeps) *RevisionApplier {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.XrayProber == nil {
		d.XrayProber = &probe.Prober{Logger: d.Log}
	}
	if d.AWGProber == nil {
		d.AWGProber = &awg.Prober{Log: d.Log}
	}
	return &RevisionApplier{d: d}
}

// Apply converges the box on doc (see the Applier contract in loop.go and
// the type's own comment for the order of operations). It blocks until any
// cycle in flight has finished and for as long as a restart takes.
func (a *RevisionApplier) Apply(ctx context.Context, doc *proto.ConfigDoc) error {
	a.cycle.Lock()
	defer a.cycle.Unlock()

	if err := a.apply(ctx, doc); err != nil {
		// The text is the configError verbatim (spec §4 step 3: first line,
		// ≤ 256), so it is shortened here rather than at every heartbeat.
		cfgErr := errors.New(firstLine(err.Error()))
		a.mu.Lock()
		a.lastErr = cfgErr
		a.mu.Unlock()
		return cfgErr
	}
	return nil
}

// Applied reports the document the box is currently probing by, its probe
// map and the configError (see the Applier contract).
//
// While the xray child is down (see Revive) the xray-targets are left out
// of the probe map — probing them through socks ports nobody listens on
// would report a false tcp_refused for every one of them — and the
// configError is xray's own. mon-server passes no verdict on results that
// did not arrive, so those targets age to STALE rather than DOWN.
func (a *RevisionApplier) Applied() (*proto.ConfigDoc, map[proto.TargetKey]probe.Fn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.xrayDown == nil {
		return a.doc, a.probes, a.lastErr
	}
	probes := make(map[proto.TargetKey]probe.Fn, len(a.probes))
	for k, fn := range a.probes {
		if !a.xrayKeys[k] {
			probes[k] = fn
		}
	}
	return a.doc, probes, a.xrayDown
}

// SweepProbes is the loop's Sweeper (decision #100): the probes of the
// applied document's sweepTargets of the given inbound kinds, for a cycle
// that runs a diagnostic sweep. They were applied with the revision — the
// xray child already has their outbounds — so a sweep restarts nothing.
// While the xray child is down its targets are left out, as in Applied.
func (a *RevisionApplier) SweepProbes(kinds []string) map[proto.TargetKey]probe.Fn {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[proto.TargetKey]probe.Fn)
	for k, fn := range a.sweep {
		if a.xrayDown != nil && a.xrayKeys[k] {
			continue
		}
		for _, kind := range kinds {
			if k.InboundKind == kind {
				out[k] = fn
				break
			}
		}
	}
	return out
}

// Rejected is the loop's Rejecter: the targets of the applied revision
// that were rejected when it was applied, in document order, for the
// heartbeat's client.rejectedTargets (decision #53 п. 3). They change only
// when a revision applies, so a revision that failed as a whole keeps the
// previous one's.
func (a *RevisionApplier) Rejected() []proto.RejectedTarget {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rejected
}

// Revive is the loop's Reviver (decision #53 п. 4): before every cycle, if
// the applied revision has xray-targets and the child is not running, it
// restarts the child on the applied xray.json — one attempt per cycle, so
// the interval is the backoff. A child that comes back clears the xray
// error, and the configError returns to the revision's own (or none); one
// that does not keeps its xray-targets out of the cycle and reports
// "xray: <first line it printed>" as the configError.
func (a *RevisionApplier) Revive(ctx context.Context) {
	if a.d.Xray == nil || a.d.Dir == nil {
		return
	}
	a.cycle.Lock()
	defer a.cycle.Unlock()

	a.mu.Lock()
	ports := a.ports
	a.mu.Unlock()
	if len(ports) == 0 {
		return
	}
	if a.d.Xray.Running() {
		a.setXrayDown(nil)
		return
	}

	a.d.Log.Warn("xray is not running, restarting it")
	rctx, cancel := context.WithTimeout(ctx, reviveTimeout)
	defer cancel()
	if err := a.d.Xray.Restart(rctx, a.d.Dir.Path(xrayConfigName), ports); err != nil {
		down := errors.New(firstLine("xray: " + strings.TrimPrefix(err.Error(), "xray: ")))
		a.d.Log.Error("xray did not come back, its targets are not probed this cycle", "error", down)
		a.setXrayDown(down)
		return
	}
	a.d.Log.Info("xray restarted on the applied revision")
	a.setXrayDown(nil)
}

func (a *RevisionApplier) setXrayDown(err error) {
	a.mu.Lock()
	a.xrayDown = err
	a.mu.Unlock()
}

// BeginCycle and EndCycle are the loop's CycleGuard: they hold the read
// side of the cycle lock for the duration of one cycle, which is what
// makes "применение между циклами" true rather than merely intended.
func (a *RevisionApplier) BeginCycle() { a.cycle.RLock() }
func (a *RevisionApplier) EndCycle()   { a.cycle.RUnlock() }

// Stop shuts the xray child down. It belongs to the applier because the
// applier is what started the child; cmd/mon-client calls it on the way
// out so a stopped mon-client leaves no xray behind.
func (a *RevisionApplier) Stop(ctx context.Context) error {
	if a.d.Xray == nil {
		return nil
	}
	return a.d.Xray.Stop(ctx)
}

// apply is Apply without the locking and the error shortening.
func (a *RevisionApplier) apply(ctx context.Context, doc *proto.ConfigDoc) error {
	if doc == nil {
		doc = &proto.ConfigDoc{}
	}

	// Everything that can fail on one target's own material fails here,
	// before a byte is written or the child is touched, and rejects that
	// target only (decision #53 п. 3).
	cfgJSON, plans, awgs, rejected, err := parseDoc(doc)
	if err != nil {
		return err
	}
	for _, r := range rejected {
		a.d.Log.Warn("target rejected", "target", r.Target, "error", r.Error)
	}
	if len(plans) > 0 && a.d.Xray == nil {
		return fmt.Errorf("no xray binary: %d xray targets cannot be probed", len(plans))
	}

	ports := socksPorts(plans)
	if a.d.Xray != nil {
		if err := a.installConfig(ctx, cfgJSON, ports); err != nil {
			return err
		}
	}

	all := a.buildProbes(doc, plans, awgs)
	probes, sweep := splitSweep(doc, all)

	// appliedRevision is recorded *before* the probe set is swapped, and a
	// failure to record it fails the whole apply. The other order looks
	// harmless and is not: a box whose state.json could not be written
	// would probe the new revision's targets while every heartbeat
	// reported the old revision (protocol §5.3's configRevision), and
	// mon-server would attribute the new targets' results to a config it
	// believes is not in force. Failing here instead leaves the old
	// revision fully in force — old doc, old probes — and reports the
	// write failure as configError, which is what an operator has to see
	// to go and fix the state directory (spec §4 step 3).
	if a.d.File != nil {
		a.mu.Lock()
		file := *a.d.File
		a.mu.Unlock()
		if file.AppliedRevision != doc.ConfigRevision {
			file.AppliedRevision = doc.ConfigRevision
			if a.d.Dir != nil {
				if err := a.d.Dir.Save(&file); err != nil {
					return fmt.Errorf("save applied revision: %w", err)
				}
			}
			a.mu.Lock()
			*a.d.File = file
			a.mu.Unlock()
		}
	}

	a.mu.Lock()
	a.doc, a.probes, a.sweep, a.ports, a.rejected, a.lastErr = doc, probes, sweep, ports, rejected, nil
	a.xrayKeys = xrayKeys(plans)
	// The child was just (re)started on this revision, or the revision has
	// no xray-targets: either way there is no dead child to report.
	a.xrayDown = nil
	a.mu.Unlock()

	// Spec §7's revision line: what was applied and how much of it.
	a.d.Log.Info(fmt.Sprintf("applied revision %s: %d xray targets, %d awg targets (%d of them for the diagnostic sweep), %d rejected",
		doc.ConfigRevision, len(plans), len(awgs), len(sweep), len(rejected)))
	return nil
}

// installConfig writes the generated config, gates it on `xray -test` and
// restarts the child on it (spec §4 step 3).
//
// The order is the one that keeps a failure harmless. The candidate config
// goes to a temp file first, so a `-test` that fails never replaces the
// file the running child was started from. Only once it passes is
// xray.json moved aside to xray.json.prev and the candidate renamed into
// place; a restart that then fails puts the old file back and starts the
// child on it again, so the box keeps probing the old revision instead of
// sitting with no xray at all. The recovery is best effort by nature — if
// the old config no longer starts either, there is nothing left to fall
// back to — and either way the caller gets the original error, because
// that is what the operator needs to see as configError.
func (a *RevisionApplier) installConfig(ctx context.Context, cfgJSON []byte, ports []int) error {
	if a.d.Dir == nil {
		return errors.New("no state directory for xray.json")
	}
	path := a.d.Dir.Path(xrayConfigName)

	// The candidate keeps a .json suffix: xray picks the config format from
	// the file extension, and `-test` on "xray.json.tmp-123" fails with
	// "Failed to get format" before it reads a byte (found on the stand).
	tmp, err := os.CreateTemp(a.d.Dir.Path(""), "xray.tmp-*.json")
	if err != nil {
		return fmt.Errorf("create temp xray.json: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(cfgJSON); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp xray.json: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp xray.json: %w", err)
	}

	if err := a.d.Xray.Test(ctx, tmpPath); err != nil {
		return err
	}

	if len(ports) == 0 {
		// No xray-targets: there is nothing for a child to listen on, so a
		// revision that drops the last one stops the child rather than
		// running an xray with no inbounds. The cycle then runs empty
		// (spec §4 step 4) — for the AWG-targets, if any.
		if err := a.d.Xray.Stop(ctx); err != nil {
			return err
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("install xray.json: %w", err)
		}
		keep = true
		return nil
	}

	prevPath := path + prevSuffix
	hasPrev := false
	if _, statErr := os.Stat(path); statErr == nil {
		if err := os.Rename(path, prevPath); err != nil {
			return fmt.Errorf("keep previous xray.json: %w", err)
		}
		hasPrev = true
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// The old config has already been moved aside, so the box is one
		// failed rename away from having no xray.json at all — put it
		// back before reporting, or a restart (ours or the operator's)
		// would find nothing to start on.
		if hasPrev {
			if restoreErr := os.Rename(prevPath, path); restoreErr != nil {
				a.d.Log.Error("previous xray.json not restored", "error", restoreErr)
			} else {
				a.d.Log.Warn("new xray.json not installed, kept the previous one", "error", err)
			}
		}
		return fmt.Errorf("install xray.json: %w", err)
	}
	keep = true

	if err := a.d.Xray.Restart(ctx, path, ports); err != nil {
		a.recover(ctx, path, prevPath, hasPrev, err)
		return err
	}
	// The new config is running; the copy kept for recovery is not needed
	// any more. A failure to remove it is harmless (the next apply
	// overwrites it) but not invisible: a state directory that has stopped
	// accepting writes is about to fail something that matters.
	if err := os.Remove(prevPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.d.Log.Warn("previous xray.json not cleaned up", "path", prevPath, "error", err)
	}
	return nil
}

// recover puts the previous xray.json back and starts the child on it
// after a failed restart, so probing continues on the old revision (spec
// §4 step 3). Failures here are logged, never returned: the error the
// operator must see is the one that broke the apply.
func (a *RevisionApplier) recover(ctx context.Context, path, prevPath string, hasPrev bool, cause error) {
	a.d.Log.Warn("xray did not restart on the new revision", "error", cause)
	if !hasPrev {
		return
	}
	if err := os.Rename(prevPath, path); err != nil {
		a.d.Log.Error("previous xray.json not restored", "error", err)
		return
	}
	a.mu.Lock()
	ports := a.ports
	a.mu.Unlock()
	if len(ports) == 0 {
		return
	}
	if err := a.d.Xray.Restart(ctx, path, ports); err != nil {
		a.d.Log.Error("xray did not come back on the previous revision", "error", err)
		return
	}
	a.d.Log.Info("xray restarted on the previous revision")
}

// buildProbes turns the parsed document into one probe.Fn per target:
// xray-targets through the loopback socks port their plan assigns (the
// port the child now listens on), AWG-targets through their parsed .conf.
//
// The xray child doubles as the probes' Diagnoser (spec §5): a Reality
// handshake that received a real certificate looks like a plain timeout
// from the outside and only xray's own stderr names it. A nil child is
// passed as a nil interface rather than a typed nil, which Prober.Xray
// documents as "classify without a second opinion".
func (a *RevisionApplier) buildProbes(doc *proto.ConfigDoc, plans []config.XrayPlan, awgs map[proto.TargetKey]*config.AWGConfig) map[proto.TargetKey]probe.Fn {
	probes := make(map[proto.TargetKey]probe.Fn, len(plans)+len(awgs))
	budgets := probe.BudgetsFrom(doc.Probe)
	token := a.token()

	var diag probe.Diagnoser
	if a.d.Xray != nil {
		diag = a.d.Xray
	}
	for _, plan := range plans {
		probes[plan.Key] = func(ctx context.Context, k proto.TargetKey) proto.Result {
			return a.d.XrayProber.Xray(ctx, doc.ProbeURL, token, k, plan, budgets, diag)
		}
	}
	for key, cfg := range awgs {
		probes[key] = func(ctx context.Context, k proto.TargetKey) proto.Result {
			return a.d.AWGProber.Probe(ctx, doc.ProbeURL, token, k, cfg, budgets)
		}
	}
	return probes
}

// token is the client token every probe carries (protocol §5.2), read
// under the lock because the applier shares its *state.File with the loop.
func (a *RevisionApplier) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.d.File == nil {
		return ""
	}
	return a.d.File.Token
}

// parseDoc turns a document into everything an apply needs: the xray.json
// generated from the xray-targets that parsed, the plan behind it, one
// parsed AWG config per AWG-target that parsed and passed awg.Check, and
// the targets that did not, each with the first line of its own error
// (decision #53 п. 3). A rejected target is left out of everything else,
// so it is neither in xray.json nor probed. The error is for the document
// as a whole — a generated config that could not be marshalled.
func parseDoc(doc *proto.ConfigDoc) ([]byte, []config.XrayPlan, map[proto.TargetKey]*config.AWGConfig, []proto.RejectedTarget, error) {
	var (
		accepted []proto.Target
		rejected []proto.RejectedTarget
		awgs     = make(map[proto.TargetKey]*config.AWGConfig)
	)
	reject := func(key proto.TargetKey, err error) {
		rejected = append(rejected, proto.RejectedTarget{Target: key.String(), Error: firstLine(err.Error())})
	}
	// The sweep targets (decision #100) are parsed and applied exactly like
	// the others — a bad one is rejected on its own — and only split off
	// when the probes are built (splitSweep).
	for _, t := range append(slices.Clip(doc.Targets), doc.SweepTargets...) {
		switch {
		case t.Link != "":
			// BuildXray parses the link again; parsing it here first is
			// what lets one bad link cost only its own target.
			if _, _, _, err := config.ParseLink(t.Link); err != nil {
				reject(t.TargetKey, err)
				continue
			}
			accepted = append(accepted, t)
		case t.Conf != "":
			cfg, err := config.ParseAWGConf(t.Conf)
			if err == nil {
				err = awg.Check(cfg)
			}
			if err != nil {
				reject(t.TargetKey, err)
				continue
			}
			awgs[t.TargetKey] = cfg
		default:
			reject(t.TargetKey, errors.New("target has neither a link nor a conf"))
		}
	}

	cfgJSON, plans, err := config.BuildXray(accepted, config.FirstSocksPort)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return cfgJSON, plans, awgs, rejected, nil
}

// splitSweep separates a revision's probes into the ones every cycle runs
// (the document's targets) and the ones only a diagnostic sweep runs (its
// sweepTargets). A key in both is an every-cycle target.
func splitSweep(doc *proto.ConfigDoc, all map[proto.TargetKey]probe.Fn) (probes, sweep map[proto.TargetKey]probe.Fn) {
	steady := make(map[proto.TargetKey]bool, len(doc.Targets))
	for _, t := range doc.Targets {
		steady[t.TargetKey] = true
	}
	probes = make(map[proto.TargetKey]probe.Fn, len(doc.Targets))
	sweep = make(map[proto.TargetKey]probe.Fn)
	for k, fn := range all {
		if steady[k] {
			probes[k] = fn
		} else {
			sweep[k] = fn
		}
	}
	return probes, sweep
}

// xrayKeys is the set of targets a revision probes through the xray child.
func xrayKeys(plans []config.XrayPlan) map[proto.TargetKey]bool {
	keys := make(map[proto.TargetKey]bool, len(plans))
	for _, p := range plans {
		keys[p.Key] = true
	}
	return keys
}

// socksPorts is the set of loopback ports the restarted child has to be
// listening on before the next cycle may probe (spec §4 step 3: "дождаться
// готовности socks-портов").
func socksPorts(plans []config.XrayPlan) []int {
	ports := make([]int, 0, len(plans))
	for _, p := range plans {
		ports = append(ports, p.SocksPort)
	}
	return ports
}

// firstLine is protocol §5.3's client.configError shape: the first line of
// an error, at most maxConfigError characters (spec §4 step 3).
func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	if len(text) > maxConfigError {
		text = text[:maxConfigError]
	}
	return text
}
