package state

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// The diagnostic sweep's timing (decision #100, CONTEXT.md: Diagnostic
// sweep).
var (
	// sweepSchedule is the wait from one run to the next: 1, 2, 5, 10 and
	// 15 minutes, then every 15. Any change of the picture starts it over.
	sweepSchedule = []time.Duration{1 * time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute}
)

const (
	// sweepDueSlack lets a run that is due a little after this heartbeat
	// go out with it rather than a whole cycle later: heartbeats come once
	// a minute, give or take the cycle's own length.
	sweepDueSlack = 15 * time.Second
	// sweepRequestStale is how long a run handed to a mon-client may stay
	// unanswered before it is handed out again — its cycle's heartbeat was
	// lost, or the mon-client is too old to know the job.
	sweepRequestStale = 3 * time.Minute
	// hopCheckStale is how old a hop's report of its next hop may be and
	// still count as current. A hop reports on every chain poll (~30 s),
	// over the very leg it checks, so a report this old says the leg went
	// quiet: the sweep shows "no report since" rather than a stale number.
	hopCheckStale = 3 * time.Minute
)

// ReasonICMPUnavailable is a host reachability check's reason when the
// mon-client could not open an ICMP socket at all (no ping_group_range for
// its group): nothing was measured, which is not 100% loss.
const ReasonICMPUnavailable = "icmp_unavailable"

// applySweep is the diagnostic sweep of decision #100, run in every
// heartbeat's transaction after the live cycle has moved the targets.
// For each inbound kind of this mon-client:
//
//   - a sweep starts when no edge-path of the kind is UP and every one is
//     DOWN or FLAPPING (UNKNOWN is not an outage yet); its first run is due
//     at once;
//   - the live cycle's run (Cycle.Sweep), if one was asked for, becomes the
//     report: the start event goes out with the first one, a change event
//     with every later one whose picture differs (the set of paths that
//     work and the ICMP category of every pair of nodes); the held targets
//     of the kind (direct, inner:*) take its verdict with reason sweep;
//     and the next run is scheduled — 1 minute after a start or change,
//     then 2, 5, 10, 15 and every 15;
//   - the sweep ends when an edge-path of the kind is UP again: the end
//     event carries the last report with the edge-paths as they are now.
//     A sweep that never reported ends silently — its outage was over
//     before anyone was told of it.
//
// It returns the run to hand the mon-client in this heartbeat's answer, nil
// when none is due.
func (e *Engine) applySweep(tx *gorm.DB, notify *notices, mc *store.MonClient, live *Cycle, excl registry.Exclusions, nowMs int64) (*SweepJob, error) {
	var rows []store.Target
	if err := tx.Where("mon_client_id = ?", mc.Id).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("state: read targets of %s: %w", mc.Id, err)
	}
	var sweeps []store.Sweep
	if err := tx.Where("mon_client_id = ?", mc.Id).Find(&sweeps).Error; err != nil {
		return nil, fmt.Errorf("state: read sweeps of %s: %w", mc.Id, err)
	}
	byKind := make(map[string]*store.Sweep, len(sweeps))
	kinds := map[string]bool{}
	for i := range sweeps {
		byKind[sweeps[i].InboundKind] = &sweeps[i]
		kinds[sweeps[i].InboundKind] = true
	}
	for _, t := range rows {
		if store.IsEdgePath(t.Path) {
			kinds[t.InboundKind] = true
		}
	}

	var due []string
	for _, kind := range sortedSet(kinds) {
		anyUp, allDown, hasEdges := edgeStatus(rows, kind)
		sw := byKind[kind]

		if sw != nil && sw.RequestedAt != nil && live != nil && live.Sweep != nil && slices.Contains(live.Sweep.Kinds, kind) {
			if err := e.takeSweepRun(tx, notify, mc, sw, kind, *live, excl, rows, anyUp, nowMs); err != nil {
				return nil, err
			}
		}

		// An edge-path UP again ends the sweep; so does having none left to
		// wait for (the mon-client's paths changed, the edges left the
		// chain), or the sweep would ask for runs forever.
		if sw != nil && (anyUp || !hasEdges) {
			if sw.Announced {
				report := endReport(sw.ReportValue(), kind, rows)
				if err := e.emitSweep(tx, notify, mc, kind, store.SweepPhaseEnd, report, nowMs); err != nil {
					return nil, err
				}
			}
			if err := tx.Delete(&store.Sweep{}, sw.Id).Error; err != nil {
				return nil, fmt.Errorf("state: end sweep of %s/%s: %w", mc.Id, kind, err)
			}
			continue
		}
		if sw == nil && allDown {
			sw = &store.Sweep{MonClientId: mc.Id, InboundKind: kind, StartedAt: nowMs, NextAt: nowMs}
			if err := tx.Create(sw).Error; err != nil {
				return nil, fmt.Errorf("state: start sweep of %s/%s: %w", mc.Id, kind, err)
			}
		}
		if sw == nil {
			continue
		}
		if sw.NextAt > nowMs+sweepDueSlack.Milliseconds() {
			continue
		}
		if sw.RequestedAt != nil && nowMs-*sw.RequestedAt < sweepRequestStale.Milliseconds() {
			continue
		}
		at := nowMs
		sw.RequestedAt = &at
		if err := tx.Save(sw).Error; err != nil {
			return nil, fmt.Errorf("state: schedule sweep of %s/%s: %w", mc.Id, kind, err)
		}
		due = append(due, kind)
	}
	if len(due) == 0 {
		return nil, nil
	}
	job := &SweepJob{Kinds: due, Hosts: []SweepJobHost{}}
	for _, h := range excl.Hosts {
		job.Hosts = append(job.Hosts, SweepJobHost{Name: h.Name, Host: h.Host})
	}
	return job, nil
}

// takeSweepRun files one run's results: the report and its event, the
// held targets' verdicts and the next run's time.
func (e *Engine) takeSweepRun(tx *gorm.DB, notify *notices, mc *store.MonClient, sw *store.Sweep, kind string, live Cycle, excl registry.Exclusions, rows []store.Target, anyUp bool, nowMs int64) error {
	sweepResults := make([]Result, 0, len(live.Sweep.Results))
	for _, r := range live.Sweep.Results {
		key := registry.TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundID, Path: r.Path}
		if r.InboundKind == kind && excl.Derived[key] {
			sweepResults = append(sweepResults, r)
		}
	}
	report := store.SweepReport{
		Paths: pathReport(kind, live.Results, sweepResults),
		Hosts: e.hostReport(excl, live, nowMs),
	}

	if err := e.applySweepVerdicts(tx, mc.Id, sweepResults, rows, anyUp, nowMs); err != nil {
		return err
	}

	// A run that lands in the heartbeat that also ends the sweep (an
	// edge-path is UP again) announces nothing: a sweep that was never
	// announced ends silently, and one that was ends with its end event.
	phase := ""
	switch {
	case anyUp:
	case !sw.Announced:
		phase = store.SweepPhaseStart
	case sweepPicture(report) != sweepPicture(sw.ReportValue()):
		phase = store.SweepPhaseChange
	}
	if phase != "" {
		sw.Step = 0
		sw.Announced = true
		if err := e.emitSweep(tx, notify, mc, kind, phase, report, nowMs); err != nil {
			return err
		}
	} else if sw.Step < len(sweepSchedule)-1 {
		sw.Step++
	}
	sw.NextAt = *sw.RequestedAt + sweepSchedule[sw.Step].Milliseconds()
	sw.RequestedAt = nil
	sw.SetReport(report)
	if err := tx.Save(sw).Error; err != nil {
		return fmt.Errorf("state: save sweep of %s/%s: %w", mc.Id, kind, err)
	}
	return nil
}

// applySweepVerdicts moves the held targets a run probed to what their
// tunnel probe said — UP or DOWN at once, no thresholds: a sweep run is
// minutes apart, and its whole point is the picture now — with reason
// sweep, notified (decision #100). PAUSED targets stay PAUSED. While an
// edge-path of the kind is UP again the inner ones are left to derived
// state, which takes them back in this same heartbeat; direct always keeps
// the result, as it has no other source.
func (e *Engine) applySweepVerdicts(tx *gorm.DB, monClientID string, results []Result, rows []store.Target, anyUp bool, nowMs int64) error {
	have := make(map[registry.TargetKey]store.Target, len(rows))
	for _, t := range rows {
		have[registry.TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path}] = t
	}
	for _, r := range results {
		if anyUp && store.IsInnerPath(r.Path) {
			continue
		}
		key := registry.TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundID, Path: r.Path}
		t, ok := have[key]
		if !ok {
			row, err := e.targetRow(tx, monClientID, r, nowMs)
			if err != nil {
				return err
			}
			t = *row
		}
		out := OutcomeOf(r)
		to, rowReason := store.TargetUp, ""
		if !out.Ok {
			to, rowReason = store.TargetDown, out.Reason
		}
		if t.State == store.TargetPaused || t.State == to {
			continue
		}
		if err := e.moveQuiet(tx, t, to, ReasonSweep, rowReason, nowMs); err != nil {
			return err
		}
	}
	return nil
}

// emitSweep files one kind "sweep" event (contract §4.6): notified=false
// normally, so the panel sends the summary; in PANEL_DOWN mon-server sends
// it itself, after the commit, and marks it notified.
func (e *Engine) emitSweep(tx *gorm.DB, notify *notices, mc *store.MonClient, kind, phase string, report store.SweepReport, nowMs int64) error {
	worthy := e.panelDown()
	ev, err := e.enqueue(tx, store.EventPayload{
		Ts:          nowMs,
		Kind:        eventKindSweep,
		MonClientID: mc.Id,
		InboundKind: kind,
		Phase:       phase,
		Report:      &report,
		Notified:    worthy,
	})
	if err != nil {
		return err
	}
	if worthy {
		notify.add(ev, tg.MsgSweep(mc.Name, mc.Region, kind, phase, sweepLines(report)))
	}
	return nil
}

// edgeStatus is the sweep's detector over one kind's edge-paths (the
// targets on edge:* or proxy that are not PAUSED): whether any is UP,
// whether there is at least one and every one is DOWN or FLAPPING, and
// whether there is any at all.
func edgeStatus(rows []store.Target, kind string) (anyUp, allDown, has bool) {
	n, down := 0, 0
	for _, t := range rows {
		if t.InboundKind != kind || !store.IsEdgePath(t.Path) || t.State == store.TargetPaused {
			continue
		}
		n++
		switch t.State {
		case store.TargetUp:
			anyUp = true
		case store.TargetDown, store.TargetFlapping:
			down++
		}
	}
	return anyUp, n > 0 && down == n, n > 0
}

// pathReport is a run's tunnel probes by path: the live cycle's own
// results of the kind (the edge-paths, and any other path the mon-client
// probes every cycle) and the run's held targets. A path with several
// inbounds of the kind works when any of them does — the question is
// whether traffic gets through that hop — and otherwise carries the first
// failure's reason. Edge-paths come first, then the inner ones, then
// direct.
func pathReport(kind string, results ...[]Result) []store.SweepPath {
	byPath := map[string]*store.SweepPath{}
	var order []string
	for _, list := range results {
		for _, r := range list {
			if r.InboundKind != kind {
				continue
			}
			p, ok := byPath[r.Path]
			if !ok {
				p = &store.SweepPath{Path: r.Path}
				byPath[r.Path] = p
				order = append(order, r.Path)
			}
			out := OutcomeOf(r)
			switch {
			case out.Ok:
				p.Ok, p.Reason = true, ""
			case !p.Ok && p.Reason == "":
				p.Reason = out.Reason
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := pathRank(order[i]), pathRank(order[j])
		if a != b {
			return a < b
		}
		return order[i] < order[j]
	})
	out := make([]store.SweepPath, 0, len(order))
	for _, p := range order {
		out = append(out, *byPath[p])
	}
	return out
}

func pathRank(p string) int {
	switch {
	case store.IsEdgePath(p):
		return 0
	case store.IsInnerPath(p):
		return 1
	default:
		return 2
	}
}

// hostReport is a run's host reachability checks: the mon-client's own, to
// every host it was given (no answer for one — at null), then every hop's
// check of its next hop as the panel last reported it (decision #100): no
// report, or one older than hopCheckStale, is at null with lastAt when
// there was one. Only the hops this mon-client was given are reported on.
func (e *Engine) hostReport(excl registry.Exclusions, live Cycle, nowMs int64) []store.SweepHostCheck {
	measured := make(map[string]HostCheck, len(live.Sweep.Hosts))
	for _, h := range live.Sweep.Hosts {
		measured[h.Name] = h
	}
	at := live.Ts
	if at <= 0 {
		at = nowMs
	}
	out := []store.SweepHostCheck{}
	hops := map[string]bool{}
	for _, h := range excl.Hosts {
		if h.Name != "" && h.Name != store.PathProxy {
			hops[h.Name] = true
		}
		check := store.SweepHostCheck{From: store.SweepFromMonClient, To: h.Name}
		if m, ok := measured[h.Name]; ok && m.Reason == nil && m.Sent > 0 {
			ts := at
			check.At = &ts
			check.Sent = m.Sent
			check.LossPct = clampPct(m.LossPct)
			check.RttAvgMs = m.RttAvgMs
			if check.LossPct == 100 {
				check.RttAvgMs = nil
			}
		}
		out = append(out, check)
	}

	chain := e.latestChain()
	if chain == nil {
		return out
	}
	for _, h := range chain.ProbedHops() {
		if !hops[h.Name] {
			continue
		}
		check := store.SweepHostCheck{From: h.Name, To: chain.NextName(h)}
		if c := h.NextHopCheck; c != nil && c.At > 0 {
			ts := c.At
			if nowMs-c.At > hopCheckStale.Milliseconds() {
				check.LastAt = &ts
			} else {
				check.At = &ts
				check.Sent = c.Sent
				check.LossPct = clampPct(c.LossPct)
				check.RttAvgMs = c.RttAvgMs
				if check.LossPct == 100 {
					check.RttAvgMs = nil
				}
			}
		}
		out = append(out, check)
	}
	return out
}

// latestChain is the chain of the panel's last GET /state, nil without a
// source or a chain.
func (e *Engine) latestChain() *panel.Chain {
	if e.chain == nil {
		return nil
	}
	return e.chain()
}

func clampPct(v int) int {
	return min(max(v, 0), 100)
}

// endReport is the end event's report: the last run's, with every
// edge-path of the kind as the targets show it now — the one that is UP
// again is what the end message names.
func endReport(last store.SweepReport, kind string, rows []store.Target) store.SweepReport {
	var edges []Result
	for _, t := range rows {
		if t.InboundKind != kind || !store.IsEdgePath(t.Path) || t.State == store.TargetPaused {
			continue
		}
		r := Result{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path, Ok: t.State == store.TargetUp}
		if !r.Ok && t.Reason != "" {
			reason := t.Reason
			r.Reason = &reason
		}
		edges = append(edges, r)
	}
	var rest []store.SweepPath
	for _, p := range last.Paths {
		if !store.IsEdgePath(p.Path) {
			rest = append(rest, p)
		}
	}
	return store.SweepReport{Paths: append(pathReport(kind, edges), rest...), Hosts: last.Hosts}
}

// sweepPicture is what "the picture changed" compares (decision #100): the
// paths that work and those that do not, and the ICMP category — 0%, some
// loss, all lost or no report — of every pair of nodes; not the numbers.
func sweepPicture(r store.SweepReport) string {
	var parts []string
	for _, p := range r.Paths {
		parts = append(parts, fmt.Sprintf("p %s %v", p.Path, p.Ok))
	}
	for _, h := range r.Hosts {
		parts = append(parts, fmt.Sprintf("h %s>%s %d", h.From, h.To, icmpCategory(h)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// icmpCategory buckets one check the way the summary's badges do: 0 for no
// loss, 1 for some, 2 for all lost or no report.
func icmpCategory(h store.SweepHostCheck) int {
	switch {
	case h.At == nil || h.LossPct >= 100:
		return 2
	case h.LossPct > 0:
		return 1
	default:
		return 0
	}
}

// sweepLines renders a report for mon-server's own Telegram message in
// PANEL_DOWN: one line per path, one per host reachability check.
func sweepLines(r store.SweepReport) []string {
	var out []string
	for _, p := range r.Paths {
		if p.Ok {
			out = append(out, fmt.Sprintf("tunnel %s ✅", p.Path))
		} else {
			out = append(out, fmt.Sprintf("tunnel %s ❌ %s", p.Path, p.Reason))
		}
	}
	for _, h := range r.Hosts {
		to := h.To
		if to == "" {
			to = "real"
		}
		badge := [...]string{"✅", "⚠️", "❌"}[icmpCategory(h)]
		switch {
		case h.At == nil && h.LastAt != nil:
			out = append(out, fmt.Sprintf("ICMP %s → %s %s no report since %s", h.From, to, badge,
				time.UnixMilli(*h.LastAt).UTC().Format("15:04")))
		case h.At == nil:
			out = append(out, fmt.Sprintf("ICMP %s → %s %s no report", h.From, to, badge))
		case h.RttAvgMs != nil:
			out = append(out, fmt.Sprintf("ICMP %s → %s %s %d%% · %d ms", h.From, to, badge, h.LossPct, *h.RttAvgMs))
		default:
			out = append(out, fmt.Sprintf("ICMP %s → %s %s %d%%", h.From, to, badge, h.LossPct))
		}
	}
	return out
}

// sortedSet is a string set in order.
func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
