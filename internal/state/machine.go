package state

import (
	"encoding/json"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Thresholds are spec §7.2's knobs in the units the machine reasons in.
// They are read from the settings table on every heartbeat (never cached),
// because an administrator can change them at runtime and the next cycle is
// expected to use the new values.
type Thresholds struct {
	// DownAfter is how many consecutive failures of live cycles make a
	// target DOWN (default 3).
	DownAfter int
	// UpAfter is how many consecutive successes bring a DOWN target back to
	// UP (default 2). A target leaving UNKNOWN does not wait for it: spec
	// §7.2 calls the first success the starting state.
	UpAfter int
	// FlapN is how many UP<->DOWN transitions inside FlapMin make a target
	// FLAPPING (default 4).
	FlapN int
	// FlapMin is the sliding window FlapN transitions are counted over
	// (default 30 min).
	FlapMin time.Duration
	// FlapHoldMin is how long FLAPPING must go without a change of probe
	// outcome (ok<->fail) before the target drops back to its actual state
	// (default 15 min).
	FlapHoldMin time.Duration
}

// ThresholdsFrom converts stored settings (spec §9.4) into Thresholds,
// forcing every count to at least 1 and every window to at least a minute.
// A zero or negative threshold — which the settings table can hold, since
// it stores whatever an admin typed — would otherwise make the machine
// degenerate (downAfter 0 means "DOWN before any result"), and refusing to
// run at all would be worse than clamping.
func ThresholdsFrom(set *store.Settings) Thresholds {
	return Thresholds{
		DownAfter:   atLeast(set.DownAfter, 1),
		UpAfter:     atLeast(set.UpAfter, 1),
		FlapN:       atLeast(set.FlapN, 1),
		FlapMin:     time.Duration(atLeast(set.FlapMin, 1)) * time.Minute,
		FlapHoldMin: time.Duration(atLeast(set.FlapHoldMin, 1)) * time.Minute,
	}
}

func atLeast(v, min int) int {
	if v < min {
		return min
	}
	return v
}

// Outcome is one live-cycle probe result reduced to what the machine
// actually decides on: did it work, and if not, what did the mon-client
// blame. Reason is already defaulted to ReasonHTTPError for a failure the
// mon-client left unexplained, so the machine never has to invent one.
type Outcome struct {
	Ok     bool
	Reason string
}

// OutcomeOf reduces a wire Result to an Outcome (protocol §5.3: `reason` is
// nullable, and a null on a failing result still has to produce an event
// with a reason in it).
func OutcomeOf(r Result) Outcome {
	if r.Ok {
		return Outcome{Ok: true}
	}
	reason := ReasonHTTPError
	if r.Reason != nil && *r.Reason != "" {
		reason = *r.Reason
	}
	return Outcome{Reason: reason}
}

// Transition is one state change the machine decided on: what the panel's
// event feed (contract §4.6) and, in PANEL_DOWN, Telegram will carry.
// Every transition is a real one: the target's flips inside FLAPPING are
// not transitions at all (see stepFlapping).
type Transition struct {
	From   string
	To     string
	Reason string
	// SinceMs is when the From state began — Target.Since as it stood
	// before this transition rewrote it. Spec §7.2's "UP" row needs it: the
	// Telegram message for DOWN → UP has to carry how long the target was
	// down, and once the row is saved that start time is gone.
	SinceMs int64
}

// Step is the state machine of spec §7.2 as a pure function: it takes a
// target row, the thresholds, one live-cycle result and mon-server's
// receive time, and returns the row as it should now be plus the
// transitions to publish. Nothing here touches the database, the clock or
// the notifier, which is what lets the whole transition table be tested as
// a plain table (docs/agents/testing.md) and what keeps "when does a target
// go DOWN" readable in one place.
//
// A PAUSED target is returned untouched: its inbound is not in the config
// at all (spec §4 step 3), so a result for it is stale and must not move
// any state.
func Step(cur store.Target, th Thresholds, res Outcome, now time.Time) (store.Target, []Transition) {
	if cur.State == store.TargetPaused {
		return cur, nil
	}

	nowMs := clock.Ms(now)
	next := cur
	var evs []Transition

	// FLAPPING first: a hold that ran out before this result means the
	// target has already gone flapHoldMin without its probe outcome
	// changing, so it leaves FLAPPING on the streak that served the hold,
	// and this result lands in the state the target has actually returned
	// to (spec §7.2: "flapHoldMin без смены исхода → фактическое состояние").
	if next.State == store.TargetFlapping && holdServed(cur, nowMs) {
		if to, ok := settledState(cur, th); ok {
			evs = append(evs, leaveFlapping(&next, to, cur.Reason, nowMs))
		}
	}

	// Whether this result changes the probe outcome (ok<->fail) is read
	// off the counters before they move: after any result exactly one of
	// them is non-zero and names the last outcome.
	outcomeChanged := !lastOutcomeIs(cur, res.Ok)

	next.LastResultAt = &nowMs
	if res.Ok {
		next.ConsecutiveOk++
		next.ConsecutiveFail = 0
	} else {
		next.ConsecutiveFail++
		next.ConsecutiveOk = 0
	}

	if next.State == store.TargetFlapping {
		// Still FLAPPING means the block above did not leave it, so there
		// are no earlier events to keep.
		return stepFlapping(next, th, res, outcomeChanged, nowMs)
	}

	want := next.State
	switch {
	case res.Ok && next.State == store.TargetUnknown:
		// Spec §7.2: the first success is the starting state, with no
		// upAfter wait — a fresh target that works should not spend a
		// minute claiming to be unknown.
		want = store.TargetUp
	case res.Ok && next.State == store.TargetDown && next.ConsecutiveOk >= th.UpAfter:
		want = store.TargetUp
	case !res.Ok && next.State != store.TargetDown && next.ConsecutiveFail >= th.DownAfter:
		want = store.TargetDown
	}
	if want == next.State {
		return next, evs
	}

	from := next.State
	// The start of the state being left, captured before Since is rewritten:
	// it is what a DOWN → UP transition reports as the downtime (spec §7.2).
	fromSince := next.Since
	if isUpDown(from) && isUpDown(want) {
		var n int
		next.Transitions, n = recordTransition(next.Transitions, nowMs, th.FlapMin)
		if n >= th.FlapN {
			until := nowMs + th.FlapHoldMin.Milliseconds()
			next.State = store.TargetFlapping
			next.Since = nowMs
			next.FlappingUntil = &until
			next.Reason = rowReason(res)
			return next, append(evs, Transition{From: from, To: store.TargetFlapping, Reason: ReasonFlapping, SinceMs: fromSince})
		}
	}

	next.State = want
	next.Since = nowMs
	next.Reason = rowReason(res)
	return next, append(evs, Transition{From: from, To: want, Reason: eventReason(res), SinceMs: fromSince})
}

// stepFlapping is one result applied to a target that is (still) FLAPPING,
// with its counters already moved. The whole point of FLAPPING is that the
// target keeps flipping underneath while the panel shows one unstable
// target, so nothing inside it is published (issue #101): no UP/DOWN
// events, silent or otherwise — the panel moves its row and sends Telegram
// on every target event it gets with notified=false, so a "silent" flip
// still reached the administrator as a false DOWN/UP. The only events a
// FLAPPING target produces are entering it and leaving it.
//
// The hold restarts on every change of probe outcome (ok<->fail) — not on
// UP<->DOWN flips guessed from a streak too short to cross a threshold,
// which is what used to restart it. A hold that has run out ends the state as soon as the
// current streak crosses its normal threshold (downAfter failures or
// upAfter successes): until it does, the counters do not say what the
// target actually is, and guessing would bring back the very false DOWN
// after a single success this function exists to avoid.
func stepFlapping(next store.Target, th Thresholds, res Outcome, outcomeChanged bool, nowMs int64) (store.Target, []Transition) {
	// The row keeps the last failure's diagnosis while the streak is
	// failing, so a hold served before the next result (Step's first
	// block) can leave into DOWN with the reason that put it there.
	next.Reason = rowReason(res)
	if outcomeChanged {
		until := nowMs + th.FlapHoldMin.Milliseconds()
		next.FlappingUntil = &until
		return next, nil
	}
	if holdServed(next, nowMs) {
		if to, ok := settledState(next, th); ok {
			ev := leaveFlapping(&next, to, next.Reason, nowMs)
			return next, []Transition{ev}
		}
	}
	return next, nil
}

// leaveFlapping moves t out of FLAPPING into to and returns the one event
// that announces it. A DOWN exit carries the last failure's reason
// (failReason, the row's reason while the failing streak lasted); an UP
// exit carries recovered. DOWN never carries recovered: settledState only
// answers DOWN for a failing streak.
func leaveFlapping(t *store.Target, to, failReason string, nowMs int64) Transition {
	reason := ReasonRecovered
	if to == store.TargetDown {
		reason = lastFailureReason(failReason)
	}
	ev := Transition{From: store.TargetFlapping, To: to, Reason: reason, SinceMs: t.Since}
	t.State = to
	t.Since = nowMs
	t.FlappingUntil = nil
	// The window is cleared with the hold: it has just been served, and
	// keeping the four old transitions would send the target straight back
	// into FLAPPING on the very next flip, which would make the cooldown
	// meaningless.
	t.Transitions = "[]"
	if to == store.TargetUp {
		t.Reason = ""
	} else {
		t.Reason = reason
	}
	return ev
}

// holdServed reports whether t's FLAPPING hold has run out by nowMs. A
// FLAPPING row without a hold (which this package never writes) is treated
// as still holding; its next outcome change arms one.
func holdServed(t store.Target, nowMs int64) bool {
	return t.FlappingUntil != nil && nowMs >= *t.FlappingUntil
}

// settledState is what a FLAPPING target's current streak says it actually
// is, by the ordinary thresholds: DOWN after downAfter failures in a row,
// UP after upAfter successes in a row. A streak still short of its
// threshold settles nothing (ok=false) and the target stays FLAPPING.
func settledState(t store.Target, th Thresholds) (string, bool) {
	switch {
	case t.ConsecutiveFail >= th.DownAfter:
		return store.TargetDown, true
	case t.ConsecutiveOk >= th.UpAfter:
		return store.TargetUp, true
	default:
		return "", false
	}
}

// lastOutcomeIs reports whether t's last result had outcome ok. A row with
// no result at all has no last outcome, so any result counts as a change.
func lastOutcomeIs(t store.Target, ok bool) bool {
	if ok {
		return t.ConsecutiveOk > 0
	}
	return t.ConsecutiveFail > 0
}

// isUpDown reports whether s is one of the two states whose flips feed the
// FLAPPING window (spec §7.2 counts UP<->DOWN transitions; leaving UNKNOWN
// or PAUSED is a config or liveness event, not instability).
func isUpDown(s string) bool { return s == store.TargetUp || s == store.TargetDown }

// eventReason is the reason a result-driven transition publishes: the
// mon-client's own diagnosis for a failure, ReasonRecovered for every
// transition into UP (spec §7.2's "UP" row).
func eventReason(res Outcome) string {
	if res.Ok {
		return ReasonRecovered
	}
	return res.Reason
}

// rowReason is what the target row keeps as its current reason: a failure's
// diagnosis, or nothing at all while the target is working (the admin UI
// and the panel show this field next to the state, where a stale
// "tls_timeout" on a healthy target would be actively misleading).
func rowReason(res Outcome) string {
	if res.Ok {
		return ""
	}
	return res.Reason
}

// lastFailureReason falls back to ReasonHTTPError when a target somehow
// reaches DOWN with no recorded reason (a row written before this code, or
// a failure the mon-client never explained): an event's reason field must
// always carry a dictionary value.
func lastFailureReason(reason string) string {
	if reason == "" {
		return ReasonHTTPError
	}
	return reason
}

// recordTransition appends now to the sliding UP<->DOWN window stored in
// Target.Transitions, dropping everything older than window, and returns
// the new JSON and how many transitions are left inside it — the number
// spec §7.2 compares against flapN. A column that fails to decode (only
// this package writes it) restarts from an empty window rather than
// failing the whole heartbeat.
func recordTransition(raw string, nowMs int64, window time.Duration) (string, int) {
	kept := make([]int64, 0, 8)
	cutoff := nowMs - window.Milliseconds()
	for _, ts := range decodeTransitions(raw) {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, nowMs)

	b, err := json.Marshal(kept)
	if err != nil {
		// Marshalling a []int64 cannot fail.
		panic("state: marshal transitions: " + err.Error())
	}
	return string(b), len(kept)
}

// decodeTransitions reads Target.Transitions, treating an empty or corrupt
// value as "no transitions recorded" (see recordTransition).
func decodeTransitions(raw string) []int64 {
	if raw == "" {
		return nil
	}
	var out []int64
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
