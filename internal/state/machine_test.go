package state

import (
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testThresholds are spec §9.4's defaults, the values the transition table
// below is written against.
func testThresholds() Thresholds { return ThresholdsFrom(store.DefaultSettings()) }

var baseTime = time.Date(2025, 9, 12, 10, 0, 0, 0, time.UTC)

// ok and fail spell one live-cycle result in the table.
func ok() Outcome            { return Outcome{Ok: true} }
func fail(r string) Outcome  { return Outcome{Reason: r} }
func failNoReason() Outcome  { return OutcomeOf(Result{Ok: false}) }
func okResult() Outcome      { return OutcomeOf(Result{Ok: true}) }
func minute(n int) time.Time { return baseTime.Add(time.Duration(n) * time.Minute) }

// drive applies a sequence of results one simulated minute apart and
// returns the final row plus every transition in order.
func drive(start store.Target, th Thresholds, results []Outcome) (store.Target, []Transition) {
	cur := start
	var all []Transition
	for i, r := range results {
		next, evs := Step(cur, th, r, minute(i+1))
		cur = next
		all = append(all, evs...)
	}
	return cur, all
}

// target builds a starting row in the given state with the counters a
// target in that state plausibly has.
func target(state string, okN, failN int) store.Target {
	return store.Target{
		Id: 1, MonClientId: "ams-1", InboundKind: store.InboundKindXray, InboundId: 12, Path: store.PathProxy,
		State: state, Since: clock.Ms(baseTime), Transitions: "[]",
		ConsecutiveOk: okN, ConsecutiveFail: failN,
	}
}

// TestStep_TransitionTable is spec §7.2's table: every state, every
// threshold, as one plain table (architecture brief §4).
func TestStep_TransitionTable(t *testing.T) {
	th := testThresholds()

	cases := []struct {
		name    string
		start   store.Target
		results []Outcome
		want    string
		events  []Transition
	}{
		{
			name:    "UNKNOWN goes UP on the very first success",
			start:   target(store.TargetUnknown, 0, 0),
			results: []Outcome{okResult()},
			want:    store.TargetUp,
			events:  []Transition{{From: store.TargetUnknown, To: store.TargetUp, Reason: ReasonRecovered}},
		},
		{
			name:    "UNKNOWN needs downAfter failures to go DOWN",
			start:   target(store.TargetUnknown, 0, 0),
			results: []Outcome{fail("tcp_refused"), fail("tcp_refused")},
			want:    store.TargetUnknown,
		},
		{
			name:    "UNKNOWN reaches DOWN on the third failure",
			start:   target(store.TargetUnknown, 0, 0),
			results: []Outcome{fail("tcp_refused"), fail("tcp_refused"), fail("tcp_refused")},
			want:    store.TargetDown,
			events:  []Transition{{From: store.TargetUnknown, To: store.TargetDown, Reason: "tcp_refused"}},
		},
		{
			name:    "UP survives downAfter-1 failures",
			start:   target(store.TargetUp, 5, 0),
			results: []Outcome{fail("tls_timeout"), fail("tls_timeout")},
			want:    store.TargetUp,
		},
		{
			name:    "UP goes DOWN with the failing result's reason",
			start:   target(store.TargetUp, 5, 0),
			results: []Outcome{fail("tls_timeout"), fail("tls_timeout"), fail("tls_timeout")},
			want:    store.TargetDown,
			events:  []Transition{{From: store.TargetUp, To: store.TargetDown, Reason: "tls_timeout"}},
		},
		{
			name:    "a failure with no reason still produces http_error",
			start:   target(store.TargetUp, 5, 0),
			results: []Outcome{failNoReason(), failNoReason(), failNoReason()},
			want:    store.TargetDown,
			events:  []Transition{{From: store.TargetUp, To: store.TargetDown, Reason: ReasonHTTPError}},
		},
		{
			name:    "DOWN needs upAfter successes",
			start:   target(store.TargetDown, 0, 4),
			results: []Outcome{ok()},
			want:    store.TargetDown,
		},
		{
			name:    "DOWN recovers on the second success",
			start:   target(store.TargetDown, 0, 4),
			results: []Outcome{ok(), ok()},
			want:    store.TargetUp,
			events:  []Transition{{From: store.TargetDown, To: store.TargetUp, Reason: ReasonRecovered}},
		},
		{
			name:    "a failure resets the recovery streak",
			start:   target(store.TargetDown, 0, 4),
			results: []Outcome{ok(), fail("tcp_timeout"), ok()},
			want:    store.TargetDown,
		},
		{
			name:    "PAUSED ignores results entirely",
			start:   target(store.TargetPaused, 0, 0),
			results: []Outcome{ok(), fail("tcp_refused"), fail("tcp_refused"), fail("tcp_refused")},
			want:    store.TargetPaused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, evs := drive(tc.start, th, tc.results)
			if got.State != tc.want {
				t.Fatalf("state = %s, want %s (events %+v)", got.State, tc.want, evs)
			}
			if len(evs) != len(tc.events) {
				t.Fatalf("events = %+v, want %+v", evs, tc.events)
			}
			for i, want := range tc.events {
				// SinceMs is not part of this table — it is about which
				// transitions happen, not when the state being left began;
				// TestStep_TransitionCarriesTheStartOfTheStateItLeaves
				// covers that field on its own.
				got := evs[i]
				got.SinceMs = 0
				if got != want {
					t.Fatalf("event %d = %+v, want %+v", i, evs[i], want)
				}
			}
		})
	}
}

// TestStep_PausedKeepsEveryField pins the "results for a paused target
// change nothing" rule harder than the state column: counters and
// last_result_at must not move either, or the row would quietly disagree
// with the state it is in.
func TestStep_PausedKeepsEveryField(t *testing.T) {
	start := target(store.TargetPaused, 3, 0)
	got, evs := Step(start, testThresholds(), fail("tcp_refused"), minute(1))
	if got != start || evs != nil {
		t.Fatalf("Step on PAUSED = %+v / %+v, want the row untouched", got, evs)
	}
}

// flap drives n UP<->DOWN flips starting from UP, one result per minute:
// downAfter failures, then upAfter successes, repeatedly.
func flapResults(th Thresholds, flips int) []Outcome {
	var out []Outcome
	for i := 0; i < flips; i++ {
		if i%2 == 0 {
			for j := 0; j < th.DownAfter; j++ {
				out = append(out, fail("tcp_timeout"))
			}
		} else {
			for j := 0; j < th.UpAfter; j++ {
				out = append(out, ok())
			}
		}
	}
	return out
}

// TestStep_FlappingEntry checks spec §7.2's FLAPPING row: the flapN-th
// UP<->DOWN transition inside flapMin turns into one FLAPPING event
// instead of that transition's own, and arms the hold.
func TestStep_FlappingEntry(t *testing.T) {
	th := testThresholds()
	got, evs := drive(target(store.TargetUp, 3, 0), th, flapResults(th, th.FlapN))

	if got.State != store.TargetFlapping {
		t.Fatalf("state = %s, want FLAPPING (events %+v)", got.State, evs)
	}
	if len(evs) != th.FlapN {
		t.Fatalf("got %d events, want %d (one per transition, the last one FLAPPING): %+v", len(evs), th.FlapN, evs)
	}
	last := evs[len(evs)-1]
	if last.To != store.TargetFlapping || last.Reason != ReasonFlapping {
		t.Fatalf("last event = %+v, want a transition into FLAPPING with reason flapping", last)
	}
	if got.FlappingUntil == nil || *got.FlappingUntil != clock.Ms(minute(len(flapResults(th, th.FlapN))))+th.FlapHoldMin.Milliseconds() {
		t.Fatalf("flapping_until = %v, want the last result's time + flapHoldMin", got.FlappingUntil)
	}
}

// TestStep_FlappingIsQuietInside is issue #101: while FLAPPING, the
// target's flips underneath produce no events at all — not even "silent"
// ones, which the panel would turn into a false DOWN/UP row and Telegram
// message — and the row stays FLAPPING.
func TestStep_FlappingIsQuietInside(t *testing.T) {
	th := testThresholds()
	entry := flapResults(th, th.FlapN)
	inside := flapResults(th, 2)

	got, evs := drive(target(store.TargetUp, 3, 0), th, append(entry, inside...))
	if got.State != store.TargetFlapping {
		t.Fatalf("state = %s, want FLAPPING", got.State)
	}
	if insideEvents := evs[th.FlapN:]; len(insideEvents) != 0 {
		t.Fatalf("inside events = %+v, want none", insideEvents)
	}
}

// enterFlapping drives a fresh UP target into FLAPPING and returns the row
// and the time of its last result.
func enterFlapping(t *testing.T, th Thresholds) (store.Target, time.Time) {
	t.Helper()
	results := flapResults(th, th.FlapN)
	cur, _ := drive(target(store.TargetUp, 3, 0), th, results)
	if cur.State != store.TargetFlapping {
		t.Fatalf("setup: state = %s, want FLAPPING", cur.State)
	}
	return cur, minute(len(results))
}

// TestStep_FlappingAlternatingSingleResults is the production case behind
// issue #101: single failures and single successes alternating every
// minute used to read as UP→DOWN "recovered" and DOWN→UP flips. Each
// result changes the probe outcome, so each restarts the hold, and none of
// them is an event.
func TestStep_FlappingAlternatingSingleResults(t *testing.T) {
	th := testThresholds()
	cur, at := enterFlapping(t, th)

	for i := 0; i < 60; i++ {
		at = at.Add(time.Minute)
		r := ok()
		if i%2 == 0 {
			r = fail("awg_no_handshake")
		}
		var evs []Transition
		cur, evs = Step(cur, th, r, at)
		if len(evs) != 0 {
			t.Fatalf("result %d (%+v) inside FLAPPING produced %+v, want nothing", i, r, evs)
		}
		if cur.State != store.TargetFlapping {
			t.Fatalf("result %d: state = %s, want FLAPPING", i, cur.State)
		}
		if want := clock.Ms(at) + th.FlapHoldMin.Milliseconds(); *cur.FlappingUntil != want {
			t.Fatalf("result %d: flapping_until = %d, want %d (restarted by the outcome change)", i, *cur.FlappingUntil, want)
		}
	}
}

// settleAfterFlapping alternates single results inside FLAPPING, then
// feeds the steady outcome r one per minute until the target leaves
// FLAPPING, and returns every event of the steady part.
func settleAfterFlapping(t *testing.T, th Thresholds, r Outcome) (store.Target, []Transition, time.Time) {
	t.Helper()
	cur, at := enterFlapping(t, th)
	for i := 0; i < 6; i++ {
		at = at.Add(time.Minute)
		alt := ok()
		if i%2 == 0 {
			alt = fail("tls_timeout")
		}
		cur, _ = Step(cur, th, alt, at)
	}
	var all []Transition
	for i := 0; i < 60 && cur.State == store.TargetFlapping; i++ {
		at = at.Add(time.Minute)
		var evs []Transition
		cur, evs = Step(cur, th, r, at)
		all = append(all, evs...)
	}
	return cur, all, at
}

// TestStep_FlappingExitsUpRecovered: a steady run of successes for
// flapHoldMin ends FLAPPING with one FLAPPING → UP, reason recovered.
func TestStep_FlappingExitsUpRecovered(t *testing.T) {
	th := testThresholds()
	got, evs, _ := settleAfterFlapping(t, th, ok())
	if got.State != store.TargetUp {
		t.Fatalf("state = %s, want UP", got.State)
	}
	if len(evs) != 1 || evs[0].From != store.TargetFlapping || evs[0].To != store.TargetUp || evs[0].Reason != ReasonRecovered {
		t.Fatalf("events = %+v, want exactly one FLAPPING → UP (recovered)", evs)
	}
	if got.Reason != "" || got.FlappingUntil != nil || got.Transitions != "[]" {
		t.Fatalf("row after exit = %+v, want empty reason, no hold, empty window", got)
	}
}

// TestStep_FlappingExitsDownWithFailureReason: a steady run of failures
// ends FLAPPING with one FLAPPING → DOWN carrying the failure's reason.
func TestStep_FlappingExitsDownWithFailureReason(t *testing.T) {
	th := testThresholds()
	got, evs, _ := settleAfterFlapping(t, th, fail("awg_no_handshake"))
	if got.State != store.TargetDown {
		t.Fatalf("state = %s, want DOWN", got.State)
	}
	if len(evs) != 1 || evs[0].From != store.TargetFlapping || evs[0].To != store.TargetDown || evs[0].Reason != "awg_no_handshake" {
		t.Fatalf("events = %+v, want exactly one FLAPPING → DOWN (awg_no_handshake)", evs)
	}
	if got.Reason != "awg_no_handshake" {
		t.Fatalf("row reason = %q, want the failure's reason", got.Reason)
	}
}

// TestStep_FlappingExitWaitsForThreshold: a hold that has run out does not
// end FLAPPING on a streak too short to say what the target is (the old
// code read one success after failures as DOWN and left with http_error).
// The target leaves once the streak crosses its ordinary threshold.
func TestStep_FlappingExitWaitsForThreshold(t *testing.T) {
	th := testThresholds()
	cur, at := enterFlapping(t, th)

	// A failure (outcome change, hold restarts), then a single success,
	// then silence well past the hold.
	at = at.Add(time.Minute)
	cur, _ = Step(cur, th, fail("tcp_timeout"), at)
	at = at.Add(time.Minute)
	cur, _ = Step(cur, th, ok(), at)
	at = at.Add(2 * th.FlapHoldMin)

	// The first result after the hold: cur's streak is one success, short
	// of upAfter, so the hold settles nothing before this result; with it
	// the streak reaches upAfter and the target leaves as UP.
	next, evs := Step(cur, th, ok(), at)
	if next.State != store.TargetUp || len(evs) != 1 || evs[0].To != store.TargetUp || evs[0].Reason != ReasonRecovered {
		t.Fatalf("state %s, events %+v, want one FLAPPING → UP (recovered)", next.State, evs)
	}

	// The same row, but the first result after the hold is a failure: it
	// changes the outcome, so the target stays FLAPPING with a fresh hold
	// rather than leaving into anything.
	next, evs = Step(cur, th, fail("tcp_timeout"), at)
	if next.State != store.TargetFlapping || len(evs) != 0 {
		t.Fatalf("state %s, events %+v, want FLAPPING and no events", next.State, evs)
	}
	if want := clock.Ms(at) + th.FlapHoldMin.Milliseconds(); *next.FlappingUntil != want {
		t.Fatalf("flapping_until = %d, want %d", *next.FlappingUntil, want)
	}
}

// TestStep_FlappingServedHoldExitsBeforeTheResult: a hold that ran out on
// a settled streak ends FLAPPING before the arriving result is applied, so
// a single opposite result does not re-arm it (spec §7.2: the result is
// applied to the actual state).
func TestStep_FlappingServedHoldExitsBeforeTheResult(t *testing.T) {
	th := testThresholds()
	cur, at := enterFlapping(t, th)
	for i := 0; i < th.DownAfter; i++ {
		at = at.Add(time.Minute)
		cur, _ = Step(cur, th, fail("tcp_timeout"), at)
	}
	quiet := clock.FromMs(*cur.FlappingUntil).Add(time.Second)

	next, evs := Step(cur, th, ok(), quiet)
	if len(evs) != 1 || evs[0].From != store.TargetFlapping || evs[0].To != store.TargetDown || evs[0].Reason != "tcp_timeout" {
		t.Fatalf("events = %+v, want one FLAPPING → DOWN (tcp_timeout), never recovered", evs)
	}
	if next.State != store.TargetDown || next.ConsecutiveOk != 1 {
		t.Fatalf("row = %+v, want DOWN with the success counted towards upAfter", next)
	}
}

// TestStep_NoDownIsEverRecovered runs long pseudo-random result sequences
// with random gaps through the machine and checks the invariants of issue
// #101 on every step: no DOWN carries recovered, and a target that was
// FLAPPING before a result publishes nothing but its exit.
func TestStep_NoDownIsEverRecovered(t *testing.T) {
	th := testThresholds()
	rng := rand.New(rand.NewSource(101))
	reasons := []string{"tcp_timeout", "awg_no_handshake", "tls_timeout"}
	entries, exitsUp, exitsDown := 0, 0, 0

	for run := 0; run < 200; run++ {
		cur := target(store.TargetUnknown, 0, 0)
		at := baseTime
		// The walk switches between coin flips and steady runs of either
		// outcome, so targets both enter FLAPPING and leave it.
		mode, left := 0, 0
		for i := 0; i < 300; i++ {
			if left == 0 {
				mode, left = rng.Intn(3), 1+rng.Intn(25)
			}
			left--
			gap := time.Minute
			if rng.Intn(20) == 0 {
				gap = time.Duration(1+rng.Intn(40)) * time.Minute
			}
			at = at.Add(gap)
			failed := mode == 1 || (mode == 0 && rng.Intn(2) == 0)
			r := ok()
			if failed {
				r = fail(reasons[rng.Intn(len(reasons))])
			}

			wasFlapping := cur.State == store.TargetFlapping
			var evs []Transition
			cur, evs = Step(cur, th, r, at)
			for j, ev := range evs {
				if ev.To == store.TargetDown && ev.Reason == ReasonRecovered {
					t.Fatalf("run %d step %d: %+v is a DOWN with reason recovered", run, i, ev)
				}
				if wasFlapping && j == 0 && ev.From != store.TargetFlapping {
					t.Fatalf("run %d step %d: FLAPPING target published %+v, want only its exit", run, i, ev)
				}
				switch {
				case ev.To == store.TargetFlapping:
					entries++
				case ev.From == store.TargetFlapping && ev.To == store.TargetUp:
					exitsUp++
					if ev.Reason != ReasonRecovered {
						t.Fatalf("run %d step %d: %+v, want recovered on an UP exit", run, i, ev)
					}
				case ev.From == store.TargetFlapping:
					exitsDown++
				}
			}
			if wasFlapping && len(evs) > 0 && cur.State == store.TargetFlapping {
				t.Fatalf("run %d step %d: events %+v while staying FLAPPING", run, i, evs)
			}
		}
	}
	if entries == 0 || exitsUp == 0 || exitsDown == 0 {
		t.Fatalf("walk covered %d entries, %d UP exits, %d DOWN exits; want all three non-zero", entries, exitsUp, exitsDown)
	}
}

// TestStep_FlappingExit checks the exit: flapHoldMin with no change of
// probe outcome drops the target back to what its counters actually say,
// with one event.
func TestStep_FlappingExit(t *testing.T) {
	th := testThresholds()
	// One flip past the entry, so the target is really DOWN underneath
	// while FLAPPING masks it.
	cur, _ := drive(target(store.TargetUp, 3, 0), th, flapResults(th, th.FlapN+1))
	if cur.State != store.TargetFlapping {
		t.Fatalf("setup: state = %s, want FLAPPING", cur.State)
	}

	quiet := clock.FromMs(*cur.FlappingUntil).Add(time.Second)
	next, evs := Step(cur, th, fail("tcp_timeout"), quiet)
	if next.State != store.TargetDown {
		t.Fatalf("state after the hold = %s, want DOWN", next.State)
	}
	if len(evs) != 1 || evs[0].From != store.TargetFlapping || evs[0].To != store.TargetDown {
		t.Fatalf("events = %+v, want one FLAPPING → DOWN", evs)
	}
	if evs[0].Reason != "tcp_timeout" {
		t.Fatalf("exit reason = %q, want the last failure's reason", evs[0].Reason)
	}
	if next.FlappingUntil != nil || next.Transitions != "[]" {
		t.Fatalf("hold/window not cleared on exit: %v / %s", next.FlappingUntil, next.Transitions)
	}
}

// TestStep_FlappingExitToUp covers the other exit: a target that settled
// healthy leaves FLAPPING as UP with reason recovered.
func TestStep_FlappingExitToUp(t *testing.T) {
	th := testThresholds()
	cur, _ := drive(target(store.TargetUp, 3, 0), th, append(flapResults(th, th.FlapN), ok(), ok()))
	if cur.State != store.TargetFlapping {
		t.Fatalf("setup: state = %s, want FLAPPING", cur.State)
	}

	quiet := clock.FromMs(*cur.FlappingUntil).Add(time.Second)
	next, evs := Step(cur, th, ok(), quiet)
	if next.State != store.TargetUp {
		t.Fatalf("state after the hold = %s, want UP", next.State)
	}
	if len(evs) != 1 || evs[0].To != store.TargetUp || evs[0].Reason != ReasonRecovered {
		t.Fatalf("events = %+v, want one FLAPPING → UP (recovered)", evs)
	}
}

// TestStep_FlappingHoldRestartsOnEveryFlip pins spec §7.2's exit condition
// — flapHoldMin *without a change of probe outcome*, not flapHoldMin after
// entering: a target that keeps flipping stays FLAPPING however long that
// takes.
func TestStep_FlappingHoldRestartsOnEveryFlip(t *testing.T) {
	th := testThresholds()
	cur, _ := drive(target(store.TargetUp, 3, 0), th, flapResults(th, th.FlapN))
	entered := *cur.FlappingUntil

	// One more flip, well inside the hold.
	for _, r := range flapResults(th, 1) {
		cur, _ = Step(cur, th, r, clock.FromMs(entered).Add(-time.Minute))
	}
	if cur.State != store.TargetFlapping {
		t.Fatalf("state = %s, want FLAPPING", cur.State)
	}
	if *cur.FlappingUntil <= entered {
		t.Fatalf("flapping_until = %d, want it pushed out past %d by the new transition", *cur.FlappingUntil, entered)
	}
}

// TestStep_FlapWindowExpires checks the other half of the FLAPPING rule:
// transitions older than flapMin do not count, so a target that flips
// slowly never becomes FLAPPING.
func TestStep_FlapWindowExpires(t *testing.T) {
	th := testThresholds()
	cur := target(store.TargetUp, 3, 0)
	at := baseTime
	for i := 0; i < th.FlapN+2; i++ {
		results := flapResults(th, 1)
		if i%2 == 1 {
			results = []Outcome{ok(), ok()}
		}
		for _, r := range results {
			at = at.Add(th.FlapMin/2 + time.Minute)
			cur, _ = Step(cur, th, r, at)
		}
		if cur.State == store.TargetFlapping {
			t.Fatalf("became FLAPPING on flip %d even though the flips are %s apart", i, th.FlapMin/2+time.Minute)
		}
	}
}

// TestRecordTransition_PrunesTheWindow is the window helper on its own: it
// keeps only what is inside flapMin and always counts the new transition.
func TestRecordTransition_PrunesTheWindow(t *testing.T) {
	now := clock.Ms(baseTime)
	old := now - int64(31*time.Minute/time.Millisecond)
	recent := now - int64(2*time.Minute/time.Millisecond)

	raw, n := recordTransition(`[`+strconv.FormatInt(old, 10)+`,`+strconv.FormatInt(recent, 10)+`]`, now, 30*time.Minute)
	if n != 2 {
		t.Fatalf("count = %d, want 2 (the recent one plus the new one)", n)
	}
	if got := decodeTransitions(raw); len(got) != 2 || got[0] != recent || got[1] != now {
		t.Fatalf("window = %v, want [%d %d]", got, recent, now)
	}
}

// TestRecordTransition_CorruptWindow proves a column this package cannot
// decode restarts rather than failing the heartbeat that hit it.
func TestRecordTransition_CorruptWindow(t *testing.T) {
	now := clock.Ms(baseTime)
	raw, n := recordTransition("not json", now, 30*time.Minute)
	if n != 1 || len(decodeTransitions(raw)) != 1 {
		t.Fatalf("recordTransition on a corrupt window = %q / %d, want a fresh one-entry window", raw, n)
	}
}

// TestThresholdsFrom_ClampsNonsense checks the settings guard: a zero or
// negative threshold (an admin can save one) degrades to 1 rather than
// making the machine fire on every result.
func TestThresholdsFrom_ClampsNonsense(t *testing.T) {
	th := ThresholdsFrom(&store.Settings{DownAfter: 0, UpAfter: -2, FlapN: 0, FlapMin: 0, FlapHoldMin: -1})
	if th.DownAfter != 1 || th.UpAfter != 1 || th.FlapN != 1 || th.FlapMin != time.Minute || th.FlapHoldMin != time.Minute {
		t.Fatalf("thresholds = %+v, want everything clamped to the minimum", th)
	}
}

// TestStep_TransitionCarriesTheStartOfTheStateItLeaves pins
// Transition.SinceMs, which spec §7.2's "UP" row depends on: the DOWN → UP
// message has to say how long the target was down, and only the machine
// still knows when the DOWN began by the time the row is rewritten.
func TestStep_TransitionCarriesTheStartOfTheStateItLeaves(t *testing.T) {
	th := testThresholds()

	// A target that went DOWN at minute 1 and recovers at minute 5.
	cur := target(store.TargetUp, 0, 0)
	cur.Since = clock.Ms(minute(0))
	var evs []Transition
	for i := 1; i <= 3; i++ {
		cur, evs = Step(cur, th, fail("tls_timeout"), minute(i))
	}
	if len(evs) != 1 || evs[0].To != store.TargetDown {
		t.Fatalf("events = %+v, want one UP → DOWN", evs)
	}
	if evs[0].SinceMs != clock.Ms(minute(0)) {
		t.Fatalf("SinceMs = %d, want the start of UP (%d)", evs[0].SinceMs, clock.Ms(minute(0)))
	}
	downSince := clock.Ms(minute(3))
	if cur.Since != downSince {
		t.Fatalf("row Since = %d, want the moment it went DOWN (%d)", cur.Since, downSince)
	}

	for i := 4; i <= 5; i++ {
		cur, evs = Step(cur, th, ok(), minute(i))
	}
	if len(evs) != 1 || evs[0].From != store.TargetDown || evs[0].To != store.TargetUp {
		t.Fatalf("events = %+v, want one DOWN → UP", evs)
	}
	if evs[0].SinceMs != downSince {
		t.Fatalf("SinceMs = %d, want the start of DOWN (%d): that is the downtime the message reports",
			evs[0].SinceMs, downSince)
	}
}
