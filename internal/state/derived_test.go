package state

import (
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

var keyAwgInner = registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0, Path: "inner:core-1"}

// onEdges describes a mon-client on paths edges on a chained panel (edge-a,
// edge-b, inner core-1; decision #100): it probes the two edges every
// cycle and holds direct and the inner hop as derived targets — xray on
// both, AWG on the inner hop only.
func onEdges() registry.Exclusions {
	x := chained([]string{"edge:edge-a", "edge:edge-b", "inner:core-1"}, "edge:edge-a", "edge:edge-b")
	x.Monitored = map[string]bool{store.PathDirect: true, "edge:edge-a": true, "edge:edge-b": true, "inner:core-1": true}
	x.Derived = map[registry.TargetKey]bool{keyDirect: true, keyInner: true, keyAwgInner: true}
	return x
}

// eventsFor is the outbox's target events for one key.
func (f *fixture) eventsFor(key registry.TargetKey) []store.EventPayload {
	var out []store.EventPayload
	for _, ev := range f.events() {
		if ev.Kind == eventKindTarget && ev.InboundKind == key.InboundKind && *ev.InboundID == key.InboundID && ev.Path == key.Path {
			out = append(out, ev)
		}
	}
	return out
}

// TestHeartbeat_DerivedStateFollowsTheEdges is decision #100's derived
// state: a mon-client on edges holds direct and the inner hop without
// probing them. The inner target goes UP as soon as an edge-path of the
// same inbound kind is UP — one event, reason derived, notified, and no
// Telegram even while the panel is down — and stays as it is when every
// edge goes DOWN (the diagnostic sweep settles it). direct has no derived
// state: it waits in UNKNOWN for the first sweep. An inbound kind with no
// edge-path UP leaves its inner target alone.
func TestHeartbeat_DerivedStateFollowsTheEdges(t *testing.T) {
	f := newFixture(t)
	f.panelDown = true
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)
	f.cfg.keys = []registry.TargetKey{keyEdgeA, keyEdgeB}
	f.cfg.excl = onEdges()

	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyEdgeA, true, ""), result(keyEdgeB, false, "tcp_timeout")))

	if got := f.targetState(keyInner); got.State != store.TargetUp {
		t.Fatalf("inner target = %s, want UP derived from edge-a", got.State)
	}
	evs := f.eventsFor(keyInner)
	if len(evs) != 1 || evs[0].From != store.TargetUnknown || evs[0].To != store.TargetUp ||
		evs[0].Reason != ReasonDerived || !evs[0].Notified {
		t.Fatalf("inner events = %+v, want one notified UNKNOWN → UP derived", evs)
	}
	if got := f.targetState(keyDirect); got.State != store.TargetUnknown {
		t.Fatalf("direct target = %s, want UNKNOWN until a sweep", got.State)
	}
	if evs := f.eventsFor(keyDirect); len(evs) != 0 {
		t.Fatalf("direct events = %+v, want none", evs)
	}
	if got := f.targetState(keyAwgInner); got.State != store.TargetUnknown {
		t.Fatalf("awg inner target = %s, want UNKNOWN: no AWG edge-path is UP", got.State)
	}
	for _, msg := range f.tgr.Sent {
		if strings.Contains(msg, "inner:core-1") {
			t.Fatalf("Telegram was sent %q, want derived state silent", msg)
		}
	}

	// Every edge goes DOWN: the inner target keeps its state, no event.
	seq := int64(1)
	for i := 0; i < 3; i++ {
		seq++
		f.clk.Advance(time.Minute)
		f.beat(f.cycle(seq, result(keyEdgeA, false, "tcp_timeout"), result(keyEdgeB, false, "tcp_timeout")))
	}
	if got := f.targetState(keyEdgeA); got.State != store.TargetDown {
		t.Fatalf("edge-a = %s, want DOWN", got.State)
	}
	if got := f.targetState(keyInner); got.State != store.TargetUp {
		t.Fatalf("inner target = %s after every edge went DOWN, want it left UP", got.State)
	}
	if evs := f.eventsFor(keyInner); len(evs) != 1 {
		t.Fatalf("inner events = %+v, want still the one", evs)
	}
}

// TestHeartbeat_DerivedStateRecoversAfterOffline checks the derived
// targets through a liveness move: OFFLINE drives them to UNKNOWN like any
// target, and the first heartbeat with an edge UP brings the inner one
// back, derived.
func TestHeartbeat_DerivedStateRecoversAfterOffline(t *testing.T) {
	f := newFixture(t)
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)
	f.cfg.keys = []registry.TargetKey{keyEdgeA, keyEdgeB}
	f.cfg.excl = onEdges()
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyEdgeA, true, "")))

	f.clk.Advance(f.offlineSilence() + time.Minute)
	f.sweep(baseTime)
	if got := f.targetState(keyInner); got.State != store.TargetUnknown || got.Reason != ReasonMonClientOffline {
		t.Fatalf("inner target after OFFLINE = %s/%s, want UNKNOWN/mon_client_offline", got.State, got.Reason)
	}

	f.beat(f.cycle(2, result(keyEdgeB, true, "")))
	if got := f.targetState(keyInner); got.State != store.TargetUp {
		t.Fatalf("inner target = %s, want UP derived from edge-b", got.State)
	}
}

// TestHeartbeat_PausedTargetBecomesDerived checks the switch of a
// mon-client from an explicit vocabulary to edges: a target that was PAUSED
// path_removed (the box did not probe the inner hop) is now one it holds
// derived, so it is released to UNKNOWN and then follows the edges. A
// target PAUSED by its inbound is left alone.
func TestHeartbeat_PausedTargetBecomesDerived(t *testing.T) {
	f := newFixture(t)
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)
	f.cfg.keys = []registry.TargetKey{keyEdgeA}
	f.cfg.excl = chained([]string{"edge:edge-a", "inner:core-1"}, "edge:edge-a")
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyEdgeA, true, ""), result(keyInner, true, "")))
	seed := store.Target{MonClientId: f.mc.Id, InboundKind: store.InboundKindXray, InboundId: 12, Path: "inner:core-1",
		State: store.TargetPaused, Reason: ReasonPathRemoved, Transitions: "[]"}
	if err := f.st.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	x := chained([]string{"edge:edge-a", "inner:core-1"}, "edge:edge-a")
	x.Monitored = map[string]bool{"edge:edge-a": true, "inner:core-1": true}
	x.Derived = map[registry.TargetKey]bool{keyInner: true}
	f.cfg.excl = x
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2, result(keyEdgeA, true, "")))

	evs := f.eventsFor(keyInner)
	if len(evs) != 2 || evs[0].Reason != ReasonConfigEnabled || evs[1].Reason != ReasonDerived || evs[1].To != store.TargetUp {
		t.Fatalf("inner events = %+v, want config_enabled then derived UP", evs)
	}
}
