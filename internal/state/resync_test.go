package state

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// resyncFixture is the engine fixture plus the stats flush that carries the
// panel's resync request: a real Buckets over the same store and fake
// clock, answering to a paneltest stub through the real HTTP client. The
// outbox the engine writes is where every assertion looks.
type resyncFixture struct {
	*fixture
	b    *Buckets
	stub *paneltest.Stub
	cl   panel.Client
	seq  int64
}

func newResyncFixture(t *testing.T) *resyncFixture {
	t.Helper()
	f := newFixture(t)
	stub := paneltest.NewStub(t)
	cl := panel.NewHTTPClient(stub.URL(), stub.Token(), f.clk,
		panel.WithSleeper(func(context.Context, time.Duration) error { return nil }))
	b := NewBuckets(f.st, f.clk)
	b.SetResyncer(f.e)
	return &resyncFixture{fixture: f, b: b, stub: stub, cl: cl, seq: 100}
}

// ref names a target of the fixture's mon-client the way the panel does.
func (f *resyncFixture) ref(key registry.TargetKey) panel.TargetRef {
	return panel.TargetRef{MonClientId: f.mc.Id, InboundKind: key.InboundKind, InboundId: key.InboundID, Path: key.Path}
}

// statsCycle runs one stats cycle the way the poller does: a bucket's
// worth of data, the clock past its close, and a Flush that POSTs it — the
// only request whose answer can carry the panel's resync request.
func (f *resyncFixture) statsCycle() {
	f.t.Helper()
	f.seq++
	if err := f.b.Record(context.Background(), f.st.DB, f.mc.Id,
		[]Cycle{{Seq: f.seq, Ts: clock.Ms(f.clk.Now()), Results: []Result{statOK(40)}}}); err != nil {
		f.t.Fatalf("Record: %v", err)
	}
	f.clk.Advance(bucketWindow + bucketCloseDelay)
	if err := f.b.Flush(context.Background(), f.cl); err != nil {
		f.t.Fatalf("Flush: %v", err)
	}
}

// resyncEvents is the outbox's resync events, in insertion order.
func (f *resyncFixture) resyncEvents() []eventView {
	f.t.Helper()
	var out []eventView
	for _, ev := range f.events() {
		if ev.Reason == ReasonResync {
			out = append(out, eventView{ev.ID, ev.Ts, ev.Kind, ev.MonClientID, ev.InboundKind, ev.InboundID, ev.Path, ev.From, ev.To, ev.Notified})
		}
	}
	return out
}

type eventView struct {
	id          string
	ts          int64
	kind        string
	monClientID string
	inboundKind string
	inboundID   *int
	path        string
	from, to    string
	notified    bool
}

// TestResync_NamedUpTargetGetsOneEvent is decision #151 Q3: a target the
// panel names in its stats answer, and that mon-server holds in UP, gets
// exactly one resync event — an ordinary target event confirming the
// current state (from = to = UP), already notified so the panel stays
// silent, with a fresh id.
func TestResync_NamedUpTargetGetsOneEvent(t *testing.T) {
	f := newResyncFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	before := f.events()

	f.stub.SetResync([]panel.TargetRef{f.ref(keyProxy)})
	f.statsCycle()

	got := f.resyncEvents()
	if len(got) != 1 {
		t.Fatalf("resync events = %+v, want exactly one", got)
	}
	ev := got[0]
	if ev.kind != eventKindTarget || ev.monClientID != f.mc.Id || ev.inboundKind != keyProxy.InboundKind ||
		ev.inboundID == nil || *ev.inboundID != keyProxy.InboundID || ev.path != keyProxy.Path {
		t.Fatalf("resync event = %+v, want a target event naming %+v", ev, keyProxy)
	}
	if ev.from != "UP" || ev.to != "UP" || !ev.notified {
		t.Fatalf("resync event = %+v, want UP → UP, notified", ev)
	}
	if ev.ts != clock.Ms(f.clk.Now()) {
		t.Fatalf("resync ts = %d, want mon-server's time now (%d): the panel ignores an event older than its since",
			ev.ts, clock.Ms(f.clk.Now()))
	}
	for _, old := range before {
		if old.ID == ev.id {
			t.Fatalf("resync event reuses id %s of an earlier event, want a fresh one", ev.id)
		}
	}
	if len(f.events()) != len(before)+1 {
		t.Fatalf("outbox grew by %d, want only the resync event", len(f.events())-len(before))
	}
}

// TestResync_OncePerTargetPerStatsCycle is decision #151 Q5's throttle: the
// panel names a target in every answer until an event arrives, but
// mon-server resyncs it at most once per stats cycle — not again for a
// second batch of the same flush, nor for a re-sent bucket later in the same
// window — and once more in the next cycle, when the panel still asks.
func TestResync_OncePerTargetPerStatsCycle(t *testing.T) {
	f := newResyncFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	f.stub.SetResync([]panel.TargetRef{f.ref(keyProxy)})

	// One flush, two batches: a backlog one over the contract's limit.
	rows := make([]store.StatsBucket, 0, maxStatsPerBatch+1)
	for i := range maxStatsPerBatch + 1 {
		rows = append(rows, store.StatsBucket{
			MonClientId: f.mc.Id, InboundKind: store.InboundKindXray, InboundId: 1000 + i, Path: store.PathProxy,
			BucketStart: atMs(baseTime), NOk: 1,
		})
	}
	if err := f.st.DB.CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatalf("seed buckets: %v", err)
	}
	f.statsCycle()
	if posts := f.statsPosts(); posts != 2 {
		t.Fatalf("POST /stats calls = %d, want 2 batches in one flush", posts)
	}
	if n := len(f.resyncEvents()); n != 1 {
		t.Fatalf("resync events after one two-batch flush = %d, want 1", n)
	}

	// A late heartbeat reopens a sent bucket a minute later: the same
	// stats cycle posts again, and the panel asks again.
	f.seq++
	if err := f.b.Record(context.Background(), f.st.DB, f.mc.Id,
		[]Cycle{{Seq: f.seq, Ts: atMs(baseTime), Results: []Result{statOK(40)}}}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	f.clk.Advance(time.Minute)
	posts := f.statsPosts()
	if err := f.b.Flush(context.Background(), f.cl); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if f.statsPosts() != posts+1 {
		t.Fatalf("the reopened bucket was not re-sent")
	}
	if n := len(f.resyncEvents()); n != 1 {
		t.Fatalf("resync events after a second flush in the same stats cycle = %d, want still 1", n)
	}

	// The next stats cycle, and the panel still asks.
	f.statsCycle()
	if n := len(f.resyncEvents()); n != 2 {
		t.Fatalf("resync events after the next stats cycle = %d, want 2", n)
	}
}

// statsPosts counts the POST /stats requests the stub has seen.
func (f *resyncFixture) statsPosts() int {
	n := 0
	for _, r := range f.stub.Requests() {
		if strings.HasSuffix(r.Path, "/stats") {
			n++
		}
	}
	return n
}

// TestResync_NothingToConfirm is decision #151 Q5's other half: a target
// mon-server holds in UNKNOWN itself, or does not know at all, has no state
// to confirm, so the panel's request for it files nothing.
func TestResync_NothingToConfirm(t *testing.T) {
	f := newResyncFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	if err := f.e.MonClientDisabled(context.Background(), f.mc.Id); err != nil {
		t.Fatalf("MonClientDisabled: %v", err)
	}
	if got := f.targetState(keyProxy); got.State != "UNKNOWN" {
		t.Fatalf("state = %s, want UNKNOWN after the mon-client was disabled", got.State)
	}
	before := len(f.events())

	unknown := f.ref(keyProxy)
	unknown.InboundId = 99
	f.stub.SetResync([]panel.TargetRef{f.ref(keyProxy), f.ref(keyDirect), unknown})
	f.statsCycle()

	if got := f.resyncEvents(); len(got) != 0 {
		t.Fatalf("resync events = %+v, want none for UNKNOWN and unknown targets", got)
	}
	if n := len(f.events()); n != before {
		t.Fatalf("outbox holds %d events, want the %d it had", n, before)
	}
}

// TestResync_OldPanelChangesNothing covers a panel from before decision
// #151: its stats answer has no resync field — or, older still, no body —
// and the flush behaves exactly as it did, filing no events.
func TestResync_OldPanelChangesNothing(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		f := newResyncFixture(t)
		f.clk.Advance(time.Minute)
		f.beat(f.cycle(1, result(keyProxy, true, "")))
		f.stub.SetLegacyAnswers(legacy)
		before := len(f.events())

		f.statsCycle()

		if n := len(f.events()); n != before {
			t.Fatalf("legacy=%v: outbox holds %d events, want the %d it had", legacy, n, before)
		}
		var unsent int64
		if err := f.st.DB.Model(&store.StatsBucket{}).Where("sent_at IS NULL").Count(&unsent).Error; err != nil {
			t.Fatalf("count unsent: %v", err)
		}
		if unsent != 0 {
			t.Fatalf("legacy=%v: %d buckets unsent, want the flush to have delivered them all", legacy, unsent)
		}
	}
}
