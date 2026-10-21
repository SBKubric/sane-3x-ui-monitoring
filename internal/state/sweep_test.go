package state

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// sweepFixture is a mon-client on edges (onEdges: edge-a and edge-b probed,
// direct and inner core-1 held) with the hosts a sweep checks and a chain
// whose hops report their next hop: edge-a fresh and lossless, edge-b
// stale, core-1 never.
func sweepFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)
	f.cfg.keys = []registry.TargetKey{keyEdgeA, keyEdgeB}
	x := onEdges()
	x.Hosts = []registry.SweepHost{
		{Name: "core-1", Host: "10.0.0.7"},
		{Name: "edge-a", Host: "a.example.net"},
		{Name: "edge-b", Host: "b.example.net"},
		{Name: "", Host: "real.example.net"},
	}
	f.cfg.excl = x
	f.e.chain = func() *panel.Chain {
		rtt := int64(3)
		active := "edge-a"
		now := clock.Ms(f.clk.Now())
		return &panel.Chain{ActiveEdge: &active, Hops: []panel.Hop{
			{Name: "core-1", Role: "inner", Host: "10.0.0.7", State: "joined"},
			{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "joined",
				NextHopCheck: &panel.HopCheck{At: now - 20_000, Sent: 10, LossPct: 0, RttAvgMs: &rtt}},
			{Name: "edge-b", Role: "edge", Host: "b.example.net", State: "joined",
				NextHopCheck: &panel.HopCheck{At: now - int64(10*time.Minute/time.Millisecond), Sent: 10, LossPct: 0, RttAvgMs: &rtt}},
		}}
	}
	return f
}

// sweepRun is a live cycle that also carries a sweep run of xray: the
// edges as given, the held targets' tunnel probes, and the mon-client's
// ICMP series — every host lossless except the real server at lossReal.
func (f *fixture) sweepRun(seq int64, edgesOk, directOk, innerOk bool, lossReal int) Cycle {
	c := f.cycle(seq, result(keyEdgeA, edgesOk, "tcp_timeout"), result(keyEdgeB, edgesOk, "tcp_timeout"))
	rtt := int64(5)
	hosts := []HostCheck{
		{Name: "core-1", Sent: 10, RttAvgMs: &rtt},
		{Name: "edge-a", Sent: 10, RttAvgMs: &rtt},
		{Name: "edge-b", Sent: 10, RttAvgMs: &rtt},
		{Name: "", Sent: 10, LossPct: lossReal, RttAvgMs: &rtt},
	}
	c.Sweep = &CycleSweep{
		Kinds:   []string{store.InboundKindXray},
		Results: []Result{result(keyDirect, directOk, "tcp_refused"), result(keyInner, innerOk, "tls_timeout")},
		Hosts:   hosts,
	}
	return c
}

// sweepEvents is the outbox's kind sweep events.
func (f *fixture) sweepEvents() []store.EventPayload {
	var out []store.EventPayload
	for _, ev := range f.events() {
		if ev.Kind == eventKindSweep {
			out = append(out, ev)
		}
	}
	return out
}

// TestSweep_Lifecycle walks decision #100's diagnostic sweep for one
// mon-client and inbound kind: every edge-path DOWN starts it and hands
// the mon-client a run at once; the first run's report goes out as the
// start event and settles the held targets (reason sweep, notified); runs
// follow 1, 2, … minutes apart while nothing changes, and a change is
// announced and starts the schedule over; an edge-path UP again ends it
// with the last report and the edges as they are now, and the inner hop
// goes back to derived state.
func TestSweep_Lifecycle(t *testing.T) {
	f := sweepFixture(t)

	f.clk.Advance(time.Minute)
	if resp := f.beat(f.cycle(1, result(keyEdgeA, true, ""), result(keyEdgeB, true, ""))); resp.Sweep != nil {
		t.Fatalf("sweep job %+v while the edges are UP", resp.Sweep)
	}
	var resp *HeartbeatResponse
	for seq := int64(2); seq <= 4; seq++ {
		f.clk.Advance(time.Minute)
		resp = f.beat(f.cycle(seq, result(keyEdgeA, false, "tcp_timeout"), result(keyEdgeB, false, "tcp_timeout")))
		if seq < 4 && resp.Sweep != nil {
			t.Fatalf("sweep job at seq %d, before every edge is DOWN", seq)
		}
	}
	if resp.Sweep == nil || strings.Join(resp.Sweep.Kinds, ",") != "xray" || len(resp.Sweep.Hosts) != 4 {
		t.Fatalf("sweep job = %+v, want xray with the four hosts once every edge is DOWN", resp.Sweep)
	}
	if evs := f.sweepEvents(); len(evs) != 0 {
		t.Fatalf("sweep events before the first run = %+v, want none", evs)
	}

	// The first run: start, with its report.
	f.clk.Advance(time.Minute)
	resp = f.beat(f.sweepRun(5, false, true, false, 0))
	evs := f.sweepEvents()
	if len(evs) != 1 || evs[0].Phase != store.SweepPhaseStart || evs[0].InboundKind != store.InboundKindXray || evs[0].Notified {
		t.Fatalf("sweep events = %+v, want one start for xray, for the panel to notify", evs)
	}
	rep := evs[0].Report
	paths := []string{}
	for _, p := range rep.Paths {
		paths = append(paths, p.Path+"="+map[bool]string{true: "ok", false: "fail:" + p.Reason}[p.Ok])
	}
	if got := strings.Join(paths, ","); got != "edge:edge-a=fail:tcp_timeout,edge:edge-b=fail:tcp_timeout,inner:core-1=fail:tls_timeout,direct=ok" {
		t.Fatalf("report paths = %s", got)
	}
	raw, _ := json.Marshal(rep.Hosts)
	for _, want := range []string{
		`{"from":"mon-client","to":"core-1","at":`,
		`{"from":"mon-client","to":"","at":`,
		`{"from":"edge-a","to":"core-1","at":`,
		`{"from":"edge-b","to":"core-1","at":null,"lastAt":`,
		`{"from":"core-1","to":"","at":null}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report hosts %s lack %s", raw, want)
		}
	}
	if got := f.targetState(keyInner); got.State != store.TargetDown || got.Reason != "tls_timeout" {
		t.Fatalf("inner target = %s/%s, want DOWN tls_timeout from the sweep", got.State, got.Reason)
	}
	if got := f.targetState(keyDirect); got.State != store.TargetUp {
		t.Fatalf("direct target = %s, want UP from the sweep", got.State)
	}
	for _, key := range []registry.TargetKey{keyInner, keyDirect} {
		evs := f.eventsFor(key)
		last := evs[len(evs)-1]
		if last.Reason != ReasonSweep || !last.Notified {
			t.Fatalf("%s last event = %+v, want reason sweep, notified", key.Path, last)
		}
	}
	if resp.Sweep == nil {
		t.Fatal("no run asked for one minute after the start")
	}

	// The same picture: no event, and the next run two minutes on.
	f.clk.Advance(time.Minute)
	resp = f.beat(f.sweepRun(6, false, true, false, 0))
	if n := len(f.sweepEvents()); n != 1 {
		t.Fatalf("an unchanged run filed a sweep event (%d events)", n)
	}
	if resp.Sweep != nil {
		t.Fatal("a run asked for one minute after an unchanged one, want two")
	}
	f.clk.Advance(time.Minute)
	if resp = f.beat(f.cycle(7, result(keyEdgeA, false, "tcp_timeout"), result(keyEdgeB, false, "tcp_timeout"))); resp.Sweep == nil {
		t.Fatal("no run asked for two minutes after the last one")
	}

	// The real server starts losing echoes: change, and the schedule
	// starts over at one minute.
	f.clk.Advance(time.Minute)
	resp = f.beat(f.sweepRun(8, false, true, false, 30))
	evs = f.sweepEvents()
	if len(evs) != 2 || evs[1].Phase != store.SweepPhaseChange {
		t.Fatalf("sweep events = %+v, want a change", evs)
	}
	if resp.Sweep == nil {
		t.Fatal("no run asked for one minute after a change")
	}

	// edge-a comes back (upAfter 2): the sweep ends.
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(9, result(keyEdgeA, true, ""), result(keyEdgeB, false, "tcp_timeout")))
	f.clk.Advance(time.Minute)
	resp = f.beat(f.cycle(10, result(keyEdgeA, true, ""), result(keyEdgeB, false, "tcp_timeout")))
	evs = f.sweepEvents()
	if len(evs) != 3 || evs[2].Phase != store.SweepPhaseEnd {
		t.Fatalf("sweep events = %+v, want an end", evs)
	}
	end := evs[2].Report
	if end.Paths[0].Path != "edge:edge-a" || !end.Paths[0].Ok || end.Paths[1].Ok {
		t.Fatalf("end report paths = %+v, want edge-a ok, edge-b not", end.Paths)
	}
	if resp.Sweep != nil {
		t.Fatal("a run asked for after the sweep ended")
	}
	if got := f.targetState(keyInner); got.State != store.TargetUp {
		t.Fatalf("inner target after the end = %s, want UP derived", got.State)
	}
	if got := f.targetState(keyDirect); got.State != store.TargetUp {
		t.Fatalf("direct target after the end = %s, want the last sweep's UP", got.State)
	}
	var n int64
	f.st.DB.Model(&store.Sweep{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d sweep rows left after the end", n)
	}
}

// TestSweep_FlappingIsNotUp is decision #100's detector: an edge-path in
// FLAPPING is not UP, so every edge DOWN or FLAPPING starts a sweep; one
// edge UNKNOWN (no verdict yet) holds it back.
func TestSweep_FlappingIsNotUp(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{store.TargetDown, store.TargetFlapping, true},
		{store.TargetFlapping, store.TargetFlapping, true},
		{store.TargetDown, store.TargetUnknown, false},
		{store.TargetUp, store.TargetFlapping, false},
	} {
		rows := []store.Target{
			{InboundKind: store.InboundKindXray, Path: "edge:edge-a", State: tc.a},
			{InboundKind: store.InboundKindXray, Path: "edge:edge-b", State: tc.b},
			{InboundKind: store.InboundKindXray, Path: "inner:core-1", State: store.TargetDown},
		}
		_, allDown, _ := edgeStatus(rows, store.InboundKindXray)
		if allDown != tc.want {
			t.Errorf("edges %s/%s: sweep %v, want %v", tc.a, tc.b, allDown, tc.want)
		}
	}
}

// TestSweep_ShortOutageEndsSilently: the edges come back before the
// mon-client's first run reported — nothing was announced, so nothing is.
func TestSweep_ShortOutageEndsSilently(t *testing.T) {
	f := sweepFixture(t)
	seq := int64(0)
	beat := func(ok bool) {
		f.clk.Advance(time.Minute)
		seq++
		f.beat(f.cycle(seq, result(keyEdgeA, ok, "tcp_timeout"), result(keyEdgeB, ok, "tcp_timeout")))
	}
	beat(true)
	for i := 0; i < 3; i++ {
		beat(false)
	}
	var n int64
	f.st.DB.Model(&store.Sweep{}).Count(&n)
	if n != 1 {
		t.Fatalf("%d sweep rows, want the sweep started", n)
	}
	beat(true)
	beat(true)
	if evs := f.sweepEvents(); len(evs) != 0 {
		t.Fatalf("sweep events = %+v, want none for a sweep that never reported", evs)
	}
	f.st.DB.Model(&store.Sweep{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d sweep rows left, want the sweep ended", n)
	}
}

// TestSweep_PanelDownSendsTheSummary: in PANEL_DOWN mon-server sends the
// summary itself and marks the event notified.
func TestSweep_PanelDownSendsTheSummary(t *testing.T) {
	f := sweepFixture(t)
	f.panelDown = true
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyEdgeA, true, ""), result(keyEdgeB, true, "")))
	for seq := int64(2); seq <= 4; seq++ {
		f.clk.Advance(time.Minute)
		f.beat(f.cycle(seq, result(keyEdgeA, false, "tcp_timeout"), result(keyEdgeB, false, "tcp_timeout")))
	}
	before := len(f.tgr.Sent)
	f.clk.Advance(time.Minute)
	f.beat(f.sweepRun(5, false, true, false, 100))
	evs := f.sweepEvents()
	if len(evs) != 1 || !evs[0].Notified {
		t.Fatalf("sweep events = %+v, want one notified start", evs)
	}
	sent := f.tgr.Sent[before:]
	if len(sent) != 1 || !strings.Contains(sent[0], "sweep start: xray") || !strings.Contains(sent[0], "ICMP mon-client → real ❌ 100%") {
		t.Fatalf("telegram = %q, want the sweep summary", sent)
	}
}

// TestSweep_UnaskedRunIsIgnored: a cycle's sweep block is taken only for a
// run mon-server asked for — and its tunnel probes only for held targets.
func TestSweep_UnaskedRunIsIgnored(t *testing.T) {
	f := sweepFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.sweepRun(1, true, false, false, 0))
	if evs := f.sweepEvents(); len(evs) != 0 {
		t.Fatalf("sweep events = %+v, want none", evs)
	}
	if got := f.targetState(keyDirect); got.State != store.TargetUnknown {
		t.Fatalf("direct target = %s, want UNKNOWN: no sweep asked for", got.State)
	}
}

// TestPathReport_AnyInboundWorks: a path with several inbounds of the kind
// works when any does; otherwise it carries the first failure's reason.
func TestPathReport_AnyInboundWorks(t *testing.T) {
	r13 := registry.TargetKey{InboundKind: store.InboundKindXray, InboundID: 13, Path: "edge:edge-a"}
	got := pathReport(store.InboundKindXray,
		[]Result{result(keyEdgeA, false, "tcp_timeout"), result(r13, true, ""), result(keyEdgeB, false, "tls_timeout")},
		[]Result{result(keyDirect, false, ""), result(keyAwgInner, true, "")})
	raw, _ := json.Marshal(got)
	want := `[{"path":"edge:edge-a","ok":true},{"path":"edge:edge-b","ok":false,"reason":"tls_timeout"},{"path":"direct","ok":false,"reason":"http_error"}]`
	if string(raw) != want {
		t.Fatalf("pathReport = %s, want %s", raw, want)
	}
}

// TestSweepPicture: what counts as a change — a path flipping, an ICMP
// pair changing category — and what does not — the numbers inside one.
func TestSweepPicture(t *testing.T) {
	at := int64(1)
	base := store.SweepReport{
		Paths: []store.SweepPath{{Path: "direct", Ok: true}},
		Hosts: []store.SweepHostCheck{{From: "mon-client", To: "", At: &at, Sent: 10, LossPct: 10}},
	}
	same := store.SweepReport{
		Paths: []store.SweepPath{{Path: "direct", Ok: true}},
		Hosts: []store.SweepHostCheck{{From: "mon-client", To: "", At: &at, Sent: 10, LossPct: 60}},
	}
	if sweepPicture(base) != sweepPicture(same) {
		t.Error("a loss within the same category counted as a change")
	}
	worse := same
	worse.Hosts = []store.SweepHostCheck{{From: "mon-client", To: "", At: &at, Sent: 10, LossPct: 100}}
	if sweepPicture(base) == sweepPicture(worse) {
		t.Error("10% → 100% loss did not count as a change")
	}
	gone := same
	gone.Hosts = []store.SweepHostCheck{{From: "mon-client", To: ""}}
	if sweepPicture(worse) != sweepPicture(gone) {
		t.Error("100% loss and no report are one category (❌)")
	}
	flipped := base
	flipped.Paths = []store.SweepPath{{Path: "direct", Ok: false}}
	if sweepPicture(base) == sweepPicture(flipped) {
		t.Error("a path failing did not count as a change")
	}
}

// TestSweep_EndsWhenNoEdgeIsLeft: a sweep whose edge-paths are gone (the
// mon-client's paths changed, the edges left the chain) has nothing left to
// wait for and ends rather than asking for runs forever.
func TestSweep_EndsWhenNoEdgeIsLeft(t *testing.T) {
	f := sweepFixture(t)
	seq := int64(0)
	for _, ok := range []bool{true, false, false, false} {
		f.clk.Advance(time.Minute)
		seq++
		f.beat(f.cycle(seq, result(keyEdgeA, ok, "tcp_timeout"), result(keyEdgeB, ok, "tcp_timeout")))
	}
	f.clk.Advance(time.Minute)
	seq++
	f.beat(f.sweepRun(seq, false, true, true, 0))
	if evs := f.sweepEvents(); len(evs) != 1 {
		t.Fatalf("sweep events = %+v, want the start", evs)
	}

	if err := f.e.SyncPaths(t.Context(), []string{store.PathDirect, "inner:core-1"}); err != nil {
		t.Fatalf("SyncPaths: %v", err)
	}
	f.cfg.keys = nil
	f.clk.Advance(time.Minute)
	seq++
	if resp := f.beat(f.cycle(seq)); resp.Sweep != nil {
		t.Fatalf("a run asked for with no edge-path left: %+v", resp.Sweep)
	}
	evs := f.sweepEvents()
	if len(evs) != 2 || evs[1].Phase != store.SweepPhaseEnd {
		t.Fatalf("sweep events = %+v, want an end", evs)
	}
	var n int64
	f.st.DB.Model(&store.Sweep{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d sweep rows left", n)
	}
}
