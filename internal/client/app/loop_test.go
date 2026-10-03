package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/heartbeat"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/servertest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// fakeApplier stands in for step 8's config applier: it records every
// document it is given, keeps the probes a test handed it, and maintains
// AppliedRevision on the shared state file exactly as the real one must
// (see the Applier contract on the interface).
type fakeApplier struct {
	mu       sync.Mutex
	file     *state.File
	doc      *proto.ConfigDoc
	probes   map[proto.TargetKey]probe.Fn
	applied  []*proto.ConfigDoc
	applyErr error
	lastErr  error
}

func (a *fakeApplier) Apply(_ context.Context, doc *proto.ConfigDoc) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.applied = append(a.applied, doc)
	if a.applyErr != nil {
		a.lastErr = a.applyErr
		return a.applyErr
	}
	a.doc, a.lastErr = doc, nil
	a.file.AppliedRevision = doc.ConfigRevision
	return nil
}

func (a *fakeApplier) Applied() (*proto.ConfigDoc, map[proto.TargetKey]probe.Fn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.doc, a.probes, a.lastErr
}

func (a *fakeApplier) appliedDocs() []*proto.ConfigDoc {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*proto.ConfigDoc(nil), a.applied...)
}

// lockedBuffer is a bytes.Buffer the loop's logger can write to from its
// own goroutine while the test body reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// harness is one wired-up loop over a protocol stub: everything a test
// needs to drive iterations and then assert on what mon-server saw.
type harness struct {
	stub    *servertest.Stub
	dir     *state.Dir
	client  *api.Client
	loop    *Loop
	applier *fakeApplier
	buffer  *heartbeat.Buffer
	file    *state.File
	logs    *lockedBuffer
	sleeps  *[]time.Duration
	clk     *clock.Fake
}

// newHarness builds a loop against a fresh stub, with a fake clock and an
// injected sleeper so nothing in a test ever waits on the wall clock.
func newHarness(t *testing.T, probes map[proto.TargetKey]probe.Fn) *harness {
	t.Helper()

	stub := servertest.NewStub(t)
	stub.Approve("req-1", "ams-1", "tok")

	client := api.New(stub.URL(), stub.HTTPClient())
	client.Token = "tok"

	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	file := &state.File{MonClientID: "ams-1", Token: "tok", ServerURL: stub.URL()}
	if err := dir.Save(file); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	buf, err := heartbeat.OpenBuffer(dir.Path("cycles.json"))
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}

	applier := &fakeApplier{file: file, probes: probes}
	logs := &lockedBuffer{}
	clk := clock.NewFake(time.Date(2025, 9, 13, 12, 0, 0, 0, time.UTC))
	sleeps := &[]time.Duration{}
	var sleepMu sync.Mutex

	loop := NewLoop(Deps{
		API:     client,
		State:   dir,
		File:    file,
		Buffer:  buf,
		Runner:  probe.NewRunner(slog.New(slog.NewTextHandler(logs, nil))),
		Applier: applier,
		Clock:   clk,
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleepMu.Lock()
			*sleeps = append(*sleeps, d)
			sleepMu.Unlock()
			clk.Advance(d)
			return ctx.Err()
		},
		Rand:      mrand.New(mrand.NewPCG(1, 2)),
		Log:       slog.New(slog.NewTextHandler(logs, nil)),
		Version:   "0.1.0",
		StartedAt: clk.Now().Add(-time.Minute),
	})

	return &harness{stub: stub, dir: dir, client: client, loop: loop, applier: applier, buffer: buf, file: file, logs: logs, sleeps: sleeps, clk: clk}
}

// restart builds a second Loop over the same state directory and
// cycles.json, standing in for the process being restarted mid-outage.
func (h *harness) restart(t *testing.T) *Loop {
	t.Helper()
	buf, err := heartbeat.OpenBuffer(h.dir.Path("cycles.json"))
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}
	applier := &fakeApplier{file: h.file, probes: h.applier.probes, doc: h.applier.doc}
	return NewLoop(Deps{
		API:       h.client,
		State:     h.dir,
		File:      h.file,
		Buffer:    buf,
		Runner:    probe.NewRunner(slog.New(slog.NewTextHandler(h.logs, nil))),
		Applier:   applier,
		Clock:     h.clk,
		Sleep:     func(ctx context.Context, d time.Duration) error { return ctx.Err() },
		Rand:      mrand.New(mrand.NewPCG(3, 4)),
		Log:       slog.New(slog.NewTextHandler(h.logs, nil)),
		Version:   "0.1.0",
		StartedAt: h.clk.Now(),
	})
}

// okProbe is a probe that always succeeds, standing in for a healthy
// tunnel without one existing.
func okProbe(_ context.Context, k proto.TargetKey) proto.Result {
	ms := int64(47)
	ip := "203.0.113.10"
	return proto.Result{TargetKey: k, Ok: true, TlsMs: &ms, EgressIp: &ip}
}

func targetKey() proto.TargetKey {
	return proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"}
}

func doc(revision string) *proto.ConfigDoc {
	return &proto.ConfigDoc{
		ConfigRevision: revision,
		MonClientID:    "ams-1",
		ProbeURL:       "https://mon.example/v1/probe",
		Probe: proto.ProbeParams{
			IntervalMs:         60_000,
			BudgetMs:           30_000,
			StartJitterMs:      5_000,
			HeartbeatTimeoutMs: 10_000,
		},
		Targets: []proto.Target{{TargetKey: targetKey(), Protocol: "vless", Link: "vless://x"}},
	}
}

// TestLoop_OnceSendsTheCycleInAHeartbeat is protocol §5.3's body: who is
// reporting, on which revision, the client block, and one cycle with its
// seq, ts, unverified flag and results.
func TestLoop_OnceSendsTheCycleInAHeartbeat(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 {
		t.Fatalf("%d heartbeats, want 1", len(hbs))
	}
	hb := hbs[0]
	if hb.MonClientID != "ams-1" {
		t.Fatalf("monClientId = %q, want ams-1", hb.MonClientID)
	}
	if hb.ConfigRevision != "rev1" {
		t.Fatalf("configRevision = %q, want rev1 (the applied revision)", hb.ConfigRevision)
	}
	if hb.Client.Version != "0.1.0" {
		t.Fatalf("client.version = %q, want 0.1.0", hb.Client.Version)
	}
	if hb.Client.UptimeMs != 60_000 {
		t.Fatalf("client.uptimeMs = %d, want 60000", hb.Client.UptimeMs)
	}
	if hb.Client.ConfigError != nil {
		t.Fatalf("client.configError = %v, want null", *hb.Client.ConfigError)
	}
	if len(hb.Cycles) != 1 {
		t.Fatalf("%d cycles, want 1", len(hb.Cycles))
	}
	c := hb.Cycles[0]
	if c.Seq != 1 {
		t.Fatalf("cycle seq = %d, want 1", c.Seq)
	}
	if c.Ts != clock.Ms(h.clk.Now()) {
		t.Fatalf("cycle ts = %d, want the cycle start %d", c.Ts, clock.Ms(h.clk.Now()))
	}
	if c.Unverified {
		t.Fatal("a delivered cycle must not be unverified")
	}
	if len(c.Results) != 1 || !c.Results[0].Ok || c.Results[0].TargetKey != targetKey() {
		t.Fatalf("results = %+v, want one ok result for %v", c.Results, targetKey())
	}
}

// TestLoop_AckClearsTheBuffer is spec §6's "ответ 200 {ackSeq} удаляет все
// seq ≤ ackSeq", plus its spec §7 log line.
func TestLoop_AckClearsTheBuffer(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	if pending := h.buffer.Pending(); len(pending) != 0 {
		t.Fatalf("Pending() = %+v, want empty after an ack", pending)
	}
	if !strings.Contains(h.logs.String(), "ack 1") {
		t.Fatalf("logs = %q, want the spec §7 \"ack 1\" line", h.logs.String())
	}
}

// TestLoop_FailedHeartbeatBuffersTheCycleUnverified is spec §6's 5xx path:
// the cycle stays, is flagged, and rides along with the next one — which
// is then acknowledged together with it.
func TestLoop_FailedHeartbeatBuffersTheCycleUnverified(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")
	h.stub.FailNextHeartbeats(1, 500)

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	pending := h.buffer.Pending()
	if len(pending) != 1 || !pending[0].Unverified {
		t.Fatalf("Pending() = %+v, want one unverified cycle", pending)
	}
	if !strings.Contains(h.logs.String(), "buffered 1 cycles") {
		t.Fatalf("logs = %q, want the spec §7 \"buffered N cycles\" line", h.logs.String())
	}

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 {
		t.Fatalf("%d accepted heartbeats, want 1 (the first was refused)", len(hbs))
	}
	cycles := hbs[0].Cycles
	if len(cycles) != 2 {
		t.Fatalf("%d cycles resent, want the unverified one plus the new one", len(cycles))
	}
	if cycles[0].Seq != 1 || !cycles[0].Unverified {
		t.Fatalf("cycles[0] = %+v, want seq 1 unverified", cycles[0])
	}
	if cycles[1].Seq != 2 || cycles[1].Unverified {
		t.Fatalf("cycles[1] = %+v, want seq 2 not unverified", cycles[1])
	}
	if got := h.buffer.Pending(); len(got) != 0 {
		t.Fatalf("Pending() = %+v, want empty after the ack cleared both", got)
	}
}

// TestLoop_DroppedHeartbeatBuffersTheCycleUnverified is the same rule for
// the other half of spec §6's "не подтверждён (сеть, 5xx, таймаут)": a
// connection dropped mid-request, with no HTTP status at all.
func TestLoop_DroppedHeartbeatBuffersTheCycleUnverified(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")
	h.stub.DropNextHeartbeats(1)

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	pending := h.buffer.Pending()
	if len(pending) != 1 || !pending[0].Unverified {
		t.Fatalf("Pending() = %+v, want one unverified cycle", pending)
	}

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 || len(hbs[0].Cycles) != 2 {
		t.Fatalf("heartbeats = %+v, want one carrying both cycles", hbs)
	}
	if got := h.buffer.Pending(); len(got) != 0 {
		t.Fatalf("Pending() = %+v, want empty", got)
	}
}

// TestLoop_KeepsProbingWhileMonServerIsDown is spec §6's "Пробы при этом
// продолжаются": three refused heartbeats in a row cost three buffered
// cycles, not a stopped loop.
func TestLoop_KeepsProbingWhileMonServerIsDown(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")
	h.stub.FailNextHeartbeats(3, 503)

	for range 3 {
		if err := h.loop.Once(context.Background()); err != nil {
			t.Fatalf("Once: %v", err)
		}
	}

	if got := len(h.buffer.Pending()); got != 3 {
		t.Fatalf("%d buffered cycles, want 3", got)
	}
	if !strings.Contains(h.logs.String(), "buffered 3 cycles") {
		t.Fatalf("logs = %q, want the spec §7 \"buffered 3 cycles\" line", h.logs.String())
	}
}

// TestLoop_RevisionChangeRefetchesTheConfig is spec §6's "configRevision в
// ответе ≠ appliedRevision → §4 после текущего цикла".
func TestLoop_RevisionChangeRefetchesTheConfig(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev2") // mon-server has moved on since rev1

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if got := h.applier.appliedDocs(); len(got) != 1 || got[0].ConfigRevision != "rev1" {
		t.Fatalf("applied = %+v, want rev1 on the first iteration", got)
	}

	h.stub.SetConfig(doc("rev2"))
	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	applied := h.applier.appliedDocs()
	if len(applied) != 2 || applied[1].ConfigRevision != "rev2" {
		t.Fatalf("applied = %+v, want rev2 fetched after the cycle", applied)
	}
	if h.file.AppliedRevision != "rev2" {
		t.Fatalf("AppliedRevision = %q, want rev2", h.file.AppliedRevision)
	}
	if hbs := h.stub.Heartbeats(); len(hbs) != 2 || hbs[1].ConfigRevision != "rev2" {
		t.Fatalf("second heartbeat reported revision %+v, want rev2", hbs)
	}
}

// TestLoop_NoConfigYetStillHeartbeats is spec §4.4: a box mon-server has
// no config for (503 config_not_ready) runs empty cycles and reports them
// anyway, so an operator sees it as ONLINE rather than missing.
func TestLoop_NoConfigYetStillHeartbeats(t *testing.T) {
	h := newHarness(t, nil)
	// No SetConfig: the stub answers 503 config_not_ready.

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 {
		t.Fatalf("%d heartbeats, want 1", len(hbs))
	}
	if hbs[0].ConfigRevision != "" {
		t.Fatalf("configRevision = %q, want empty (nothing applied)", hbs[0].ConfigRevision)
	}
	if len(hbs[0].Cycles) != 1 || len(hbs[0].Cycles[0].Results) != 0 {
		t.Fatalf("cycles = %+v, want one cycle with no results", hbs[0].Cycles)
	}
	if got := h.applier.appliedDocs(); len(got) != 1 || len(got[0].Targets) != 0 {
		t.Fatalf("applied = %+v, want the empty spec §5 defaults document", got)
	}
}

// TestLoop_ConfigErrorIsReportedInEveryHeartbeat is spec §4.3: a document
// that would not apply leaves the old revision in force and shows up as
// client.configError until a later one applies.
func TestLoop_ConfigErrorIsReportedInEveryHeartbeat(t *testing.T) {
	h := newHarness(t, nil)
	h.applier.applyErr = errors.New("xray -test failed: bad outbound\nsecond line")
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 || hbs[0].Client.ConfigError == nil {
		t.Fatalf("heartbeat = %+v, want a configError", hbs)
	}
	if got := *hbs[0].Client.ConfigError; got != "xray -test failed: bad outbound" {
		t.Fatalf("configError = %q, want only the first line", got)
	}
	if hbs[0].ConfigRevision != "" {
		t.Fatalf("configRevision = %q, want the old (empty) revision kept", hbs[0].ConfigRevision)
	}
}

// TestLoop_TokenRevokedAndDisabledAreReturned checks the two answers step
// 9 has to branch on come back unwrapped (spec §6: 401 → re-register, 403
// → heartbeat every 5 minutes).
func TestLoop_TokenRevokedAndDisabledAreReturned(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{"revoked", 401, api.ErrTokenRevoked},
		{"disabled", 403, api.ErrDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.stub.SetConfig(doc("rev1"))
			h.stub.SetTokenStatus(tc.status)

			err := h.loop.Once(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Once error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestLoop_CycleHonoursTheBudget drives spec §5's parallel budget through
// the whole loop: three hung targets and a 300 ms budget cost one cycle
// about one budget, and the heartbeat still goes out.
func TestLoop_CycleHonoursTheBudget(t *testing.T) {
	hang := func(ctx context.Context, k proto.TargetKey) proto.Result {
		<-ctx.Done()
		reason := proto.ReasonProbeTimeout
		return proto.Result{TargetKey: k, Reason: &reason}
	}
	probes := map[proto.TargetKey]probe.Fn{}
	for i := range 3 {
		probes[proto.TargetKey{InboundKind: "xray", InboundID: i, Path: "proxy"}] = hang
	}

	h := newHarness(t, probes)
	d := doc("rev1")
	d.Probe.BudgetMs = 300
	h.stub.SetConfig(d)
	h.stub.SetRevision("rev1")

	start := time.Now()
	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("one cycle took %s with a 300ms budget — probes did not run in parallel", elapsed)
	}
	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 || len(hbs[0].Cycles[0].Results) != 3 {
		t.Fatalf("heartbeat = %+v, want one cycle with three failed results", hbs)
	}
	for _, r := range hbs[0].Cycles[0].Results {
		if r.Ok {
			t.Fatalf("result %+v, want every hung target failed", r)
		}
	}
}

// TestLoop_SeqContinuesAfterARestart checks spec §6's monotonic seq end to
// end: a mon-client restarted after an unacknowledged cycle resends it and
// numbers the next cycle after it, rather than starting over at 1.
func TestLoop_SeqContinuesAfterARestart(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")
	h.stub.FailNextHeartbeats(1, 500)

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	// A "restart": a second Loop over the same state directory and the
	// same cycles.json, exactly what a fresh process would open.
	restarted := h.restart(t)
	if err := restarted.Once(context.Background()); err != nil {
		t.Fatalf("Once after restart: %v", err)
	}

	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 {
		t.Fatalf("%d accepted heartbeats, want 1 (the first was refused)", len(hbs))
	}
	cycles := hbs[0].Cycles
	if len(cycles) != 2 {
		t.Fatalf("%d cycles, want the unacknowledged one plus the new one", len(cycles))
	}
	if cycles[0].Seq != 1 || !cycles[0].Unverified {
		t.Fatalf("cycles[0] = %+v, want seq 1 unverified", cycles[0])
	}
	if cycles[1].Seq != 2 {
		t.Fatalf("cycle seq after restart = %d, want 2", cycles[1].Seq)
	}
}

// TestLoop_RunJittersOnlyTheFirstCycle is spec §5's "старт со случайным
// джиттером": the first cycle waits somewhere in [0, startJitterMs), every
// later one waits the full interval.
func TestLoop_RunJittersOnlyTheFirstCycle(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	ctx, cancel := context.WithCancel(context.Background())
	// The injected sleeper returns ctx.Err(), so Run stops at the wait
	// that follows the cancelled iteration.
	done := make(chan error, 1)
	go func() { done <- h.loop.Run(ctx) }()

	deadline := time.After(5 * time.Second)
	for {
		if len(h.stub.Heartbeats()) >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for two cycles")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	sleeps := *h.sleeps
	if len(sleeps) < 2 {
		t.Fatalf("sleeps = %v, want at least two waits", sleeps)
	}
	if sleeps[0] < 0 || sleeps[0] >= 5*time.Second {
		t.Fatalf("first wait = %s, want the start jitter in [0, 5s)", sleeps[0])
	}
	if sleeps[1] != time.Minute {
		t.Fatalf("second wait = %s, want the 60s interval", sleeps[1])
	}
}

// revivingApplier is a fakeApplier that also implements Reviver and
// records when it was asked to revive.
type revivingApplier struct {
	*fakeApplier
	note func(string)
}

func (a *revivingApplier) Revive(context.Context) { a.note("revive") }

// TestLoop_RevivesBeforeEveryCycle is the loop's half of decision #53 п. 4:
// an applier that keeps a child process alive is given the chance to
// restart it before every cycle — after the config is applied, before a
// single probe runs.
func TestLoop_RevivesBeforeEveryCycle(t *testing.T) {
	var mu sync.Mutex
	var events []string
	note := func(what string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, what)
	}
	probes := map[proto.TargetKey]probe.Fn{targetKey(): func(ctx context.Context, k proto.TargetKey) proto.Result {
		note("probe")
		return okProbe(ctx, k)
	}}
	h := newHarness(t, probes)
	loop := h.withApplier(t, &revivingApplier{fakeApplier: h.applier, note: note})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	for i := 0; i < 2; i++ {
		if err := loop.Once(context.Background()); err != nil {
			t.Fatalf("Once: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(events, ","); got != "revive,probe,revive,probe" {
		t.Errorf("events = %s, want a revive before every cycle's probes", got)
	}
}

// runCycles runs h.loop until n heartbeats reached the stub, then stops it
// and returns the start of every cycle, read from the heartbeats' cycles
// (protocol §5.3's ts is the cycle start).
func runCycles(t *testing.T, h *harness, n int) []int64 {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.loop.Run(ctx) }()

	deadline := time.After(10 * time.Second)
	for len(h.stub.Heartbeats()) < n {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("timed out waiting for %d cycles", n)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	var starts []int64
	for _, hb := range h.stub.Heartbeats()[:n] {
		c := hb.Cycles[len(hb.Cycles)-1]
		starts = append(starts, c.Ts)
	}
	return starts
}

// slowProbe is a probe that takes d of the harness' fake time, so a cycle
// has a length without the test waiting for it.
func slowProbe(clk **clock.Fake, d time.Duration) probe.Fn {
	return func(ctx context.Context, k proto.TargetKey) proto.Result {
		(*clk).Advance(d)
		return okProbe(ctx, k)
	}
}

// TestLoop_RunKeepsAFixedPeriod is decision #53 п. 5: the next cycle
// starts intervalMs after the previous one *started*, so a 25 s cycle at a
// 60 s interval still gives a 60 s period — not the 85 s a sleep after the
// cycle used to give.
func TestLoop_RunKeepsAFixedPeriod(t *testing.T) {
	var clk *clock.Fake
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): slowProbe(&clk, 25*time.Second)})
	clk = h.clk
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	starts := runCycles(t, h, 4)
	for i := 1; i < len(starts); i++ {
		if got := time.Duration(starts[i]-starts[i-1]) * time.Millisecond; got != time.Minute {
			t.Errorf("cycle %d started %s after cycle %d, want the 60s interval (starts %v)", i+1, got, i, starts)
		}
	}
	sleeps := *h.sleeps
	for i, d := range sleeps[1:4] {
		if d != 35*time.Second {
			t.Errorf("wait %d = %s, want 35s (the interval minus the 25s cycle)", i+2, d)
		}
	}
}

// TestLoop_RunFitsAFullBudgetCycle is #102's check on the defaults: with
// the 30 s probe budget, a cycle whose probes all run out their budget and
// whose heartbeat then waits out its whole timeout (30 s + 10 s) still
// fits the 60 s interval — the period stays 60 s and no tick is skipped.
func TestLoop_RunFitsAFullBudgetCycle(t *testing.T) {
	worst := probe.DefaultBudget + time.Duration(DefaultHeartbeatTimeoutMs)*time.Millisecond
	interval := time.Duration(DefaultIntervalMs) * time.Millisecond
	if worst >= interval {
		t.Fatalf("budget + heartbeat timeout = %s, does not fit the %s interval", worst, interval)
	}

	var clk *clock.Fake
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): slowProbe(&clk, worst)})
	clk = h.clk
	d := doc("rev1")
	d.Probe.IntervalMs = DefaultIntervalMs
	d.Probe.BudgetMs = probe.DefaultBudget.Milliseconds()
	h.stub.SetConfig(d)
	h.stub.SetRevision("rev1")

	starts := runCycles(t, h, 3)
	for i := 1; i < len(starts); i++ {
		if got := time.Duration(starts[i]-starts[i-1]) * time.Millisecond; got != interval {
			t.Errorf("cycle %d started %s after cycle %d, want the %s interval (starts %v)", i+1, got, i, interval, starts)
		}
	}
	if strings.Contains(h.logs.String(), "skipping") {
		t.Errorf("a full-budget cycle skipped a tick:\n%s", h.logs.String())
	}
}

// TestLoop_RunSkipsMissedTicks is the other half of decision #53 п. 5: a
// cycle longer than the interval skips the tick it overran instead of
// starting the next cycle at once to catch up — no burst, the period
// simply becomes two intervals while the cycles stay that slow.
func TestLoop_RunSkipsMissedTicks(t *testing.T) {
	var clk *clock.Fake
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): slowProbe(&clk, 70*time.Second)})
	clk = h.clk
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	starts := runCycles(t, h, 3)
	for i := 1; i < len(starts); i++ {
		if got := time.Duration(starts[i]-starts[i-1]) * time.Millisecond; got != 2*time.Minute {
			t.Errorf("cycle %d started %s after cycle %d, want 120s (one tick skipped; starts %v)", i+1, got, i, starts)
		}
	}
	for i, d := range (*h.sleeps)[1:3] {
		if d != 50*time.Second {
			t.Errorf("wait %d = %s, want 50s to the next tick on the grid, never an immediate catch-up", i+2, d)
		}
	}
}

// TestLoop_RunStopsOnContextCancellation checks an ordinary shutdown is
// not an error: SIGINT/SIGTERM cancels the context, Run returns nil, and
// cmd/mon-client exits 0.
func TestLoop_RunStopsOnContextCancellation(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.loop.Run(ctx); err != nil {
		t.Fatalf("Run: %v, want nil on shutdown", err)
	}
	if got := h.stub.Heartbeats(); len(got) != 0 {
		t.Fatalf("%d heartbeats, want none from a cancelled run", len(got))
	}
}

// withApplier builds a second Loop over this harness's stub, state
// directory and buffer but with a different Applier — how a test drives
// the loop against the real RevisionApplier (apply_test.go).
func (h *harness) withApplier(t *testing.T, applier Applier) *Loop {
	t.Helper()
	return NewLoop(Deps{
		API:       h.client,
		State:     h.dir,
		File:      h.file,
		Buffer:    h.buffer,
		Runner:    probe.NewRunner(slog.New(slog.NewTextHandler(h.logs, nil))),
		Applier:   applier,
		Clock:     h.clk,
		Sleep:     func(ctx context.Context, d time.Duration) error { return ctx.Err() },
		Rand:      mrand.New(mrand.NewPCG(5, 6)),
		Log:       slog.New(slog.NewTextHandler(h.logs, nil)),
		Version:   "0.1.0",
		StartedAt: h.clk.Now(),
	})
}

// guardedApplier is a fakeApplier that also implements CycleGuard, with the
// same read/write lock RevisionApplier uses. It is how the loop's half of
// the "применение между циклами" contract is tested without a child
// process: the loop must hold the guard for the whole cycle.
type guardedApplier struct {
	*fakeApplier
	cycle sync.RWMutex
}

func (a *guardedApplier) Apply(ctx context.Context, doc *proto.ConfigDoc) error {
	a.cycle.Lock()
	defer a.cycle.Unlock()
	return a.fakeApplier.Apply(ctx, doc)
}

func (a *guardedApplier) BeginCycle() { a.cycle.RLock() }
func (a *guardedApplier) EndCycle()   { a.cycle.RUnlock() }

// TestLoop_ApplyWaitsForTheCycleInFlight is spec §4 step 3 seen from the
// loop: a cycle that is already probing finishes before an apply arriving
// from another goroutine is allowed to swap anything.
func TestLoop_ApplyWaitsForTheCycleInFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})

	// events is the order the test asserts on; a mutex rather than two
	// timestamps because the probe and the apply run in two goroutines.
	var mu sync.Mutex
	var events []string
	note := func(what string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, what)
	}

	slow := func(ctx context.Context, k proto.TargetKey) proto.Result {
		close(started)
		<-release
		note("probe")
		return proto.Result{TargetKey: k, Ok: true}
	}

	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): slow})
	// The apply comes from a second goroutine here, which production never
	// does (Once calls Apply itself) — so the applier under test gets its
	// own state.File rather than the loop's, which the loop reads from its
	// own goroutine while building the heartbeat.
	guarded := &guardedApplier{fakeApplier: &fakeApplier{file: &state.File{}, probes: h.applier.probes}}
	loop := h.withApplier(t, guarded)
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	done := make(chan error, 1)
	go func() { done <- loop.Once(context.Background()) }()

	<-started
	applied := make(chan struct{})
	go func() {
		defer close(applied)
		if err := guarded.Apply(context.Background(), doc("rev2")); err != nil {
			t.Errorf("Apply: %v", err)
		}
		note("apply")
	}()

	// Give the apply a chance to run early if the guard does not hold.
	time.Sleep(50 * time.Millisecond)
	close(release)

	if err := <-done; err != nil {
		t.Fatalf("Once: %v", err)
	}
	<-applied

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0] != "probe" || events[1] != "apply" {
		t.Fatalf("events = %v, want the probe in flight to finish before the apply", events)
	}
}

// TestLoop_ResultsOfRemovedTargetsAreDropped is spec §4 step 3's "грейса
// нет: результаты по удалённым targets отбрасываются" — a revision that
// drops a target stops it appearing in heartbeats at once.
func TestLoop_ResultsOfRemovedTargetsAreDropped(t *testing.T) {
	gone := proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "direct"}
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe, gone: okProbe})
	two := doc("rev1")
	two.Targets = append(two.Targets, proto.Target{TargetKey: gone, Protocol: "trojan", Link: "trojan://x"})
	h.stub.SetConfig(two)
	h.stub.SetRevision("rev2") // a newer revision is waiting

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if got := h.stub.Heartbeats()[0].Cycles[0].Results; len(got) != 2 {
		t.Fatalf("%d results in the first cycle, want both targets", len(got))
	}

	// rev2 drops the second target: the applier installs a probe set
	// without it.
	h.applier.mu.Lock()
	h.applier.probes = map[proto.TargetKey]probe.Fn{targetKey(): okProbe}
	h.applier.mu.Unlock()
	h.stub.SetConfig(doc("rev2"))

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	results := h.stub.Heartbeats()[1].Cycles[0].Results
	if len(results) != 1 || results[0].TargetKey != targetKey() {
		t.Fatalf("results = %+v, want only the surviving target", results)
	}
}

// TestLoop_ResultsForUnknownTargetsAreFiltered is the belt-and-braces half
// of the same rule: even a probe that hands back a result for a key the
// applied document does not have must not reach a heartbeat.
func TestLoop_ResultsForUnknownTargetsAreFiltered(t *testing.T) {
	stale := proto.TargetKey{InboundKind: "xray", InboundID: 99, Path: "stale"}
	impostor := func(_ context.Context, _ proto.TargetKey) proto.Result {
		return proto.Result{TargetKey: stale, Ok: true}
	}

	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): impostor})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if got := h.stub.Heartbeats()[0].Cycles[0].Results; len(got) != 0 {
		t.Fatalf("results = %+v, want the foreign result dropped", got)
	}
}

// TestLoop_AckIsPersistedInState is decision #51 §1: the last ackSeq
// mon-server gave is kept in state.json, the file that survives a lost
// cycles.json.
func TestLoop_AckIsPersistedInState(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")

	for i := 0; i < 2; i++ {
		if err := h.loop.Once(context.Background()); err != nil {
			t.Fatalf("Once: %v", err)
		}
	}
	f, err := h.dir.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.LastAckSeq != 2 {
		t.Fatalf("state.json lastAckSeq = %d, want 2", f.LastAckSeq)
	}
}

// TestLoop_LostBufferContinuesAfterLastAck is decision #51 §1: with
// cycles.json gone (or corrupt and discarded) the next seq is the last
// ackSeq + 1 from state.json, not 1 — mon-server would drop 1…ackSeq as
// already seen, and no re-registration is needed.
func TestLoop_LostBufferContinuesAfterLastAck(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")
	if err := h.loop.Once(context.Background()); err != nil {
		t.Fatalf("Once: %v", err)
	}

	if err := os.Remove(h.dir.Path("cycles.json")); err != nil {
		t.Fatalf("remove cycles.json: %v", err)
	}
	restarted := h.restart(t)
	if err := restarted.Once(context.Background()); err != nil {
		t.Fatalf("Once after restart: %v", err)
	}

	hbs := h.stub.Heartbeats()
	last := hbs[len(hbs)-1]
	if len(last.Cycles) != 1 || last.Cycles[0].Seq != 2 {
		t.Fatalf("cycles after losing the buffer = %+v, want one with seq 2", last.Cycles)
	}
}

// TestLoop_ServerAheadIsCaughtUpByTheAck: with both files lost the box
// starts at 1; mon-server answers with its own, higher ackSeq, and the very
// next cycle continues after it — one cycle lost, not a day of them.
func TestLoop_ServerAheadIsCaughtUpByTheAck(t *testing.T) {
	h := newHarness(t, map[proto.TargetKey]probe.Fn{targetKey(): okProbe})
	h.stub.SetConfig(doc("rev1"))
	h.stub.SetRevision("rev1")
	h.stub.SetLastAckSeq("ams-1", 1440)

	for i := 0; i < 2; i++ {
		if err := h.loop.Once(context.Background()); err != nil {
			t.Fatalf("Once: %v", err)
		}
	}
	hbs := h.stub.Heartbeats()
	if got := hbs[1].Cycles; len(got) != 1 || got[0].Seq != 1441 {
		t.Fatalf("second heartbeat's cycles = %+v, want one with seq 1441", got)
	}
}
