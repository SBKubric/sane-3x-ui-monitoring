package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray/xraytest"
)

// TestMain removes the fake xray binary xraytest built for this package's
// tests: Build has to leave it in place for the whole run (every test
// shares one build), so the only moment left to clean up is here, and
// os.Exit runs no deferred function.
func TestMain(m *testing.M) {
	code := m.Run()
	xraytest.Cleanup()
	os.Exit(code)
}

// Sample material in the shapes the panel generates (the same links
// internal/client/config's own tests use): documentation addresses and
// throwaway keys only.
const (
	vlessRealityLink = "vless://8c1ef5c2-2c09-4f3a-93f2-3b5c1a4d6e70@198.51.100.10:443" +
		"?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality" +
		"&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0" +
		"&sid=6ba85179e30d4fc2&fp=chrome&spx=%2FKmSmLBwPvOvfmd#ams-1-proxy"

	trojanGRPCLink = "trojan://s3cr3t-p4ssw0rd@198.51.100.20:443" +
		"?type=grpc&security=tls&sni=trojan.example.org&serviceName=probesvc&mode=multi#ams-2"

	awgConf = `[Interface]
PrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
Address = 10.66.66.2/32
MTU = 1420
Jc = 4

[Peer]
PublicKey = KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkc=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.50:51820
`
)

func xrayTarget(path, link string) proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: path},
		Protocol:  "vless",
		Link:      link,
	}
}

// awgTargetWith is an AWG-target on inbound id carrying conf.
func awgTargetWith(id int, conf string) proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "awg", InboundID: id, Path: "proxy"},
		Protocol:  "awg",
		Conf:      conf,
	}
}

func awgTarget() proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"},
		Protocol:  "awg",
		Conf:      awgConf,
	}
}

// revisionDoc is a config document of one revision carrying targets.
func revisionDoc(revision string, targets ...proto.Target) *proto.ConfigDoc {
	return &proto.ConfigDoc{
		ConfigRevision: revision,
		MonClientID:    "ams-1",
		ProbeURL:       "https://mon.example/v1/probe",
		Probe: proto.ProbeParams{
			IntervalMs: 60_000, BudgetMs: 500, ConnectMs: 200, TlsMs: 200,
			HeadersMs: 200, StartJitterMs: 0, HeartbeatTimeoutMs: 1_000,
		},
		Targets: targets,
	}
}

// applierHarness is a RevisionApplier over a fresh state directory and the
// fake xray binary (internal/client/xray/xraytest), which is as close to
// the real apply path as a unit test gets: a real child process is started,
// tested and restarted.
type applierHarness struct {
	applier *RevisionApplier
	dir     *state.Dir
	file    *state.File
	child   *xray.Process
	logs    *lockedBuffer
}

func newApplierHarness(t *testing.T, withXray bool) *applierHarness {
	t.Helper()

	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	file := &state.File{MonClientID: "ams-1", Token: "tok"}
	if err := dir.Save(file); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	var child *xray.Process
	if withXray {
		child = xray.New(xraytest.Build(t), logger)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = child.Stop(ctx)
		})
	}

	return &applierHarness{
		applier: NewRevisionApplier(ApplierDeps{Xray: child, Dir: dir, File: file, Log: logger}),
		dir:     dir,
		file:    file,
		child:   child,
		logs:    logs,
	}
}

func (h *applierHarness) xrayJSON(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.dir.Path("xray.json"))
	if err != nil {
		t.Fatalf("read xray.json: %v", err)
	}
	return string(raw)
}

func dialable(t *testing.T, port int) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestApply_WritesXrayJSONAndStartsTheChild is spec §4 step 3's happy
// path: the generated config lands in the state directory, passes -test,
// the child runs on it with its socks ports up, and appliedRevision is
// recorded.
func TestApply_WritesXrayJSONAndStartsTheChild(t *testing.T) {
	h := newApplierHarness(t, true)

	if err := h.applier.Apply(context.Background(), revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := h.xrayJSON(t); !strings.Contains(got, `"port": `+strconv.Itoa(config.FirstSocksPort)) {
		t.Errorf("xray.json does not carry the first socks inbound:\n%s", got)
	}
	if !h.child.Running() {
		t.Error("the xray child is not running after a successful apply")
	}
	if !dialable(t, config.FirstSocksPort) {
		t.Errorf("socks port %d does not accept connections", config.FirstSocksPort)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1", h.file.AppliedRevision)
	}
	saved, err := h.dir.Load()
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if saved.AppliedRevision != "rev1" {
		t.Errorf("state.json appliedRevision = %q, want rev1", saved.AppliedRevision)
	}

	doc, probes, cfgErr := h.applier.Applied()
	if cfgErr != nil {
		t.Errorf("configError = %v, want none", cfgErr)
	}
	if doc == nil || doc.ConfigRevision != "rev1" {
		t.Errorf("Applied doc = %+v, want rev1", doc)
	}
	if len(probes) != 1 {
		t.Errorf("%d probes, want one per target", len(probes))
	}
	if !strings.Contains(h.logs.String(), "applied revision rev1: 1 xray targets, 0 awg targets") {
		t.Errorf("logs = %q, want the spec §7 revision line", h.logs.String())
	}
}

// TestApply_TestFailureKeepsTheOldRevision is spec §4 step 3's "`-test`
// упал → остаться на старой ревизии": the previous document, the previous
// xray.json and the running child all stay, and the error becomes the
// configError. A later good revision clears it.
func TestApply_TestFailureKeepsTheOldRevision(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	before := h.xrayJSON(t)

	xraytest.Scripted(t, xraytest.Script{TestFail: "Failed to start: main: failed to load config files: bad outbound"})
	err := h.applier.Apply(ctx, revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), xrayTarget("direct", trojanGRPCLink)))
	if err == nil {
		t.Fatal("Apply = nil, want the -test failure")
	}
	if !strings.Contains(err.Error(), "bad outbound") {
		t.Errorf("error = %q, want xray's own first line", err)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1 kept", h.file.AppliedRevision)
	}
	if got := h.xrayJSON(t); got != before {
		t.Error("xray.json was replaced by a config that failed -test")
	}
	if !h.child.Running() {
		t.Error("the child was stopped by a failed -test; probes must continue on the old config")
	}
	doc, probes, cfgErr := h.applier.Applied()
	if doc.ConfigRevision != "rev1" || len(probes) != 1 {
		t.Errorf("Applied = %+v / %d probes, want the rev1 document", doc, len(probes))
	}
	if cfgErr == nil || !strings.Contains(cfgErr.Error(), "bad outbound") {
		t.Errorf("configError = %v, want the -test failure", cfgErr)
	}

	// A later revision that does pass clears the configError (spec §4
	// step 3: it is carried "until the next successful apply").
	t.Setenv(xraytest.ScriptEnv, "")
	if err := h.applier.Apply(ctx, revisionDoc("rev3", xrayTarget("proxy", vlessRealityLink), xrayTarget("direct", trojanGRPCLink))); err != nil {
		t.Fatalf("Apply rev3: %v", err)
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 2 {
		t.Errorf("after a good apply: configError = %v, %d probes; want none and two", cfgErr, len(probes))
	}
	if h.file.AppliedRevision != "rev3" {
		t.Errorf("AppliedRevision = %q, want rev3", h.file.AppliedRevision)
	}
	if !dialable(t, config.FirstSocksPort+1) {
		t.Errorf("socks port %d of the second target is not up", config.FirstSocksPort+1)
	}
}

// TestApply_RejectsBrokenTargetsAndAppliesTheRest is decision #53 п. 3:
// a revision is applied target by target. A link or .conf that will not
// parse — an unknown AWG key and an unsupported transport included — and an
// AWG-target whose trial IpcSet fails are rejected, each with its own
// error; the rest are applied and appliedRevision moves on. The rejections
// are what the heartbeat reports as client.rejectedTargets, and the
// configError stays clear, because the revision itself did apply.
func TestApply_RejectsBrokenTargetsAndAppliesTheRest(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}

	noFP := xrayTarget("direct", "vless://id@198.51.100.10:443?security=reality&pbk=k")
	kcp := proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 13, Path: "proxy"},
		Protocol:  "vless",
		Link:      "vless://id@198.51.100.11:443?type=kcp&encryption=none",
	}
	unknownKey := awgTargetWith(1, strings.Replace(awgConf, "Jc = 4", "Jc = 4\nFoo = 1", 1))
	badJc := awgTargetWith(2, strings.Replace(awgConf, "Jc = 4", "Jc = four", 1))
	doc := revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), noFP, kcp, awgTarget(), unknownKey, badJc)

	if err := h.applier.Apply(ctx, doc); err != nil {
		t.Fatalf("Apply rev2 = %v, want the valid targets applied", err)
	}
	if h.file.AppliedRevision != "rev2" {
		t.Errorf("AppliedRevision = %q, want rev2", h.file.AppliedRevision)
	}
	got, probes, cfgErr := h.applier.Applied()
	if cfgErr != nil {
		t.Errorf("configError = %v, want none: the revision applied", cfgErr)
	}
	if got.ConfigRevision != "rev2" {
		t.Errorf("Applied doc = %s, want rev2", got.ConfigRevision)
	}
	if len(probes) != 2 {
		t.Errorf("%d probes, want the valid xray and AWG targets only", len(probes))
	}
	for _, k := range []proto.TargetKey{{InboundKind: "xray", InboundID: 12, Path: "proxy"}, awgTarget().TargetKey} {
		if probes[k] == nil {
			t.Errorf("no probe for the valid target %s", k)
		}
	}
	if strings.Contains(h.xrayJSON(t), "198.51.100.11") {
		t.Error("xray.json carries a rejected target's outbound")
	}

	want := map[string]string{
		"xray:12:direct": "fp",
		"xray:13:proxy":  "unsupported transport",
		"awg:1:proxy":    "unknown key",
		"awg:2:proxy":    "jc",
	}
	rejected := h.applier.Rejected()
	if len(rejected) != len(want) {
		t.Fatalf("Rejected = %+v, want %d targets", rejected, len(want))
	}
	for _, r := range rejected {
		sub, ok := want[r.Target]
		if !ok {
			t.Errorf("rejected %s, which is valid", r.Target)
			continue
		}
		if !strings.Contains(r.Error, sub) {
			t.Errorf("%s rejected with %q, want it to name %q", r.Target, r.Error, sub)
		}
		if len(r.Error) > maxConfigError || strings.Contains(r.Error, "\n") {
			t.Errorf("%s error %q is not one line of at most %d characters", r.Target, r.Error, maxConfigError)
		}
	}

	// A revision that fixes them clears the rejections.
	if err := h.applier.Apply(ctx, revisionDoc("rev3", xrayTarget("proxy", vlessRealityLink), awgTarget())); err != nil {
		t.Fatalf("Apply rev3: %v", err)
	}
	if r := h.applier.Rejected(); len(r) != 0 {
		t.Errorf("Rejected = %+v after a clean revision, want none", r)
	}
}

// TestApply_AllTargetsRejectedStillApplies: a revision none of whose
// targets can be probed is still applied, with an empty probe set, so that
// the heartbeat carries the rejections under the new revision instead of
// the box sitting on the old one (decision #53 п. 3).
func TestApply_AllTargetsRejectedStillApplies(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	bad := xrayTarget("proxy", "vless://id@198.51.100.10:443?security=reality&pbk=k")
	if err := h.applier.Apply(ctx, revisionDoc("rev2", bad)); err != nil {
		t.Fatalf("Apply rev2 = %v, want it applied with nothing to probe", err)
	}
	if h.file.AppliedRevision != "rev2" {
		t.Errorf("AppliedRevision = %q, want rev2", h.file.AppliedRevision)
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 0 {
		t.Errorf("Applied = %d probes, err %v; want an empty probe set and no configError", len(probes), cfgErr)
	}
	if h.child.Running() {
		t.Error("the child still runs with every xray-target rejected")
	}
	if r := h.applier.Rejected(); len(r) != 1 || r[0].Target != "xray:12:proxy" {
		t.Errorf("Rejected = %+v, want the one target", r)
	}
}

// TestApply_TestFailureKeepsTheOldRejections: `xray -test` failing still
// rejects the revision as a whole (decision #53 п. 3), and with it every
// per-target verdict of that revision — the heartbeat keeps reporting the
// rejections of the revision that is actually in force.
func TestApply_TestFailureKeepsTheOldRejections(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	broken := awgTargetWith(1, strings.Replace(awgConf, "Jc = 4", "Jc = four", 1))
	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink), broken)); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}

	xraytest.Scripted(t, xraytest.Script{TestFail: "Failed to start: main: bad outbound"})
	bad := xrayTarget("direct", "vless://id@198.51.100.10:443?security=reality&pbk=k")
	if err := h.applier.Apply(ctx, revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), bad)); err == nil {
		t.Fatal("Apply rev2 = nil, want the -test failure")
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1 kept", h.file.AppliedRevision)
	}
	if r := h.applier.Rejected(); len(r) != 1 || r[0].Target != "awg:1:proxy" {
		t.Errorf("Rejected = %+v, want rev1's rejection kept", r)
	}
}

// TestApply_AWGOnlyDocumentWithoutXray is the AWG-only box of spec §1: no
// xray binary at all, and a document of AWG-targets still applies.
func TestApply_AWGOnlyDocumentWithoutXray(t *testing.T) {
	h := newApplierHarness(t, false)

	if err := h.applier.Apply(context.Background(), revisionDoc("rev1", awgTarget())); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1", h.file.AppliedRevision)
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 1 {
		t.Errorf("Applied = %d probes, err %v; want one AWG probe and no error", len(probes), cfgErr)
	}
	if _, err := os.Stat(h.dir.Path("xray.json")); !os.IsNotExist(err) {
		t.Error("xray.json was written by a box with no xray binary")
	}
}

// TestApply_XrayTargetWithoutBinaryIsAConfigError: the same box handed a
// document with xray-targets cannot probe them, and says so rather than
// pretending they are down (spec §4 step 3's configError).
func TestApply_XrayTargetWithoutBinaryIsAConfigError(t *testing.T) {
	h := newApplierHarness(t, false)

	err := h.applier.Apply(context.Background(), revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink)))
	if err == nil || !strings.Contains(err.Error(), "xray") {
		t.Fatalf("Apply = %v, want an error naming the missing xray binary", err)
	}
	if h.file.AppliedRevision != "" {
		t.Errorf("AppliedRevision = %q, want nothing applied", h.file.AppliedRevision)
	}
}

// TestApply_EmptyDocumentRunsAnEmptyCycle is spec §4 step 4: a box with no
// targets applies the document, keeps no child running and probes nothing.
func TestApply_EmptyDocumentRunsAnEmptyCycle(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	if err := h.applier.Apply(ctx, revisionDoc("rev2")); err != nil {
		t.Fatalf("Apply rev2 (empty): %v", err)
	}

	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 0 {
		t.Errorf("Applied = %d probes, err %v; want an empty cycle", len(probes), cfgErr)
	}
	if h.child.Running() {
		t.Error("the child is still running with no xray-targets left to probe")
	}
	if strings.Contains(h.xrayJSON(t), "198.51.100.10") {
		t.Error("xray.json still carries the dropped target")
	}
	if h.file.AppliedRevision != "rev2" {
		t.Errorf("AppliedRevision = %q, want rev2", h.file.AppliedRevision)
	}
}

// TestApply_WaitsForProbesInFlight is spec §4 step 3's "дождаться проб в
// полёте": the applier's cycle guard is what the loop holds for the
// duration of a cycle, and Apply must not swap anything while it is held.
func TestApply_WaitsForProbesInFlight(t *testing.T) {
	h := newApplierHarness(t, false)
	ctx := context.Background()
	if err := h.applier.Apply(ctx, revisionDoc("rev1", awgTarget())); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}

	var guard CycleGuard = h.applier
	guard.BeginCycle()

	applied := make(chan struct{})
	go func() {
		defer close(applied)
		if err := h.applier.Apply(ctx, revisionDoc("rev2", awgTarget())); err != nil {
			t.Errorf("Apply rev2: %v", err)
		}
	}()

	// While the cycle is in flight the old revision is still in force, no
	// matter how long the apply has been waiting.
	select {
	case <-applied:
		t.Fatal("Apply finished while a cycle was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	if doc, _, _ := h.applier.Applied(); doc.ConfigRevision != "rev1" {
		t.Fatalf("Applied revision = %q during a cycle, want rev1", doc.ConfigRevision)
	}

	guard.EndCycle()
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not finish after the cycle ended")
	}
	if doc, _, _ := h.applier.Applied(); doc.ConfigRevision != "rev2" {
		t.Fatalf("Applied revision = %q after the cycle, want rev2", doc.ConfigRevision)
	}
}

// TestLoop_ConfigErrorFromARealApplyReachesTheHeartbeat drives the whole
// step through the loop and a protocol stub: a revision that xray rejects
// leaves the heartbeat reporting the old revision plus the configError
// (spec §4 step 3, protocol §5.3), and the next revision that applies
// clears it.
func TestLoop_ConfigErrorFromARealApplyReachesTheHeartbeat(t *testing.T) {
	h := newHarness(t, nil)
	ha := newApplierHarness(t, true)
	// The loop and the applier must share one state file, exactly as
	// cmd/mon-client wires them.
	applier := NewRevisionApplier(ApplierDeps{
		XrayProber: &probe.Prober{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Xray:       ha.child,
		Dir:        h.dir,
		File:       h.file,
		Log:        slog.New(slog.NewTextHandler(h.logs, nil)),
	})
	loop := h.withApplier(t, applier)
	ctx := context.Background()

	h.stub.SetConfig(revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink)))
	h.stub.SetRevision("rev2") // mon-server already has a newer one
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if hbs := h.stub.Heartbeats(); len(hbs) != 1 || hbs[0].ConfigRevision != "rev1" || hbs[0].Client.ConfigError != nil {
		t.Fatalf("first heartbeat = %+v, want rev1 with no configError", hbs)
	}

	xraytest.Scripted(t, xraytest.Script{TestFail: "Failed to start: main: bad outbound in rev2"})
	h.stub.SetConfig(revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), xrayTarget("direct", trojanGRPCLink)))
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs := h.stub.Heartbeats()
	if len(hbs) != 2 {
		t.Fatalf("%d heartbeats, want 2", len(hbs))
	}
	if hbs[1].ConfigRevision != "rev1" {
		t.Errorf("configRevision = %q, want the old revision kept", hbs[1].ConfigRevision)
	}
	if hbs[1].Client.ConfigError == nil || !strings.Contains(*hbs[1].Client.ConfigError, "bad outbound in rev2") {
		t.Fatalf("client.configError = %v, want xray's -test line", hbs[1].Client.ConfigError)
	}

	t.Setenv(xraytest.ScriptEnv, "")
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs = h.stub.Heartbeats()
	if len(hbs) != 3 {
		t.Fatalf("%d heartbeats, want 3", len(hbs))
	}
	if hbs[2].ConfigRevision != "rev2" || hbs[2].Client.ConfigError != nil {
		t.Fatalf("third heartbeat = %+v, want rev2 with the configError cleared", hbs[2])
	}
	// Two targets now, so two results — and both probes went through the
	// child's socks ports, which is the whole point of the restart.
	if got := hbs[2].Cycles[0].Results; len(got) != 2 {
		t.Fatalf("%d results, want one per applied target", len(got))
	}
}

// TestLoop_RejectedTargetsReachTheHeartbeat: the applier's rejections ride
// along in every heartbeat as client.rejectedTargets (protocol §5.3), under
// the revision they belong to, and disappear once a revision applies
// without any.
func TestLoop_RejectedTargetsReachTheHeartbeat(t *testing.T) {
	h := newHarness(t, nil)
	applier := NewRevisionApplier(ApplierDeps{
		Dir:  h.dir,
		File: h.file,
		Log:  slog.New(slog.NewTextHandler(h.logs, nil)),
	})
	loop := h.withApplier(t, applier)
	ctx := context.Background()

	broken := awgTargetWith(3, strings.Replace(awgConf, "Jc = 4", "Jc = four", 1))
	h.stub.SetConfig(revisionDoc("rev1", broken))
	h.stub.SetRevision("rev1")
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs := h.stub.Heartbeats()
	if len(hbs) != 1 {
		t.Fatalf("%d heartbeats, want 1", len(hbs))
	}
	hb := hbs[0]
	if hb.ConfigRevision != "rev1" || hb.Client.ConfigError != nil {
		t.Errorf("heartbeat = rev %q, configError %v; want rev1 applied with no configError", hb.ConfigRevision, hb.Client.ConfigError)
	}
	if r := hb.Client.RejectedTargets; len(r) != 1 || r[0].Target != "awg:3:proxy" || !strings.Contains(r[0].Error, "jc") {
		t.Errorf("rejectedTargets = %+v, want awg:3:proxy with its IpcSet error", r)
	}

	h.stub.SetConfig(revisionDoc("rev2"))
	h.stub.SetRevision("rev2")
	if err := loop.Once(ctx); err != nil { // learns of rev2
		t.Fatalf("Once: %v", err)
	}
	if err := loop.Once(ctx); err != nil { // applies it
		t.Fatalf("Once: %v", err)
	}
	hbs = h.stub.Heartbeats()
	last := hbs[len(hbs)-1]
	if last.ConfigRevision != "rev2" || len(last.Client.RejectedTargets) != 0 {
		t.Errorf("last heartbeat = rev %q, rejectedTargets %+v; want rev2 with none", last.ConfigRevision, last.Client.RejectedTargets)
	}
}

// TestApply_StateSaveFailureKeepsOldRevision pins the order apply() works
// in: appliedRevision reaches state.json before the probe set is swapped,
// so a state directory that cannot be written (here read-only, the shape a
// full disk takes) leaves the old revision *fully* in force rather than
// probing the new targets while reporting the old revision to mon-server
// (protocol §5.3).
func TestApply_StateSaveFailureKeepsOldRevision(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	h := newApplierHarness(t, false)
	ctx := context.Background()

	// An AWG-only document: no xray child is involved, so the only write
	// this apply does is state.json's.
	first := revisionDoc("rev1", awgTarget())
	if err := h.applier.Apply(ctx, first); err != nil {
		t.Fatalf("apply rev1: %v", err)
	}

	if err := os.Chmod(h.dir.Path(""), 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(h.dir.Path(""), 0o700) })

	second := revisionDoc("rev2", awgTarget(), awgTarget2())
	err := h.applier.Apply(ctx, second)
	if err == nil {
		t.Fatal("apply reported success although appliedRevision could not be saved")
	}

	doc, probes, configErr := h.applier.Applied()
	if doc != first {
		t.Errorf("applied doc = %v, want rev1 — the old revision stays in force", doc)
	}
	if len(probes) != 1 {
		t.Errorf("applied probes = %d, want rev1's single target", len(probes))
	}
	if configErr == nil || !strings.Contains(configErr.Error(), "save applied revision") {
		t.Errorf("configError = %v, want the save failure", configErr)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("appliedRevision = %q, want rev1", h.file.AppliedRevision)
	}
}

// awgTarget2 is a second AWG-target, so a revision can differ from another
// in more than its name.
func awgTarget2() proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "awg", InboundID: 1, Path: "direct"},
		Protocol:  "awg",
		Conf:      awgConf,
	}
}

// TestRevive_RestartsADeadChild is decision #53 п. 4: an xray child that
// died between cycles (OOM, a crash) is restarted on the applied xray.json
// before the next cycle, so its targets are probed rather than reported as
// a false tcp_refused on a loopback port nobody listens on.
func TestRevive_RestartsADeadChild(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()
	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A healthy child is left alone: no restart, no log line.
	starts := strings.Count(h.logs.String(), "xray started")
	h.applier.Revive(ctx)
	if got := strings.Count(h.logs.String(), "xray started"); got != starts {
		t.Fatalf("Revive restarted a running child (%d starts, want %d)", got, starts)
	}

	if err := h.child.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	h.applier.Revive(ctx)

	if !h.child.Running() {
		t.Fatal("the dead child was not restarted")
	}
	if !dialable(t, config.FirstSocksPort) {
		t.Errorf("socks port %d is not up after the restart", config.FirstSocksPort)
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 1 {
		t.Errorf("Applied = %d probes, err %v; want the xray probe and no error", len(probes), cfgErr)
	}
}

// TestRevive_ChildThatStaysDownSkipsXrayProbes is the failing half of
// decision #53 п. 4: one restart attempt per cycle; while it fails, the
// cycle runs without the xray probes (AWG-targets still probed) and the
// configError is "xray: <first stderr line>". Once the child is back, the
// configError returns to the revision's own — here a later revision whose
// -test failed — and the xray probes return.
func TestRevive_ChildThatStaysDownSkipsXrayProbes(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()
	xrayKey := xrayTarget("proxy", vlessRealityLink).TargetKey
	awgKey := awgTarget().TargetKey

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink), awgTarget())); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	xraytest.Scripted(t, xraytest.Script{TestFail: "Failed to start: main: bad outbound in rev2"})
	if err := h.applier.Apply(ctx, revisionDoc("rev2", xrayTarget("direct", trojanGRPCLink))); err == nil {
		t.Fatal("Apply rev2 = nil, want the -test failure")
	}

	if err := h.child.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	xraytest.Scripted(t, xraytest.Script{ExitNow: true, ExitMsg: "Failed to start: main: port 10801 taken"})
	h.applier.Revive(ctx)

	if h.child.Running() {
		t.Fatal("the scripted child should not have come up")
	}
	_, probes, cfgErr := h.applier.Applied()
	if _, ok := probes[xrayKey]; ok {
		t.Error("the xray probe is still scheduled although xray is down")
	}
	if _, ok := probes[awgKey]; !ok {
		t.Error("the AWG probe was dropped along with xray's")
	}
	if cfgErr == nil || cfgErr.Error() != "xray: Failed to start: main: port 10801 taken" {
		t.Errorf("configError = %v, want xray's first stderr line", cfgErr)
	}

	// Still down on the next cycle: one more attempt, same report.
	h.applier.Revive(ctx)
	if _, _, cfgErr := h.applier.Applied(); cfgErr == nil || !strings.HasPrefix(cfgErr.Error(), "xray: ") {
		t.Errorf("configError = %v on the second failed attempt, want the xray error kept", cfgErr)
	}

	t.Setenv(xraytest.ScriptEnv, "")
	h.applier.Revive(ctx)
	if !h.child.Running() {
		t.Fatal("the child did not come back once it could")
	}
	_, probes, cfgErr = h.applier.Applied()
	if len(probes) != 2 {
		t.Errorf("%d probes after recovery, want both rev1 targets", len(probes))
	}
	if cfgErr == nil || !strings.Contains(cfgErr.Error(), "bad outbound in rev2") {
		t.Errorf("configError = %v after recovery, want the revision's own error back", cfgErr)
	}
}

// TestRevive_NothingToDoWithoutXrayTargets: an AWG-only revision has no
// child to keep alive, and Revive must not start one.
func TestRevive_NothingToDoWithoutXrayTargets(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()
	if err := h.applier.Apply(ctx, revisionDoc("rev1", awgTarget())); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	h.applier.Revive(ctx)
	if h.child.Running() {
		t.Error("Revive started an xray child for a revision with no xray-targets")
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 1 {
		t.Errorf("Applied = %d probes, err %v; want the AWG probe and no error", len(probes), cfgErr)
	}
}

// TestApply_SweepTargetsAreKeptReady is decision #100's mon-client side of
// sweepTargets: they are applied with the revision — an xray one gets its
// outbound and socks port in xray.json, so a sweep restarts nothing — but
// they are not in the every-cycle probe set; SweepProbes hands them out by
// inbound kind, and a broken one is rejected like any target.
func TestApply_SweepTargetsAreKeptReady(t *testing.T) {
	h := newApplierHarness(t, true)
	d := revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))
	sweepXray := xrayTarget("direct", trojanGRPCLink)
	sweepAwg := awgTarget()
	sweepAwg.Path = "direct"
	broken := awgTargetWith(2, strings.Replace(awgConf, "Jc = 4", "Jc = four", 1))
	broken.Path = "inner:core-1"
	d.SweepTargets = []proto.Target{sweepXray, sweepAwg, broken}

	if err := h.applier.Apply(context.Background(), d); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	_, probes, cfgErr := h.applier.Applied()
	if cfgErr != nil || len(probes) != 1 {
		t.Fatalf("Applied = %d probes, err %v; want the one every-cycle target", len(probes), cfgErr)
	}
	if _, ok := probes[xrayTarget("proxy", vlessRealityLink).TargetKey]; !ok {
		t.Fatal("the every-cycle target is not in the probe set")
	}
	if got := h.applier.SweepProbes([]string{"xray"}); len(got) != 1 || got[sweepXray.TargetKey] == nil {
		t.Fatalf("SweepProbes(xray) = %v, want the xray sweep target", got)
	}
	if got := h.applier.SweepProbes([]string{"xray", "awg"}); len(got) != 2 {
		t.Fatalf("SweepProbes(xray, awg) = %d probes, want both kinds' sweep targets", len(got))
	}
	if cfg := h.xrayJSON(t); !strings.Contains(cfg, "in-xray-12-direct") {
		t.Fatalf("xray.json has no inbound for the xray sweep target:\n%s", cfg)
	}
	rejected := h.applier.Rejected()
	if len(rejected) != 1 || rejected[0].Target != broken.TargetKey.String() {
		t.Fatalf("rejected = %+v, want the broken sweep target", rejected)
	}
}
