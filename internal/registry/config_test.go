package registry

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// testProbeURL is the probeUrl internal/app would compute from bootstrap
// config (spec §5); the builder itself takes it as a value.
const testProbeURL = "https://203.0.113.10:443/v1/probe"

// fakeMaterial is a MaterialSource a test can set by hand, standing in for
// *panel.Poller everywhere the panel itself is not what is under test.
type fakeMaterial struct {
	m  panel.Material
	ok bool
}

func (f *fakeMaterial) Material() (panel.Material, bool) { return f.m, f.ok }

// sampleMaterial is one panel revision with one xray inbound and one AWG
// one on both paths, the smallest material that exercises every rule in
// spec §5 (two kinds, two paths, an override). The AWG server has a probe
// peer per mon-client × path (contract 2, decision #80): ams-1 and fra-1
// each have their own item, with a conf that names its owner.
func sampleMaterial() panel.Material {
	return panel.Material{
		Revision:   "rev-1",
		Override:   panel.Override{Enabled: true, Host: "front.example.net"},
		ProbeSubID: "sub-1",
		Proxy: []panel.ProbeItem{
			{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe@front.example.net:443#probe-12"},
			{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "ams-1", Filename: "probe.conf", Conf: "[Peer]\nEndpoint = front.example.net:51820\n"},
			{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "fra-1", Filename: "probe.conf", Conf: "# fra-1 proxy\n[Peer]\nEndpoint = front.example.net:51820\n"},
		},
		Direct: []panel.ProbeItem{
			{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe@real.example.net:443#probe-12"},
			{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "ams-1", Filename: "probe.conf", Conf: "[Peer]\nEndpoint = real.example.net:51820\n"},
			{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "fra-1", Filename: "probe.conf", Conf: "# fra-1 direct\n[Peer]\nEndpoint = real.example.net:51820\n"},
		},
	}
}

// newTestBuilder builds a ConfigBuilder over a fresh store with the sample
// material already available, plus the panel_inbounds rows the protocol
// field is joined from (protocol §4.2).
func newTestBuilder(t *testing.T) (*ConfigBuilder, *Registry, *store.Store, *clock.Fake, *fakeMaterial) {
	t.Helper()
	r, st, clk := newTestRegistry(t)
	mat := &fakeMaterial{m: sampleMaterial(), ok: true}
	savePanelInbound(t, st, store.PanelInbound{
		InboundKind: store.InboundKindXray, InboundId: 12,
		Protocol: "vless", Port: 443, Remark: "Reality main", Enable: true,
	})
	savePanelInbound(t, st, store.PanelInbound{
		InboundKind: store.InboundKindAwg, InboundId: 0,
		Protocol: "awg", Port: 51820, Remark: "AWG", Enable: true,
	})
	return NewConfigBuilder(st, clk, mat, testProbeURL), r, st, clk, mat
}

// savePanelInbound upserts one panel_inbounds row the way the poller does
// (by its (kind, inboundId) key), so a test can both seed a row and change
// one it has already seeded.
func savePanelInbound(t *testing.T, st *store.Store, in store.PanelInbound) {
	t.Helper()
	err := st.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "inbound_kind"}, {Name: "inbound_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"protocol", "port", "remark", "enable", "seen_revision"}),
	}).Create(&in).Error
	if err != nil {
		t.Fatalf("save panel inbound: %v", err)
	}
}

// mustCurrent builds (if needed) and returns one mon-client's document.
func mustCurrent(t *testing.T, b *ConfigBuilder, id string) *ConfigDoc {
	t.Helper()
	doc, err := b.Current(context.Background(), id)
	if err != nil {
		t.Fatalf("Current(%q): %v", id, err)
	}
	return doc
}

// keysOf renders a document's targets as "kind:id/path" strings, the form
// an assertion failure is readable in.
func keysOf(doc *ConfigDoc) []string {
	out := make([]string, 0, len(doc.Targets))
	for _, ct := range doc.Targets {
		out = append(out, ct.InboundKind+":"+strconv.Itoa(ct.InboundID)+"/"+ct.Path)
	}
	return out
}

// --- Document shape (spec §5, protocol §4.2) ---

// TestRebuild_TargetsAreItemsTimesPaths checks the core rule: every path of
// the mon-client crossed with the items of that path, sorted, with protocol
// joined from panel_inbounds.
func TestRebuild_TargetsAreItemsTimesPaths(t *testing.T) {
	b, r, _, clk, _ := newTestBuilder(t)
	mc := approve(t, r, clk, "ams-1", nil)

	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	doc := mustCurrent(t, b, mc.Id)

	want := []string{"awg:0/direct", "awg:0/proxy", "xray:12/direct", "xray:12/proxy"}
	got := keysOf(doc)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if doc.MonClientID != mc.Id {
		t.Errorf("monClientId = %q, want %q", doc.MonClientID, mc.Id)
	}
	if doc.ProbeURL != testProbeURL {
		t.Errorf("probeUrl = %q, want %q", doc.ProbeURL, testProbeURL)
	}
	if doc.Probe.IntervalMs != 60000 || doc.Probe.HeartbeatTimeoutMs != 10000 {
		t.Errorf("probe = %+v, want the spec §9.4 defaults", doc.Probe)
	}
	for _, tgt := range doc.Targets {
		wantProto := "vless"
		if tgt.InboundKind == store.InboundKindAwg {
			wantProto = "awg"
		}
		if tgt.Protocol != wantProto {
			t.Errorf("target %s:%d/%s protocol = %q, want %q", tgt.InboundKind, tgt.InboundID, tgt.Path, tgt.Protocol, wantProto)
		}
	}
}

// TestRebuild_ProtocolComesFromPanelInbounds checks the join is real: an
// inbound whose panel_inbounds row says "vmess" shows up as vmess.
func TestRebuild_ProtocolComesFromPanelInbounds(t *testing.T) {
	b, r, st, clk, _ := newTestBuilder(t)
	savePanelInbound(t, st, store.PanelInbound{
		InboundKind: store.InboundKindXray, InboundId: 12,
		Protocol: "vmess", Port: 443, Enable: true,
	})
	mc := approve(t, r, clk, "ams-1", []string{store.PathDirect})

	if err := b.Rebuild(context.Background(), mc.Id); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	doc := mustCurrent(t, b, mc.Id)
	for _, tgt := range doc.Targets {
		if tgt.InboundKind == store.InboundKindXray && tgt.Protocol != "vmess" {
			t.Fatalf("protocol = %q, want vmess", tgt.Protocol)
		}
	}
}

// TestRebuild_ProxyOnlyClientNeverSeesRealServer is the hostile-region rule
// (protocol §4.2): a mon-client with paths=["hops"] gets no direct targets
// and its document never mentions the real server's address.
func TestRebuild_ProxyOnlyClientNeverSeesRealServer(t *testing.T) {
	b, r, st, clk, _ := newTestBuilder(t)
	mc := approve(t, r, clk, "hostile-1", []string{store.PathHops})

	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	doc := mustCurrent(t, b, mc.Id)
	for _, tgt := range doc.Targets {
		if tgt.Path != store.PathProxy {
			t.Fatalf("target %s:%d has path %q, want only proxy", tgt.InboundKind, tgt.InboundID, tgt.Path)
		}
	}

	var row store.ClientConfig
	if err := st.DB.First(&row, "mon_client_id = ?", mc.Id).Error; err != nil {
		t.Fatalf("load client_configs: %v", err)
	}
	if strings.Contains(row.Document, "real.example.net") {
		t.Fatalf("document leaks the real server's address: %s", row.Document)
	}
}

// TestRebuild_OverrideOffDropsProxyTargets checks spec §5: without the
// panel's host override there is no proxy front to probe, so a mon-client
// that asks for the proxy path simply gets no proxy targets.
func TestRebuild_OverrideOffDropsProxyTargets(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	m := sampleMaterial()
	m.Override = panel.Override{Enabled: false}
	mat.m = m
	mc := approve(t, r, clk, "ams-1", nil)

	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	doc := mustCurrent(t, b, mc.Id)
	if len(doc.Targets) == 0 {
		t.Fatal("no targets at all, want the direct ones")
	}
	for _, tgt := range doc.Targets {
		if tgt.Path == store.PathProxy {
			t.Fatalf("proxy target %s:%d present with the override off", tgt.InboundKind, tgt.InboundID)
		}
	}
}

// TestRebuild_LinkAndConfPassedThrough checks spec §5's "как есть": the
// panel has already substituted the right host, so mon-server copies.
func TestRebuild_LinkAndConfPassedThrough(t *testing.T) {
	b, r, _, clk, _ := newTestBuilder(t)
	mc := approve(t, r, clk, "ams-1", []string{store.PathHops})
	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	doc := mustCurrent(t, b, mc.Id)
	for _, tgt := range doc.Targets {
		switch tgt.InboundKind {
		case store.InboundKindXray:
			if tgt.Link != "vless://probe@front.example.net:443#probe-12" || tgt.Conf != "" {
				t.Errorf("xray target = %+v, want the proxy link verbatim and no conf", tgt)
			}
		case store.InboundKindAwg:
			if tgt.Conf != "[Peer]\nEndpoint = front.example.net:51820\n" || tgt.Link != "" {
				t.Errorf("awg target = %+v, want the proxy conf verbatim and no link", tgt)
			}
		}
	}
}

// --- Revision (spec §5, protocol §4.1) ---

// TestCanonicalJSON_KeyOrderDoesNotMatter is the canonical-JSON contract the
// revision rests on: the same document with its keys written in a different
// order hashes identically, and configRevision itself is never part of the
// input.
func TestCanonicalJSON_KeyOrderDoesNotMatter(t *testing.T) {
	a := []byte(`{"configRevision":"aaaa","monClientId":"ams-1","probe":{"budgetMs":20000,"intervalMs":60000}}`)
	bb := []byte(`{"probe":{"intervalMs":60000,"budgetMs":20000},"monClientId":"ams-1","configRevision":"bbbb"}`)

	ca, err := canonicalJSON(a)
	if err != nil {
		t.Fatalf("canonicalJSON(a): %v", err)
	}
	cb, err := canonicalJSON(bb)
	if err != nil {
		t.Fatalf("canonicalJSON(b): %v", err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("canonical forms differ:\n%s\n%s", ca, cb)
	}
	if strings.Contains(string(ca), "configRevision") {
		t.Fatalf("canonical form still carries configRevision: %s", ca)
	}
}

// TestRevision_StableAcrossRebuilds checks that rebuilding from unchanged
// material yields the same revision — otherwise every panel poll would make
// every mon-client re-fetch and restart xray (protocol §4.3).
func TestRevision_StableAcrossRebuilds(t *testing.T) {
	b, r, _, clk, _ := newTestBuilder(t)
	mc := approve(t, r, clk, "ams-1", nil)

	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	first := mustRevision(t, b, mc.Id)

	clk.Advance(time.Minute)
	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll (again): %v", err)
	}
	if got := mustRevision(t, b, mc.Id); got != first {
		t.Fatalf("revision changed on an unchanged rebuild: %q → %q", first, got)
	}
}

func mustRevision(t *testing.T, b *ConfigBuilder, id string) string {
	t.Helper()
	rev, err := b.CurrentRevision(context.Background(), id)
	if err != nil {
		t.Fatalf("CurrentRevision(%q): %v", id, err)
	}
	if len(rev) != revisionHexLen {
		t.Fatalf("revision %q is %d chars, want %d", rev, len(rev), revisionHexLen)
	}
	return rev
}

// TestRevision_ChangesWith walks every input spec §5 says the revision must
// react to — paths, probe parameters, the real server's address (which
// reaches the builder as changed direct material) and a panel revision that
// actually changed the items — and the one it must not react to: an inbound
// remark, which is not part of the document at all.
func TestRevision_ChangesWith(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, b *ConfigBuilder, st *store.Store, r *Registry, mat *fakeMaterial, id string)
		want   bool // true: the revision must change
	}{
		{
			name: "paths",
			mutate: func(t *testing.T, b *ConfigBuilder, st *store.Store, r *Registry, mat *fakeMaterial, id string) {
				if err := r.Update(context.Background(), id, "ams-1", "", []string{store.PathHops}); err != nil {
					t.Fatalf("Update: %v", err)
				}
			},
			want: true,
		},
		{
			name: "probe parameters",
			mutate: func(t *testing.T, b *ConfigBuilder, st *store.Store, r *Registry, mat *fakeMaterial, id string) {
				set, err := st.LoadSettings()
				if err != nil {
					t.Fatalf("LoadSettings: %v", err)
				}
				set.BudgetMs = 25000
				if err := st.SaveSettings(set); err != nil {
					t.Fatalf("SaveSettings: %v", err)
				}
			},
			want: true,
		},
		{
			name: "realHost",
			mutate: func(t *testing.T, b *ConfigBuilder, st *store.Store, r *Registry, mat *fakeMaterial, id string) {
				m := mat.m
				m.Revision = "rev-2"
				m.Direct = []panel.ProbeItem{
					{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe@other.example.net:443#probe-12"},
					{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "ams-1", Conf: "[Peer]\nEndpoint = other.example.net:51820\n"},
				}
				mat.m = m
			},
			want: true,
		},
		{
			name: "panel revision with new items",
			mutate: func(t *testing.T, b *ConfigBuilder, st *store.Store, r *Registry, mat *fakeMaterial, id string) {
				m := mat.m
				m.Revision = "rev-3"
				m.Direct = append(append([]panel.ProbeItem(nil), m.Direct...),
					panel.ProbeItem{Kind: store.InboundKindXray, InboundId: 13, Link: "vless://probe@real.example.net:8443#probe-13"})
				mat.m = m
			},
			want: true,
		},
		{
			name: "remark only",
			mutate: func(t *testing.T, b *ConfigBuilder, st *store.Store, r *Registry, mat *fakeMaterial, id string) {
				savePanelInbound(t, st, store.PanelInbound{
					InboundKind: store.InboundKindXray, InboundId: 12,
					Protocol: "vless", Port: 443, Remark: "renamed in the panel", Enable: true,
				})
				m := mat.m
				m.Revision = "rev-4"
				mat.m = m
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, r, st, clk, mat := newTestBuilder(t)
			mc := approve(t, r, clk, "ams-1", nil)
			if err := b.RebuildAll(context.Background()); err != nil {
				t.Fatalf("RebuildAll: %v", err)
			}
			before := mustRevision(t, b, mc.Id)

			tc.mutate(t, b, st, r, mat, mc.Id)
			if err := b.RebuildAll(context.Background()); err != nil {
				t.Fatalf("RebuildAll (after mutation): %v", err)
			}
			after := mustRevision(t, b, mc.Id)

			if tc.want && before == after {
				t.Fatalf("revision unchanged (%q) after changing %s", before, tc.name)
			}
			if !tc.want && before != after {
				t.Fatalf("revision changed (%q → %q) after changing %s, which is not part of the document", before, after, tc.name)
			}
		})
	}
}

// --- Current / CurrentRevision / TargetKeys ---

// TestCurrent_NoMaterialIsErrNoConfig checks the state a freshly installed
// mon-server is in before its first successful panel poll: there is nothing
// to answer GET /v1/config with (spec §5).
func TestCurrent_NoMaterialIsErrNoConfig(t *testing.T) {
	r, st, clk := newTestRegistry(t)
	b := NewConfigBuilder(st, clk, &fakeMaterial{}, testProbeURL)
	mc := approve(t, r, clk, "ams-1", nil)

	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll with no material: %v", err)
	}
	if _, err := b.Current(context.Background(), mc.Id); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("Current err = %v, want ErrNoConfig", err)
	}
	rev, err := b.CurrentRevision(context.Background(), mc.Id)
	if err != nil || rev != "" {
		t.Fatalf("CurrentRevision = (%q, %v), want (\"\", nil)", rev, err)
	}
	keys, err := b.TargetKeys(context.Background(), mc.Id)
	if err != nil || keys != nil {
		t.Fatalf("TargetKeys = (%v, %v), want (nil, nil)", keys, err)
	}
}

// TestCurrent_BuildsOnDemand checks a mon-client approved between two panel
// revisions still gets a document on its very first GET /v1/config, without
// waiting for the next material change to rebuild everything.
func TestCurrent_BuildsOnDemand(t *testing.T) {
	b, r, st, clk, _ := newTestBuilder(t)
	mc := approve(t, r, clk, "ams-1", nil)

	doc := mustCurrent(t, b, mc.Id)
	if len(doc.Targets) == 0 {
		t.Fatal("built document has no targets")
	}
	var n int64
	if err := st.DB.Model(&store.ClientConfig{}).Where("mon_client_id = ?", mc.Id).Count(&n).Error; err != nil {
		t.Fatalf("count client_configs: %v", err)
	}
	if n != 1 {
		t.Fatalf("client_configs rows = %d, want 1 (Current must persist what it built)", n)
	}
}

// TestTargetKeys_MatchesDocument checks step 6/8's view of the config (the
// heartbeat's unknown-target filter, the probe handler's) is exactly the
// document's target list.
func TestTargetKeys_MatchesDocument(t *testing.T) {
	b, r, _, clk, _ := newTestBuilder(t)
	mc := approve(t, r, clk, "ams-1", nil)
	doc := mustCurrent(t, b, mc.Id)

	keys, err := b.TargetKeys(context.Background(), mc.Id)
	if err != nil {
		t.Fatalf("TargetKeys: %v", err)
	}
	if len(keys) != len(doc.Targets) {
		t.Fatalf("TargetKeys len = %d, doc targets = %d", len(keys), len(doc.Targets))
	}
	for i, k := range keys {
		tgt := doc.Targets[i]
		if k != (TargetKey{InboundKind: tgt.InboundKind, InboundID: tgt.InboundID, Path: tgt.Path}) {
			t.Fatalf("key %d = %+v, want %+v", i, k, tgt)
		}
	}
}

// --- Hooks and the snapshot adapter ---

// TestApproveRunsApprovedHook checks the hook step 5 adds so a brand-new
// mon-client has a config document the moment it is approved, not a panel
// poll later (spec §5).
func TestApproveRunsApprovedHook(t *testing.T) {
	b, r, _, clk, _ := newTestBuilder(t)
	var approved []string
	r.SetHooks(Hooks{Approved: func(ctx context.Context, id string) error {
		approved = append(approved, id)
		return b.Rebuild(ctx, id)
	}})

	mc := approve(t, r, clk, "ams-1", nil)
	if len(approved) != 1 || approved[0] != mc.Id {
		t.Fatalf("Approved hook calls = %v, want [%q]", approved, mc.Id)
	}
	if rev := mustRevision(t, b, mc.Id); rev == "" {
		t.Fatal("no config built by the Approved hook")
	}

	// And again for the replacement path (spec §6).
	clk.Advance(rateLimitWindow)
	out := register(t, r, "ams-1", "", "198.51.100.9")
	if _, err := r.ApproveAsReplacement(context.Background(), out.RequestID, mc.Id); err != nil {
		t.Fatalf("ApproveAsReplacement: %v", err)
	}
	if len(approved) != 2 {
		t.Fatalf("Approved hook calls = %v, want one more after ApproveAsReplacement", approved)
	}
}

// TestSnapshotSource maps the registry rows onto the panel's own snapshot
// type (contract §4.3), including the "never heartbeated" case.
func TestSnapshotSource(t *testing.T) {
	r, st, clk := newTestRegistry(t)
	mc := approve(t, r, clk, "ams-1", nil)

	snap, err := r.SnapshotSource().Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	if snap[0].Id != mc.Id || snap[0].State != store.MonClientNever || snap[0].LastHeartbeat != 0 {
		t.Fatalf("snapshot[0] = %+v, want id %q, state NEVER, lastHeartbeat 0", snap[0], mc.Id)
	}

	hb := int64(1750000000000)
	if err := st.DB.Model(&store.MonClient{}).Where("id = ?", mc.Id).
		Updates(map[string]any{"last_heartbeat": hb, "state": store.MonClientOnline, "region": "NL"}).Error; err != nil {
		t.Fatalf("update mon-client: %v", err)
	}
	snap, err = r.SnapshotSource().Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap[0].LastHeartbeat != hb || snap[0].State != store.MonClientOnline || snap[0].Region != "NL" {
		t.Fatalf("snapshot[0] = %+v, want the updated heartbeat/state/region", snap[0])
	}
}

// TestSnapshotSource_Paths checks contract 3 §4.3 with decision #100: the
// snapshot carries every path each mon-client holds targets on, so the
// panel keeps AWG probe peers for exactly those pairs. A vocabulary without
// edges goes as stored; edges — stored, or the default applied to a row
// that has none — goes as the whole chain, direct and hops, in the words
// the panel knows, since a diagnostic sweep needs probe material on every
// path.
func TestSnapshotSource_Paths(t *testing.T) {
	r, st, clk := newTestRegistry(t)
	mc := approve(t, r, clk, "ams-1", []string{store.PathDirect})
	if err := st.DB.Model(&store.MonClient{}).Where("id = ?", mc.Id).Update("paths", "[]").Error; err != nil {
		t.Fatalf("clear paths: %v", err)
	}
	approve(t, r, clk, "msk-1", []string{store.PathDirect})
	approve(t, r, clk, "fra-1", []string{store.PathEdges, "inner:core-1"})

	snap, err := r.SnapshotSource().Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	got := map[string]string{}
	for _, s := range snap {
		got[s.Id] = strings.Join(s.Paths, ",")
	}
	want := map[string]string{"ams-1": "direct,hops", "msk-1": "direct", "fra-1": "direct,hops,inner:core-1"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("snapshot paths of %s = %q, want %q", id, got[id], w)
		}
	}
}

// TestSnapshotSource_SaveUnallocated checks that the ensure's unallocated
// pairs land on their mon-clients (spec §3 mon_clients.unallocated) with
// the panel's reasons, that a mon-client the list does not name is cleared,
// and that a pair of a mon-client mon-server does not know is ignored.
func TestSnapshotSource_SaveUnallocated(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	approve(t, r, clk, "ams-1", nil)
	approve(t, r, clk, "msk-1", nil)
	src := r.SnapshotSource()
	ctx := context.Background()

	err := src.SaveUnallocated(ctx, []panel.Unallocated{
		{MonClientId: "ams-1", Path: "inner:core-1", Reason: store.UnallocatedLimit},
		{MonClientId: "ams-1", Path: "edge:edge-b", Reason: store.UnallocatedLimit},
		{MonClientId: "msk-1", Path: store.PathDirect, Reason: store.UnallocatedPoolExhausted},
		{MonClientId: "gone-1", Path: store.PathDirect, Reason: store.UnallocatedLimit},
	})
	if err != nil {
		t.Fatalf("SaveUnallocated: %v", err)
	}
	unallocated := func(id string) string {
		mc, err := r.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get(%s): %v", id, err)
		}
		var out []string
		for _, u := range mc.UnallocatedList() {
			out = append(out, u.Path+"/"+u.Reason)
		}
		return strings.Join(out, ",")
	}
	if got := unallocated("ams-1"); got != "inner:core-1/limit,edge:edge-b/limit" {
		t.Fatalf("ams-1 unallocated = %s", got)
	}
	if got := unallocated("msk-1"); got != "direct/pool_exhausted" {
		t.Fatalf("msk-1 unallocated = %s", got)
	}

	if err := src.SaveUnallocated(ctx, []panel.Unallocated{{MonClientId: "msk-1", Path: store.PathDirect, Reason: store.UnallocatedLimit}}); err != nil {
		t.Fatalf("SaveUnallocated: %v", err)
	}
	if got := unallocated("ams-1"); got != "" {
		t.Fatalf("ams-1 unallocated = %s after a list without it, want cleared", got)
	}
	if got := unallocated("msk-1"); got != "direct/limit" {
		t.Fatalf("msk-1 unallocated = %s, want the new reason", got)
	}
}

// --- End to end through the real poller and a panel stub ---

// TestRebuildAllThroughPoller drives the whole seam spec §4 step 3
// describes: the poller reads a panel revision, hands the material to this
// builder, and a later revision with different items produces a new config
// revision for the mon-client.
func TestRebuildAllThroughPoller(t *testing.T) {
	stub := paneltest.NewStub(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	st.Clock = clk

	set := store.DefaultSettings()
	set.PanelURL = stub.URL()
	set.MonToken = stub.Token()
	set.RealHost = "real.example.net"
	if err := st.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	stub.SetInbounds([]panel.Inbound{
		{Kind: store.InboundKindXray, InboundId: 12, Tag: "inbound-443", Protocol: "vless", Port: 443, Enable: true},
	})
	stub.SetOverride(true, "front.example.net")
	stub.SetItems("direct", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://direct-1"}})
	stub.SetItems("proxy", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://proxy-1"}})

	r := New(st, clk)
	poller := panel.NewPoller(panel.PollerDeps{Store: st, Clock: clk, Notifier: tg.Nop{}})
	b := NewConfigBuilder(st, clk, poller, testProbeURL)
	poller.SetConfigs(b)
	poller.SetSnapshot(r.SnapshotSource())

	mc := approve(t, r, clk, "ams-1", nil)

	if err := poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	first := mustRevision(t, b, mc.Id)
	doc := mustCurrent(t, b, mc.Id)
	if len(doc.Targets) != 2 {
		t.Fatalf("targets = %v, want one per path", keysOf(doc))
	}

	// A panel revision that changes the material: new links on both paths.
	stub.SetItems("direct", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://direct-2"}})
	stub.SetItems("proxy", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://proxy-2"}})
	stub.SetInbounds([]panel.Inbound{
		{Kind: store.InboundKindXray, InboundId: 12, Tag: "inbound-443", Protocol: "vless", Port: 443, Enable: true},
		{Kind: store.InboundKindXray, InboundId: 13, Tag: "inbound-8443", Protocol: "vless", Port: 8443, Enable: true},
	})
	if err := poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll (second): %v", err)
	}
	if second := mustRevision(t, b, mc.Id); second == first {
		t.Fatalf("config revision unchanged (%q) after a panel revision with new material", first)
	}
}

// TestExclusions_Reason is decision #51 §3: a target outside a mon-client's
// config for a reason that is not its inbound gets the reason it is PAUSED
// with. An inbound that is disabled or gone is not this function's business
// (SyncInbounds pauses those with config_disabled), and without material
// nothing can be said at all.
func TestExclusions_Reason(t *testing.T) {
	proxy12 := TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy}
	direct12 := TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathDirect}
	direct13 := TargetKey{InboundKind: store.InboundKindXray, InboundID: 13, Path: store.PathDirect}
	direct14 := TargetKey{InboundKind: store.InboundKindXray, InboundID: 14, Path: store.PathDirect}
	direct99 := TargetKey{InboundKind: store.InboundKindXray, InboundID: 99, Path: store.PathDirect}

	cases := []struct {
		name     string
		paths    []string
		override bool
		key      TargetKey
		want     string
	}{
		{"path taken off the mon-client", []string{store.PathHops}, true, direct12, PausePathRemoved},
		{"override switched off", []string{store.PathHops, store.PathDirect}, false, proxy12, PauseOverrideDisabled},
		{"path removed wins over override", []string{store.PathDirect}, false, proxy12, PausePathRemoved},
		{"enabled inbound without a probe link", []string{store.PathDirect}, true, direct13, PauseNoProbeLink},
		{"disabled inbound is the inbound's business", []string{store.PathDirect}, true, direct14, ""},
		{"vanished inbound is the inbound's business", []string{store.PathDirect}, true, direct99, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, r, st, clk, mat := newTestBuilder(t)
			savePanelInbound(t, st, store.PanelInbound{InboundKind: store.InboundKindXray, InboundId: 13, Protocol: "vless", Enable: true})
			savePanelInbound(t, st, store.PanelInbound{InboundKind: store.InboundKindXray, InboundId: 14, Protocol: "vless", Enable: false})
			m := sampleMaterial()
			m.Override.Enabled = tc.override
			mat.m = m
			mc := approve(t, r, clk, "ams-1", tc.paths)

			x, err := b.Exclusions(context.Background(), mc.Id)
			if err != nil {
				t.Fatalf("Exclusions: %v", err)
			}
			if got := x.Reason(tc.key); got != tc.want {
				t.Fatalf("Reason(%+v) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}

	t.Run("no material says nothing", func(t *testing.T) {
		b, r, _, clk, mat := newTestBuilder(t)
		mat.ok = false
		mc := approve(t, r, clk, "ams-1", []string{store.PathHops})
		x, err := b.Exclusions(context.Background(), mc.Id)
		if err != nil {
			t.Fatalf("Exclusions: %v", err)
		}
		if got := x.Reason(direct12); got != "" {
			t.Fatalf("Reason without material = %q, want empty", got)
		}
	})
}

// TestRebuild_AwgItemsArePerMonClient is decision #80 п. 1, 7: xray items
// are shared by every mon-client, but an AWG item is one mon-client's probe
// peer on that path, so each document carries only its own mon-client's
// AWG conf. A mon-client with no item (the panel's pool is exhausted) gets
// no AWG target at all, and an AWG item naming nobody — the shared peer of
// a contract-1 panel — goes to nobody.
func TestRebuild_AwgItemsArePerMonClient(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	m := mat.m
	m.Direct = append(append([]panel.ProbeItem(nil), m.Direct...),
		panel.ProbeItem{Kind: store.InboundKindAwg, InboundId: 0, Conf: "shared peer of an old panel"})
	mat.m = m

	ams := approve(t, r, clk, "ams-1", nil)
	fra := approve(t, r, clk, "fra-1", nil)
	waw := approve(t, r, clk, "waw-1", nil)
	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}

	confs := func(doc *ConfigDoc) map[string]string {
		out := map[string]string{}
		for _, tgt := range doc.Targets {
			if tgt.InboundKind == store.InboundKindAwg {
				out[tgt.Path] = tgt.Conf
			}
		}
		return out
	}
	links := func(doc *ConfigDoc) map[string]string {
		out := map[string]string{}
		for _, tgt := range doc.Targets {
			if tgt.InboundKind == store.InboundKindXray {
				out[tgt.Path] = tgt.Link
			}
		}
		return out
	}

	amsDoc, fraDoc, wawDoc := mustCurrent(t, b, ams.Id), mustCurrent(t, b, fra.Id), mustCurrent(t, b, waw.Id)

	if got := confs(amsDoc); got[store.PathProxy] != "[Peer]\nEndpoint = front.example.net:51820\n" ||
		got[store.PathDirect] != "[Peer]\nEndpoint = real.example.net:51820\n" || len(got) != 2 {
		t.Errorf("ams-1 awg confs = %q, want its own proxy and direct confs only", got)
	}
	if got := confs(fraDoc); got[store.PathProxy] != "# fra-1 proxy\n[Peer]\nEndpoint = front.example.net:51820\n" ||
		got[store.PathDirect] != "# fra-1 direct\n[Peer]\nEndpoint = real.example.net:51820\n" || len(got) != 2 {
		t.Errorf("fra-1 awg confs = %q, want its own proxy and direct confs only", got)
	}
	if got := confs(wawDoc); len(got) != 0 {
		t.Errorf("waw-1 awg confs = %q, want none: the panel gave it no peer", got)
	}
	if got := keysOf(wawDoc); strings.Join(got, ",") != "xray:12/direct,xray:12/proxy" {
		t.Errorf("waw-1 targets = %v, want the shared xray targets only", got)
	}

	for _, doc := range []*ConfigDoc{fraDoc, wawDoc} {
		if got, want := links(doc), links(amsDoc); len(got) != 2 || got[store.PathProxy] != want[store.PathProxy] || got[store.PathDirect] != want[store.PathDirect] {
			t.Errorf("%s xray links = %q, want the shared %q", doc.MonClientID, got, want)
		}
	}
	if amsDoc.ConfigRevision == fraDoc.ConfigRevision {
		t.Error("ams-1 and fra-1 share a config revision, want different documents")
	}
}

// TestExclusions_ExpectedAwgTargets checks what the state engine asks of
// the builder for decision #80 п. 10: the AWG targets a mon-client is owed
// by the panel's state — enabled AWG servers × its paths, proxy only with
// the override on — whether or not its document has them.
func TestExclusions_ExpectedAwgTargets(t *testing.T) {
	b, r, st, clk, mat := newTestBuilder(t)
	waw := approve(t, r, clk, "waw-1", nil)
	hostile := approve(t, r, clk, "hostile-1", []string{store.PathHops})

	render := func(keys []TargetKey) string {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, k.InboundKind+":"+strconv.Itoa(k.InboundID)+"/"+k.Path)
		}
		return strings.Join(out, ",")
	}
	expected := func(id string) string {
		t.Helper()
		x, err := b.Exclusions(context.Background(), id)
		if err != nil {
			t.Fatalf("Exclusions(%s): %v", id, err)
		}
		return render(x.Expected(store.InboundKindAwg))
	}

	if got := expected(waw.Id); got != "awg:0/direct,awg:0/proxy" {
		t.Errorf("waw-1 expects %q, want both paths", got)
	}
	if got := expected(hostile.Id); got != "awg:0/proxy" {
		t.Errorf("hostile-1 expects %q, want its one path", got)
	}

	m := mat.m
	m.Override = panel.Override{}
	mat.m = m
	if got := expected(waw.Id); got != "awg:0/direct" {
		t.Errorf("override off: waw-1 expects %q, want direct only", got)
	}

	savePanelInbound(t, st, store.PanelInbound{
		InboundKind: store.InboundKindAwg, InboundId: 0, Protocol: "awg", Port: 51820, Remark: "AWG", Enable: false,
	})
	if got := expected(waw.Id); got != "" {
		t.Errorf("awg server disabled: waw-1 expects %q, want nothing", got)
	}

	mat.ok = false
	if got := expected(waw.Id); got != "" {
		t.Errorf("no material: waw-1 expects %q, want nothing", got)
	}
}

// --- Paths by chain (spec §5.1, decision #61) ---

// chainMaterial is sampleMaterial on a chained panel: an inner hop and two
// edges, edge-a active, each hop with its own xray link and one AWG peer
// per mon-client (ams-1 everywhere, fra-1 on the edges only). Proxy items
// are left in to prove they are never used once the chain has probed hops.
func chainMaterial(active string) panel.Material {
	m := sampleMaterial()
	m.Revision = "rev-chain-" + active
	m.Chain = &panel.Chain{Revision: 7, ActiveEdge: &active, Hops: []panel.Hop{
		{Name: "core-1", Role: "inner", Host: "10.0.0.7", State: "joined"},
		{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "joined"},
		{Name: "edge-b", Role: "edge", Host: "b.example.net", State: "legacy"},
	}}
	m.Hops = map[string][]panel.ProbeItem{}
	for _, h := range m.Chain.Hops {
		items := []panel.ProbeItem{
			{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe@" + h.Host + ":443#probe-12"},
			{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "ams-1", Conf: "[Peer]\nEndpoint = " + h.Host + ":51820\n"},
		}
		if h.Role == "edge" {
			items = append(items, panel.ProbeItem{Kind: store.InboundKindAwg, InboundId: 0, MonClientId: "fra-1", Conf: "# fra-1\n[Peer]\nEndpoint = " + h.Host + ":51820\n"})
		}
		m.Hops[h.Path()] = items
	}
	return m
}

// TestExpandPaths is spec §5.1's table: direct is direct; hops is every
// probed hop — or proxy on a panel without one; edges is every probed edge,
// active and standby — or proxy on a panel without one (decision #100); a
// hop by name is that hop while it is probed and nothing otherwise; a
// repeat after expansion is one path.
func TestExpandPaths(t *testing.T) {
	flat := sampleMaterial()
	chained := chainMaterial("edge-a")
	cases := []struct {
		name  string
		mat   panel.Material
		vocab []string
		want  string
	}{
		{"no chain, default", flat, []string{store.PathDirect, store.PathHops}, "direct,proxy"},
		{"no chain, hops only", flat, []string{store.PathHops}, "proxy"},
		{"no chain, a hop by name", flat, []string{store.PathDirect, "edge:edge-a"}, "direct"},
		{"chain, default", chained, []string{store.PathDirect, store.PathHops}, "direct,inner:core-1,edge:edge-a,edge:edge-b"},
		{"chain, hops only", chained, []string{store.PathHops}, "inner:core-1,edge:edge-a,edge:edge-b"},
		{"chain, hops by name", chained, []string{"edge:edge-b", "inner:core-1"}, "edge:edge-b,inner:core-1"},
		{"chain, a hop that is not probed", chained, []string{store.PathDirect, "edge:gone", "inner:edge-a"}, "direct"},
		{"chain, hops and a name", chained, []string{store.PathHops, "edge:edge-a"}, "inner:core-1,edge:edge-a,edge:edge-b"},
		{"no chain, edges", flat, []string{store.PathEdges}, "proxy"},
		{"chain, edges", chained, []string{store.PathEdges}, "edge:edge-a,edge:edge-b"},
		{"chain, edges and direct", chained, []string{store.PathEdges, store.PathDirect}, "edge:edge-a,edge:edge-b,direct"},
		{"chain, edges and an inner by name", chained, []string{store.PathEdges, "inner:core-1"}, "edge:edge-a,edge:edge-b,inner:core-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(ExpandPaths(tc.vocab, tc.mat), ","); got != tc.want {
				t.Fatalf("ExpandPaths(%v) = %s, want %s", tc.vocab, got, tc.want)
			}
		})
	}
}

// TestRebuild_ChainTargets checks the targets of a chained panel (decision
// #61 п. 1): inbounds × direct and every probed hop, proxy never, each
// hop's link as the panel rendered it, and AWG only where the mon-client
// has its own peer.
func TestRebuild_ChainTargets(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	mat.m = chainMaterial("edge-a")
	ams := approve(t, r, clk, "ams-1", nil)
	fra := approve(t, r, clk, "fra-1", []string{store.PathHops})
	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}

	amsDoc := mustCurrent(t, b, ams.Id)
	want := "awg:0/direct,awg:0/edge:edge-a,awg:0/edge:edge-b,awg:0/inner:core-1,xray:12/direct,xray:12/edge:edge-a,xray:12/edge:edge-b,xray:12/inner:core-1"
	if got := strings.Join(keysOf(amsDoc), ","); got != want {
		t.Fatalf("ams-1 targets = %s, want %s", got, want)
	}
	for _, tgt := range amsDoc.Targets {
		if tgt.InboundKind == store.InboundKindXray && tgt.Path == "inner:core-1" && tgt.Link != "vless://probe@10.0.0.7:443#probe-12" {
			t.Errorf("inner:core-1 link = %q, want the hop's own", tgt.Link)
		}
	}
	// fra-1 has no peer on the inner hop: no AWG target there.
	want = "awg:0/edge:edge-a,awg:0/edge:edge-b,xray:12/edge:edge-a,xray:12/edge:edge-b,xray:12/inner:core-1"
	if got := strings.Join(keysOf(mustCurrent(t, b, fra.Id)), ","); got != want {
		t.Fatalf("fra-1 targets = %s, want %s", got, want)
	}
}

// TestRevision_Chain checks what a wave of the chain does to config
// revisions (decision #61 п. 1–2, spec §5): switching the active edge
// changes nothing a mon-client is told, so no revision moves; a hop joining
// moves the revision of a mon-client that follows every hop, but not of one
// that names its hops; the chain appearing moves every revision (proxy
// leaves, the hops come in).
func TestRevision_Chain(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	all := approve(t, r, clk, "ams-1", nil)
	named := approve(t, r, clk, "fra-1", []string{"edge:edge-a"})
	ctx := context.Background()
	rebuild := func() (string, string) {
		t.Helper()
		if err := b.RebuildAll(ctx); err != nil {
			t.Fatalf("RebuildAll: %v", err)
		}
		return mustRevision(t, b, all.Id), mustRevision(t, b, named.Id)
	}

	flatAll, flatNamed := rebuild()

	mat.m = chainMaterial("edge-a")
	chainAll, chainNamed := rebuild()
	if chainAll == flatAll || chainNamed == flatNamed {
		t.Fatal("the chain appearing left a config revision unchanged")
	}

	mat.m = chainMaterial("edge-b")
	if a, n := rebuild(); a != chainAll || n != chainNamed {
		t.Fatalf("active edge switch moved config revisions: %s→%s, %s→%s", chainAll, a, chainNamed, n)
	}

	m := chainMaterial("edge-b")
	m.Revision = "rev-joined"
	m.Chain.Hops = append(m.Chain.Hops, panel.Hop{Name: "edge-c", Role: "edge", Host: "c.example.net", State: "joined"})
	m.Hops["edge:edge-c"] = []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://probe@c.example.net:443#probe-12"}}
	mat.m = m
	a, n := rebuild()
	if a == chainAll {
		t.Fatal("a hop joining left the revision of a mon-client on hops unchanged")
	}
	if n != chainNamed {
		t.Fatal("a hop joining moved the revision of a mon-client that names other hops")
	}
}

// TestExclusions_Chain is spec §5.1 for targets outside the document on a
// chained panel: a path the panel no longer serves (proxy, a hop that left)
// is Retired — removed without an event, never PAUSED — while a served hop
// the mon-client does not probe is path_removed, and a served hop the panel
// gave this mon-client no AWG peer on is no_probe_link.
func TestExclusions_Chain(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	mat.m = chainMaterial("edge-a")
	named := approve(t, r, clk, "fra-1", []string{store.PathDirect, "edge:edge-a"})
	all := approve(t, r, clk, "ams-1", nil)

	key := func(kind string, path string) TargetKey {
		id := 12
		if kind == store.InboundKindAwg {
			id = 0
		}
		return TargetKey{InboundKind: kind, InboundID: id, Path: path}
	}
	x, err := b.Exclusions(context.Background(), named.Id)
	if err != nil {
		t.Fatalf("Exclusions: %v", err)
	}
	for _, tc := range []struct {
		key     TargetKey
		retired bool
		reason  string
	}{
		{key(store.InboundKindXray, store.PathProxy), true, ""},
		{key(store.InboundKindXray, "edge:gone"), true, ""},
		{key(store.InboundKindXray, "edge:edge-b"), false, PausePathRemoved},
		{key(store.InboundKindAwg, "edge:edge-a"), false, PauseNoProbeLink},
	} {
		if got := x.Retired(tc.key); got != tc.retired {
			t.Errorf("Retired(%+v) = %v, want %v", tc.key, got, tc.retired)
		}
		if got := x.Reason(tc.key); got != tc.reason {
			t.Errorf("Reason(%+v) = %q, want %q", tc.key, got, tc.reason)
		}
	}

	// The AWG targets owed by the panel's state follow the expansion too.
	x, err = b.Exclusions(context.Background(), all.Id)
	if err != nil {
		t.Fatalf("Exclusions: %v", err)
	}
	var got []string
	for _, k := range x.Expected(store.InboundKindAwg) {
		got = append(got, k.Path)
	}
	if strings.Join(got, ",") != "direct,edge:edge-a,edge:edge-b,inner:core-1" {
		t.Fatalf("Expected(awg) = %v, want direct and every hop", got)
	}

	// Without material nothing is retired: that would be a guess.
	mat.ok = false
	x, _ = b.Exclusions(context.Background(), all.Id)
	if x.Retired(key(store.InboundKindXray, store.PathProxy)) {
		t.Fatal("a target was retired without material")
	}
}

// TestEdges_LaterEdgeJoins is decision #100: edges follows the chain — an
// edge that joins after approval is probed without editing the
// mon-client, and an inner hop never is.
func TestEdges_LaterEdgeJoins(t *testing.T) {
	m := chainMaterial("edge-a")
	m.Chain.Hops = append(m.Chain.Hops,
		panel.Hop{Name: "edge-c", Role: "edge", Host: "c.example.net", State: "joined"},
		panel.Hop{Name: "core-2", Role: "inner", Host: "10.0.0.8", State: "joined"},
		panel.Hop{Name: "edge-d", Role: "edge", Host: "d.example.net", State: "pending"})
	if got := strings.Join(ExpandPaths([]string{store.PathEdges}, m), ","); got != "edge:edge-a,edge:edge-b,edge:edge-c" {
		t.Fatalf("ExpandPaths(edges) = %s, want every probed edge", got)
	}
}

// TestMonitoredPaths is decision #100: a mon-client on edges holds targets
// on the whole chain — direct and every hop — so the ensure snapshot asks
// the panel for probe material on all of them; a vocabulary without edges
// holds exactly what it probes.
func TestMonitoredPaths(t *testing.T) {
	flat := sampleMaterial()
	chained := chainMaterial("edge-a")
	cases := []struct {
		name      string
		mat       panel.Material
		vocab     []string
		wantVocab string
		want      string
	}{
		{"edges on a chain", chained, []string{store.PathEdges}, "direct,hops", "direct,inner:core-1,edge:edge-a,edge:edge-b"},
		{"edges without a chain", flat, []string{store.PathEdges}, "direct,hops", "direct,proxy"},
		{"edges with an inner by name", chained, []string{store.PathEdges, "inner:core-1"}, "direct,hops,inner:core-1", "direct,inner:core-1,edge:edge-a,edge:edge-b"},
		{"explicit vocabulary", chained, []string{"edge:edge-b"}, "edge:edge-b", "edge:edge-b"},
		{"direct and hops", chained, []string{store.PathDirect, store.PathHops}, "direct,hops", "direct,inner:core-1,edge:edge-a,edge:edge-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(MonitoredVocab(tc.vocab), ","); got != tc.wantVocab {
				t.Errorf("MonitoredVocab(%v) = %s, want %s", tc.vocab, got, tc.wantVocab)
			}
			if got := strings.Join(MonitoredPaths(tc.vocab, tc.mat), ","); got != tc.want {
				t.Errorf("MonitoredPaths(%v) = %s, want %s", tc.vocab, got, tc.want)
			}
		})
	}
}

// TestExclusions_Edges is decision #100 for a mon-client on edges: its
// document holds only the edge targets, while direct and the inner hop are
// derived targets — held with their probe material, neither PAUSED nor
// retired — and an AWG target on a held path the panel gave it no peer for
// is still no_probe_link.
func TestExclusions_Edges(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	mat.m = chainMaterial("edge-a")
	ams := approve(t, r, clk, "ams-1", []string{store.PathEdges})
	fra := approve(t, r, clk, "fra-1", []string{store.PathEdges})
	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}

	want := "awg:0/edge:edge-a,awg:0/edge:edge-b,xray:12/edge:edge-a,xray:12/edge:edge-b"
	if got := strings.Join(keysOf(mustCurrent(t, b, ams.Id)), ","); got != want {
		t.Fatalf("ams-1 targets = %s, want the edges only: %s", got, want)
	}

	derived := func(id string) (Exclusions, string) {
		t.Helper()
		x, err := b.Exclusions(context.Background(), id)
		if err != nil {
			t.Fatalf("Exclusions(%s): %v", id, err)
		}
		var keys []TargetKey
		for k := range x.Derived {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b TargetKey) int {
			return strings.Compare(a.InboundKind+"/"+a.Path, b.InboundKind+"/"+b.Path)
		})
		var out []string
		for _, k := range keys {
			out = append(out, k.InboundKind+":"+strconv.Itoa(k.InboundID)+"/"+k.Path)
		}
		return x, strings.Join(out, ",")
	}

	x, got := derived(ams.Id)
	if got != "awg:0/direct,awg:0/inner:core-1,xray:12/direct,xray:12/inner:core-1" {
		t.Fatalf("ams-1 derived = %s, want direct and the inner hop of both kinds", got)
	}
	for k := range x.Derived {
		if r := x.Reason(k); r != "" || x.Retired(k) {
			t.Errorf("derived %+v: reason %q retired %v, want neither", k, r, x.Retired(k))
		}
	}

	// fra-1 has no AWG peer on the inner hop (chainMaterial): no AWG
	// derived target there, and it is no_probe_link.
	x, got = derived(fra.Id)
	if got != "awg:0/direct,xray:12/direct,xray:12/inner:core-1" {
		t.Fatalf("fra-1 derived = %s, want no AWG one on the inner hop", got)
	}
	awgInner := TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0, Path: "inner:core-1"}
	if r := x.Reason(awgInner); r != PauseNoProbeLink {
		t.Fatalf("fra-1 awg inner reason = %q, want no_probe_link", r)
	}
	var expected []string
	for _, k := range x.Expected(store.InboundKindAwg) {
		expected = append(expected, k.Path)
	}
	if strings.Join(expected, ",") != "direct,edge:edge-a,edge:edge-b,inner:core-1" {
		t.Fatalf("Expected(awg) = %v, want every held path", expected)
	}
}

// TestRebuild_SweepTargets is decision #100's sweep material: a mon-client
// on edges gets its held targets — direct and the inner hop, AWG only with
// its own peer — as sweepTargets next to the edge targets, so a diagnostic
// sweep can probe them without a new revision; a mon-client on direct and
// hops, which probes everything every cycle, gets none, and its document —
// revision included — is what it was before sweepTargets existed.
func TestRebuild_SweepTargets(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	mat.m = chainMaterial("edge-a")
	edges := approve(t, r, clk, "ams-1", []string{store.PathEdges})
	full := approve(t, r, clk, "fra-1", []string{store.PathDirect, store.PathHops})
	if err := b.RebuildAll(context.Background()); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}

	doc := mustCurrent(t, b, edges.Id)
	var sweep []string
	for _, ct := range doc.SweepTargets {
		sweep = append(sweep, ct.InboundKind+":"+strconv.Itoa(ct.InboundID)+"/"+ct.Path)
		if ct.Link == "" && ct.Conf == "" {
			t.Errorf("sweep target %s/%s carries no material", ct.InboundKind, ct.Path)
		}
	}
	if got := strings.Join(sweep, ","); got != "awg:0/direct,awg:0/inner:core-1,xray:12/direct,xray:12/inner:core-1" {
		t.Fatalf("ams-1 sweepTargets = %s", got)
	}
	if got := mustCurrent(t, b, full.Id); len(got.SweepTargets) != 0 {
		t.Fatalf("fra-1 sweepTargets = %v, want none", got.SweepTargets)
	}
	raw, _ := json.Marshal(mustCurrent(t, b, full.Id))
	if strings.Contains(string(raw), "sweepTargets") {
		t.Fatalf("a document without sweep targets names the field: %s", raw)
	}
}

// TestExclusions_SweepHosts is decision #100's host list: the hops a
// mon-client holds and the real server while it holds direct — the
// addresses its own material names, and no others.
func TestExclusions_SweepHosts(t *testing.T) {
	b, r, _, clk, mat := newTestBuilder(t)
	m := chainMaterial("edge-a")
	m.Host = "real.example.net"
	mat.m = m
	edges := approve(t, r, clk, "ams-1", []string{store.PathEdges})
	named := approve(t, r, clk, "fra-1", []string{"edge:edge-b"})

	render := func(id string) string {
		t.Helper()
		x, err := b.Exclusions(context.Background(), id)
		if err != nil {
			t.Fatalf("Exclusions: %v", err)
		}
		var out []string
		for _, h := range x.Hosts {
			out = append(out, h.Name+"="+h.Host)
		}
		return strings.Join(out, ",")
	}
	if got := render(edges.Id); got != "core-1=10.0.0.7,edge-a=a.example.net,edge-b=b.example.net,=real.example.net" {
		t.Fatalf("ams-1 hosts = %s", got)
	}
	if got := render(named.Id); got != "edge-b=b.example.net" {
		t.Fatalf("fra-1 hosts = %s, want only the hop it holds", got)
	}

	flat := sampleMaterial()
	flat.Host = "real.example.net"
	mat.m = flat
	if got := render(edges.Id); got != "proxy=front.example.net,=real.example.net" {
		t.Fatalf("ams-1 hosts without a chain = %s", got)
	}
}
