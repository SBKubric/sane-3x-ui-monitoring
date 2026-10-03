package admin

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// withMaterial gives the config builder something to build from, so a test
// can watch config revisions change. It is the shape one panel revision
// leaves behind (spec §4), not a poll cycle.
func (h *harness) withMaterial() {
	h.t.Helper()
	h.mat.mat = panel.Material{
		Revision:   "c4f1a9e2",
		Override:   panel.Override{Enabled: true, Host: "front.example.net"},
		ProbeSubID: "sub-1",
		Proxy:      []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://proxy-1"}},
		Direct:     []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://direct-1"}},
	}
	h.mat.have = true
}

// approveOne registers and approves one mon-client, returning its id.
func (h *harness) approveOne(code, hostname, ip, name, region string, paths []string) string {
	h.t.Helper()
	id := h.register(code, hostname, ip)
	w := h.do(http.MethodPost, "/admin/api/requests/"+id+"/approve", map[string]any{
		"mode": "new", "name": name, "region": region, "paths": paths,
	})
	if w.Code != http.StatusOK {
		h.t.Fatalf("approve %s: %s", name, w.Body.String())
	}
	return obj(h.t, w)["monClientId"].(string)
}

// TestClients_List shows what spec §9.3's table needs — and nothing about
// target state, which the panel's Monitoring page owns.
func TestClients_List(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops", "direct"})

	w := h.do(http.MethodGet, "/admin/api/clients", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	clients := obj(t, w)["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	row := clients[0].(map[string]any)
	if row["id"] != id || row["name"] != "Amsterdam #2" || row["state"] != store.MonClientNever || row["enabled"] != true {
		t.Fatalf("row = %+v", row)
	}
	if len(row["paths"].([]any)) != 2 {
		t.Fatalf("paths = %+v, want both", row["paths"])
	}
	rev, _ := row["serverRevision"].(string)
	if rev == "" {
		t.Fatal("serverRevision is empty although the config builder has material")
	}
	for _, forbidden := range []string{"targets", "targetState"} {
		if _, bad := row[forbidden]; bad {
			t.Fatalf("the mon-clients payload carries %q; spec §9.3 says target state is never shown here", forbidden)
		}
	}
}

// TestClients_UpdateChangesPathsAndRevision: Edit keeps the id, and a paths
// change gives the mon-client a new config revision (spec §9.3, §5).
func TestClients_UpdateChangesPathsAndRevision(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops", "direct"})

	before, err := h.configs.CurrentRevision(context.Background(), id)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}

	w := h.do(http.MethodPost, "/admin/api/clients/"+id, map[string]any{
		"name": "Amsterdam #2 (moved)", "region": "NL", "paths": []string{"hops"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	mc, err := h.reg.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if mc.Id != id {
		t.Fatalf("id changed to %q", mc.Id)
	}
	if mc.Name != "Amsterdam #2 (moved)" || len(mc.PathsList()) != 1 {
		t.Fatalf("mon-client after Edit = %+v", mc)
	}

	after, _ := h.configs.CurrentRevision(context.Background(), id)
	if after == before {
		t.Fatalf("config revision unchanged (%q) after the paths changed", after)
	}
}

// TestClients_EnabledSwitch flips spec §9.3's switch both ways.
func TestClients_EnabledSwitch(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/enabled", map[string]any{"enabled": false}); w.Code != http.StatusOK {
		t.Fatalf("disable: %s", w.Body.String())
	}
	mc, _ := h.reg.Get(context.Background(), id)
	if mc.Enabled {
		t.Fatal("mon-client is still enabled after the switch was turned off")
	}

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/enabled", map[string]any{"enabled": true}); w.Code != http.StatusOK {
		t.Fatalf("enable: %s", w.Body.String())
	}
	mc, _ = h.reg.Get(context.Background(), id)
	if !mc.Enabled {
		t.Fatal("mon-client is still disabled after the switch was turned on")
	}
}

// TestClients_Revoke clears the token but keeps the row, so a later
// registration request can be approved as its replacement (spec §6).
func TestClients_Revoke(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/revoke", nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %s", w.Body.String())
	}
	mc, err := h.reg.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("the row is gone after a revoke: %v", err)
	}
	if mc.TokenHash != "" {
		t.Fatal("token hash survived the revoke")
	}
	if mc.State != store.MonClientOffline {
		t.Fatalf("state = %q, want OFFLINE", mc.State)
	}

	o := obj(t, h.do(http.MethodGet, "/admin/api/clients", nil))
	row := o["clients"].([]any)[0].(map[string]any)
	if row["tokenRevoked"] != true {
		t.Fatalf("tokenRevoked = %v, want true", row["tokenRevoked"])
	}
}

// TestClients_Delete removes the row outright (spec §6).
func TestClients_Delete(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/delete", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %s", w.Body.String())
	}
	if clients, _ := h.reg.List(context.Background()); len(clients) != 0 {
		t.Fatalf("registry still holds %+v", clients)
	}
	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/delete", nil); w.Code != http.StatusNotFound {
		t.Fatalf("deleting twice: status %d, want 404", w.Code)
	}
}

// TestClients_ListShowsRejectedTargets: the targets a mon-client reported
// as rejected from its applied revision (protocol §5.3
// client.rejectedTargets), each with its error, are on the row the
// mon-clients page renders (spec §9.3), and a row with none has an empty
// list rather than null.
func TestClients_ListShowsRejectedTargets(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops"})

	rows := func() map[string]any {
		t.Helper()
		w := h.do(http.MethodGet, "/admin/api/clients", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
		return obj(t, w)["clients"].([]any)[0].(map[string]any)
	}
	if got, ok := rows()["rejectedTargets"].([]any); !ok || len(got) != 0 {
		t.Fatalf("rejectedTargets = %#v, want an empty list", rows()["rejectedTargets"])
	}

	var mc store.MonClient
	mc.SetRejected([]store.RejectedTarget{{Target: "awg:3:proxy", Error: `[Interface] has an unknown key "Foo"`}})
	if err := h.st.DB.Model(&store.MonClient{}).Where("id = ?", id).Update("rejected_targets", mc.RejectedTargets).Error; err != nil {
		t.Fatalf("store rejected targets: %v", err)
	}
	got, _ := rows()["rejectedTargets"].([]any)
	if len(got) != 1 {
		t.Fatalf("rejectedTargets = %#v, want one", got)
	}
	r := got[0].(map[string]any)
	if r["target"] != "awg:3:proxy" || r["error"] != `[Interface] has an unknown key "Foo"` {
		t.Fatalf("rejected target = %+v, want the stored one", r)
	}
}

// withChain is withMaterial on a chained panel (spec §5.1): an inner hop and
// two edges, edge-a active, plus a pending edge the panel does not probe.
func (h *harness) withChain() {
	h.t.Helper()
	h.withMaterial()
	active := "edge-a"
	h.mat.mat.Chain = &panel.Chain{Revision: 3, ActiveEdge: &active, Hops: []panel.Hop{
		{Name: "core-1", Role: "inner", Host: "10.0.0.7", State: "joined"},
		{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "joined"},
		{Name: "edge-b", Role: "edge", Host: "b.example.net", State: "legacy"},
	}}
	h.mat.mat.Hops = map[string][]panel.ProbeItem{
		"inner:core-1": {{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://core-1"}},
		"edge:edge-a":  {{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://edge-a"}},
		"edge:edge-b":  {{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://edge-b"}},
	}
}

// strs turns a decoded JSON array into strings.
func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestClients_ListChainAndProbes is spec §9.3 on a chained panel: the page
// gets the chain's probed hops for the paths picker and the path filter,
// and every mon-client the paths it probes now — the default edges
// expanded, a hop by name only while it is probed — which is what the
// filter matches on.
func TestClients_ListChainAndProbes(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withChain()
	all := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)
	named := h.approveOne("Q2V8NM", "vps-fra-1", "198.51.100.23", "Frankfurt #1", "DE", []string{"edge:edge-b", "edge:gone"})

	o := obj(t, h.do(http.MethodGet, "/admin/api/clients", nil))
	chain := o["chain"].(map[string]any)
	if chain["chained"] != true || chain["activeEdge"] != "edge-a" {
		t.Fatalf("chain = %+v, want chained with edge-a active", chain)
	}
	if got := strs(chain["served"]); len(got) != 4 || got[0] != "direct" || got[1] != "inner:core-1" {
		t.Fatalf("served = %v, want direct then the hops in chain order", got)
	}
	hops := chain["hops"].([]any)
	if len(hops) != 3 || hops[1].(map[string]any)["path"] != "edge:edge-a" || hops[1].(map[string]any)["active"] != true {
		t.Fatalf("hops = %+v, want three with edge:edge-a active", hops)
	}

	probes := map[string]string{}
	paths := map[string]string{}
	for _, c := range o["clients"].([]any) {
		row := c.(map[string]any)
		probes[row["id"].(string)] = fmt.Sprint(strs(row["probes"]))
		paths[row["id"].(string)] = fmt.Sprint(strs(row["paths"]))
	}
	if probes[all] != "[edge:edge-a edge:edge-b]" || paths[all] != "[edges]" {
		t.Fatalf("%s: paths %s probes %s, want the default expanded into every edge", all, paths[all], probes[all])
	}
	if probes[named] != "[edge:edge-b]" || paths[named] != "[edge:edge-b edge:gone]" {
		t.Fatalf("%s: paths %s probes %s, want only the probed hop it names", named, paths[named], probes[named])
	}
}

// TestClients_ListShowsUnallocated is spec §9.3: the pairs the panel's last
// ensure left without an AWG probe peer are listed per mon-client with the
// panel's reason, for the "no peer" tag and the Edit modal.
func TestClients_ListShowsUnallocated(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)
	var mc store.MonClient
	mc.SetUnallocated([]store.UnallocatedPeer{{Path: "inner:core-1", Reason: store.UnallocatedLimit}, {Path: "direct", Reason: store.UnallocatedPoolExhausted}})
	if err := h.st.DB.Model(&store.MonClient{}).Where("id = ?", id).Update("unallocated", mc.Unallocated).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	o := obj(t, h.do(http.MethodGet, "/admin/api/clients", nil))
	row := o["clients"].([]any)[0].(map[string]any)
	un := row["unallocated"].([]any)
	if len(un) != 2 || un[0].(map[string]any)["path"] != "inner:core-1" || un[0].(map[string]any)["reason"] != "limit" ||
		un[1].(map[string]any)["reason"] != "pool_exhausted" {
		t.Fatalf("unallocated = %+v", un)
	}
	// Without material nothing is known about the chain: an empty picker,
	// and no expansion to filter by.
	if chain := o["chain"].(map[string]any); chain["chained"] != false || len(chain["hops"].([]any)) != 0 {
		t.Fatalf("chain without material = %+v", chain)
	}
	if row["probes"] != nil {
		t.Fatalf("probes without material = %v, want null", row["probes"])
	}
}

// TestClients_UpdateHopPaths: Edit takes hops by name, and refuses proxy
// (it left the vocabulary, spec §5.1) with a message naming what is valid.
func TestClients_UpdateHopPaths(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withChain()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	w := h.do(http.MethodPost, "/admin/api/clients/"+id, map[string]any{
		"name": "Amsterdam #2", "region": "NL", "paths": []string{"direct", "inner:core-1"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update: %s", w.Body.String())
	}
	row := obj(t, h.do(http.MethodGet, "/admin/api/clients", nil))["clients"].([]any)[0].(map[string]any)
	if got := fmt.Sprint(strs(row["probes"])); got != "[direct inner:core-1]" {
		t.Fatalf("probes = %s", got)
	}

	w = h.do(http.MethodPost, "/admin/api/clients/"+id, map[string]any{
		"name": "Amsterdam #2", "region": "NL", "paths": []string{"proxy"},
	})
	if w.Code != http.StatusBadRequest || !strings.Contains(decode(t, w).Msg, "hops") {
		t.Fatalf("update with proxy: %d %s, want 400 naming the vocabulary", w.Code, w.Body.String())
	}
}

// TestRequests_ListCarriesChain: the Approve modal's paths picker offers
// the probed hops of the last GET /state (spec §9.2).
func TestRequests_ListCarriesChain(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withChain()
	o := obj(t, h.do(http.MethodGet, "/admin/api/requests", nil))
	chain := o["chain"].(map[string]any)
	if len(chain["hops"].([]any)) != 3 {
		t.Fatalf("chain = %+v, want the three probed hops", chain)
	}
}
