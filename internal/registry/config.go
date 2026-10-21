package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// revisionHexLen is how much of the SHA-256 a config revision keeps (spec
// §5, protocol §4.1: "первые 16 hex"). It is the same length the panel's own
// revision uses, which is not a coincidence: both are "did anything I care
// about change" fingerprints, not identifiers, and 64 bits is far more than
// enough to make an accidental collision between two consecutive documents
// impossible in practice.
const revisionHexLen = 16

// ErrNoConfig is Current's answer when this mon-client has no document yet
// and none can be built — which in practice means mon-server has never
// successfully read probe material from the panel (a fresh install, or one
// whose very first poll has not finished). internal/api turns it into
// `503 config_not_ready`: the mon-client should come back, not give up.
var ErrNoConfig = errors.New("registry: no config built yet")

// ProbeParams are the probe timings a mon-client runs its cycle by (spec
// §5, protocol §4.2), taken verbatim from the global settings an admin
// edits (spec §9.4). They are part of the config document — and therefore
// of the config revision — because changing one has to reach every
// mon-client; the state machine's thresholds deliberately are not, since
// only mon-server evaluates those.
type ProbeParams struct {
	IntervalMs         int64 `json:"intervalMs"`
	BudgetMs           int64 `json:"budgetMs"`
	ConnectMs          int64 `json:"connectMs"`
	TlsMs              int64 `json:"tlsMs"`
	HeadersMs          int64 `json:"headersMs"`
	StartJitterMs      int64 `json:"startJitterMs"`
	HeartbeatTimeoutMs int64 `json:"heartbeatTimeoutMs"`
}

// ConfigTarget is one (inbound, path) pair a mon-client probes (protocol
// §4.2). Link and Conf are the panel's own material copied verbatim — an
// xray subscription link for kind "xray", an AWG .conf for kind "awg" —
// because mon-server is deliberately transparent about protocols (protocol
// §4.2: knowing what a link means lives only in mon-client). Exactly one of
// them is ever set, which is why both are omitempty.
type ConfigTarget struct {
	InboundKind string `json:"inboundKind"`
	InboundID   int    `json:"inboundId"`
	Path        string `json:"path"`
	Protocol    string `json:"protocol"`
	Link        string `json:"link,omitempty"`
	Conf        string `json:"conf,omitempty"`
}

// ConfigDoc is the GET /v1/config document (protocol §4.2), field order and
// names exactly as the protocol shows them. It is what a mon-client turns
// into a running probe cycle, and the only thing about it mon-server ever
// compares is ConfigRevision.
type ConfigDoc struct {
	ConfigRevision string         `json:"configRevision"`
	MonClientID    string         `json:"monClientId"`
	ProbeURL       string         `json:"probeUrl"`
	Probe          ProbeParams    `json:"probe"`
	Targets        []ConfigTarget `json:"targets"`
}

// TargetKey names one target without describing it. It is comparable (so it
// works as a map key) precisely because the steps that consume it — the
// heartbeat's "is this result for a target I actually handed out" filter
// (step 6) and the tunnel probe's unknown-target flag (step 8) — need set
// membership, not the material.
type TargetKey struct {
	InboundKind string
	InboundID   int
	Path        string
}

// MaterialSource is where a ConfigBuilder gets the panel's probe material
// (spec §4 step 3). *panel.Poller satisfies it; the interface exists so the
// builder's own tests can drive it from a value instead of a live panel, and
// so registry never has to know how material is fetched.
type MaterialSource interface {
	Material() (panel.Material, bool)
}

// ConfigBuilder assembles and stores every mon-client's config document
// (spec §5). It holds no built state of its own: `client_configs` is the
// one place a document lives, so a restart, a second goroutine or the admin
// UI all see the same answer, and a rebuild is always a pure function of
// (material, mon-client row, settings, probeURL).
type ConfigBuilder struct {
	st       *store.Store
	clk      clock.Clock
	material MaterialSource
	probeURL string
}

// NewConfigBuilder wires a builder over st. probeURL is the address
// mon-clients send tunnel probes to (spec §5: "https://<publicIp>:<port>/v1/probe"),
// computed once by internal/app from bootstrap config — it cannot come from
// settings, because the listener it names is fixed at process start.
func NewConfigBuilder(st *store.Store, clk clock.Clock, material MaterialSource, probeURL string) *ConfigBuilder {
	return &ConfigBuilder{st: st, clk: clk, material: material, probeURL: probeURL}
}

// RebuildAll rebuilds every mon-client's document (panel.ConfigBuilder).
// The poller calls it on every accepted material change (spec §4 step 3),
// and step 10's Settings Save calls it when a probe parameter or realHost
// changes (spec §9.4). With no material yet it is a no-op rather than an
// error: a mon-server whose first poll has not landed simply has nothing to
// build from, and failing here would turn a normal cold start into a logged
// error every minute.
func (b *ConfigBuilder) RebuildAll(ctx context.Context) error {
	mat, ok := b.material.Material()
	if !ok {
		return nil
	}
	set, err := b.st.LoadSettings()
	if err != nil {
		return fmt.Errorf("registry: load settings: %w", err)
	}
	protocols, err := b.protocols(ctx)
	if err != nil {
		return err
	}

	var clients []store.MonClient
	if err := b.st.DB.WithContext(ctx).Order("id ASC").Find(&clients).Error; err != nil {
		return fmt.Errorf("registry: list mon-clients: %w", err)
	}
	for i := range clients {
		if _, err := b.buildAndStore(ctx, &clients[i], mat, set, protocols); err != nil {
			return err
		}
	}
	return nil
}

// Rebuild rebuilds one mon-client's document — the targeted counterpart of
// RebuildAll, for the two events that change exactly one document:
// Hooks.PathsChanged (an admin edited this client's paths) and
// Hooks.Approved (a new or replaced client that has no document yet). Like
// RebuildAll it is a no-op while there is no material.
func (b *ConfigBuilder) Rebuild(ctx context.Context, monClientID string) error {
	_, err := b.rebuild(ctx, monClientID)
	return err
}

// rebuild is Rebuild's body, returning the document it built (nil when
// there is no material) so Current can reuse it without a second read.
func (b *ConfigBuilder) rebuild(ctx context.Context, monClientID string) (*ConfigDoc, error) {
	mat, ok := b.material.Material()
	if !ok {
		return nil, nil
	}
	mc, err := b.client(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	set, err := b.st.LoadSettings()
	if err != nil {
		return nil, fmt.Errorf("registry: load settings: %w", err)
	}
	protocols, err := b.protocols(ctx)
	if err != nil {
		return nil, err
	}
	return b.buildAndStore(ctx, mc, mat, set, protocols)
}

// Current returns the mon-client's document for GET /v1/config (protocol
// §4.2). A mon-client approved between two panel revisions would otherwise
// have to wait for the next material change before it could configure
// itself at all, so a missing row is built on demand (and stored, so the
// revision it is told is the one every later comparison uses). ErrNoConfig
// means there is genuinely nothing to serve yet.
func (b *ConfigBuilder) Current(ctx context.Context, monClientID string) (*ConfigDoc, error) {
	row, err := b.row(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	if row != nil {
		var doc ConfigDoc
		if err := json.Unmarshal([]byte(row.Document), &doc); err != nil {
			return nil, fmt.Errorf("registry: decode stored config for %s: %w", monClientID, err)
		}
		return &doc, nil
	}

	doc, err := b.rebuild(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, ErrNoConfig
	}
	return doc, nil
}

// CurrentRevision returns just the stored configRevision — what a heartbeat
// answer carries (protocol §5.3) and what the admin UI compares a
// mon-client's applied revision against (spec §9.3). It never builds: an
// empty string plus a nil error means "nothing built yet", which for a
// heartbeat is not an error but simply "no config to converge on".
func (b *ConfigBuilder) CurrentRevision(ctx context.Context, monClientID string) (string, error) {
	row, err := b.row(ctx, monClientID)
	if err != nil || row == nil {
		return "", err
	}
	return row.Revision, nil
}

// TargetKeys is the set of targets this mon-client was actually handed, in
// the document's own order — the filter step 6 drops heartbeat results for
// targets nobody asked for by, and the check step 8 marks a tunnel probe as
// unknown by. nil (with a nil error) means no document exists yet.
func (b *ConfigBuilder) TargetKeys(ctx context.Context, monClientID string) ([]TargetKey, error) {
	doc, err := b.Current(ctx, monClientID)
	if errors.Is(err, ErrNoConfig) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	keys := make([]TargetKey, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		keys = append(keys, TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundID, Path: t.Path})
	}
	return keys, nil
}

// Reasons a target is PAUSED when it falls out of its mon-client's config
// for a reason that is not its inbound (decision #51 §3, contract §4.6). An
// inbound that is disabled or gone pauses its targets with config_disabled
// instead (spec §4 step 3, internal/state's SyncInbounds). A target whose
// path the panel no longer serves is not paused at all but removed
// (Exclusions.Retired, spec §5.1).
const (
	// PauseOverrideDisabled: a proxy-path target while the panel's host
	// override is off — there is no proxy front to probe through.
	PauseOverrideDisabled = "override_disabled"
	// PausePathRemoved: an administrator took the path off this mon-client,
	// while the panel still serves it.
	PausePathRemoved = "path_removed"
	// PauseNoProbeLink: the inbound is live, but the panel handed out no
	// probe link for it on this path.
	PauseNoProbeLink = "no_probe_link"
)

// Exclusions is what a ConfigBuilder knows about why a target is *not* in
// one mon-client's document: the paths the panel serves, the paths this
// mon-client probes of them, whether the override is on, and which inbounds
// the panel reports as enabled. It is a plain value so the state engine can
// take it before opening a heartbeat's transaction (the builder reads
// through its own handles) and ask it about every target row inside it —
// and so the engine's tests can write one down. The zero value knows
// nothing and names no reason.
type Exclusions struct {
	// Known is false until the panel's material has been read.
	Known bool
	// Served is the panel's probed path set (panel.Material.Served).
	Served map[string]bool
	// Paths are the paths this mon-client probes every cycle: its paths
	// vocabulary (spec §5.1's default applied) expanded by the material
	// (ExpandPaths).
	Paths map[string]bool
	// Monitored are the paths this mon-client holds targets on
	// (MonitoredPaths): Paths, plus — for a mon-client on edges — direct and
	// every hop of the chain, whose targets are not probed every cycle but
	// kept for the diagnostic sweep (decision #100).
	Monitored map[string]bool
	// Derived are this mon-client's targets on a Monitored path outside
	// Paths that the panel gave it probe material for (an AWG one only
	// with its own item, like the document's): targets it holds without
	// probing them every cycle. An inner one shows derived state, direct the
	// last sweep's result (CONTEXT.md: Derived state). They are neither in
	// the document nor PAUSED.
	Derived map[TargetKey]bool
	// Override is whether the panel's host override is on.
	Override bool
	// Inbounds maps an inbound (a TargetKey with an empty Path, the same
	// shape protocols uses) to its enable flag in panel_inbounds.
	Inbounds map[TargetKey]bool
}

// Retired reports whether key's path is one the panel no longer serves — a
// hop that was removed, renamed or left joined/legacy, or proxy once the
// chain has a probed hop (spec §5.1). Such a target is removed without an
// event rather than paused: the panel drops its own row for it. Nothing is
// retired while nothing is known.
func (x Exclusions) Retired(key TargetKey) bool {
	return x.Known && !x.Served[key.Path]
}

// Reason answers why key — a target that is not in the mon-client's
// document — is out: one of the Pause* reasons, or "" when it is not a
// config question at all (the inbound is disabled or gone, which
// SyncInbounds handles as config_disabled; the path is Retired; or nothing
// is known yet). It is only meaningful for keys that are not in the
// document; for one that is, the "default" answer below would be wrong.
func (x Exclusions) Reason(key TargetKey) string {
	if !x.Known || x.Retired(key) {
		return ""
	}
	if enabled := x.Inbounds[TargetKey{InboundKind: key.InboundKind, InboundID: key.InboundID}]; !enabled {
		return ""
	}
	switch {
	case x.Derived[key]:
		return ""
	case !x.Paths[key.Path] && !x.Monitored[key.Path]:
		return PausePathRemoved
	case key.Path == store.PathProxy && !x.Override:
		return PauseOverrideDisabled
	default:
		return PauseNoProbeLink
	}
}

// Expected lists the targets of one inbound kind this mon-client should be
// holding by the panel's own state, with or without an item in its
// document: every enabled inbound of that kind crossed with the paths the
// mon-client holds targets on (Paths and Monitored), proxy only while the
// override is on. The state engine asks it for
// AWG (decision #80 п. 10): a mon-client the panel gave no AWG probe peer
// (pool exhausted, or not ensured yet) never probes that target and so
// never creates its row, and without a row there is no PAUSED no_probe_link
// for the operator to see. Nothing is expected while nothing is known.
func (x Exclusions) Expected(kind string) []TargetKey {
	if !x.Known {
		return nil
	}
	paths := make(map[string]bool, len(x.Paths)+len(x.Monitored))
	for p := range x.Paths {
		paths[p] = true
	}
	for p := range x.Monitored {
		paths[p] = true
	}
	var out []TargetKey
	for in, enabled := range x.Inbounds {
		if !enabled || in.InboundKind != kind {
			continue
		}
		for path := range paths {
			if path == store.PathProxy && !x.Override {
				continue
			}
			out = append(out, TargetKey{InboundKind: in.InboundKind, InboundID: in.InboundID, Path: path})
		}
	}
	slices.SortFunc(out, func(a, b TargetKey) int {
		if a.InboundID != b.InboundID {
			return a.InboundID - b.InboundID
		}
		return strings.Compare(a.Path, b.Path)
	})
	return out
}

// Exclusions returns the facts Exclusions.Reason decides by, for one
// mon-client, from the same inputs a rebuild uses: the current material's
// served paths and override, the mon-client's paths expanded by it (with
// spec §5.1's default) and the enabled flags in panel_inbounds. With no material yet the answer is the
// zero value, which names no reason: pausing targets on a mon-server that
// has not heard from the panel since start-up would be a guess.
func (b *ConfigBuilder) Exclusions(ctx context.Context, monClientID string) (Exclusions, error) {
	mat, ok := b.material.Material()
	if !ok {
		return Exclusions{}, nil
	}
	mc, err := b.client(ctx, monClientID)
	if err != nil {
		return Exclusions{}, err
	}
	var rows []store.PanelInbound
	if err := b.st.DB.WithContext(ctx).Find(&rows).Error; err != nil {
		return Exclusions{}, fmt.Errorf("registry: read panel_inbounds: %w", err)
	}
	x := Exclusions{
		Known:     true,
		Served:    map[string]bool{},
		Paths:     map[string]bool{},
		Monitored: map[string]bool{},
		Derived:   map[TargetKey]bool{},
		Override:  mat.Override.Enabled,
		Inbounds:  make(map[TargetKey]bool, len(rows)),
	}
	for _, p := range mat.Served() {
		x.Served[p] = true
	}
	for _, p := range ExpandPaths(pathsOf(mc), mat) {
		x.Paths[p] = true
	}
	for _, p := range MonitoredPaths(pathsOf(mc), mat) {
		x.Monitored[p] = true
		if x.Paths[p] {
			continue
		}
		for _, item := range mat.Items(p) {
			if itemFor(item, mc.Id) {
				x.Derived[TargetKey{InboundKind: item.Kind, InboundID: item.InboundId, Path: p}] = true
			}
		}
	}
	for _, r := range rows {
		x.Inbounds[TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundId}] = r.Enable
	}
	return x, nil
}

// buildAndStore builds one document and upserts it into client_configs.
// The whole document is stored, not just its parts, because GET /v1/config
// must answer the exact bytes the revision was computed over even if the
// material has moved on since (a mon-client fetching a config it was just
// told about must not silently get a newer one under the old revision).
func (b *ConfigBuilder) buildAndStore(ctx context.Context, mc *store.MonClient, mat panel.Material, set *store.Settings, protocols map[TargetKey]string) (*ConfigDoc, error) {
	doc, err := b.build(mc, mat, set, protocols)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("registry: encode config for %s: %w", mc.Id, err)
	}
	row := store.ClientConfig{
		MonClientId: mc.Id,
		Revision:    doc.ConfigRevision,
		Document:    string(raw),
		BuiltAt:     clock.Ms(b.clk.Now()),
	}
	if err := b.st.DB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "mon_client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"revision", "document", "built_at"}),
	}).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("registry: store config for %s: %w", mc.Id, err)
	}
	return doc, nil
}

// build assembles the document itself: spec §5's targets rule (every path
// this mon-client's paths expand into, spec §5.1, crossed with that path's
// items — proxy only without a chain and while the panel's override is on,
// AWG items only the mon-client's own), the global probe parameters, the
// probe URL, and finally the revision over everything above.
func (b *ConfigBuilder) build(mc *store.MonClient, mat panel.Material, set *store.Settings, protocols map[TargetKey]string) (*ConfigDoc, error) {
	doc := &ConfigDoc{
		MonClientID: mc.Id,
		ProbeURL:    b.probeURL,
		Probe: ProbeParams{
			IntervalMs:         set.IntervalMs,
			BudgetMs:           set.BudgetMs,
			ConnectMs:          set.ConnectMs,
			TlsMs:              set.TlsMs,
			HeadersMs:          set.HeadersMs,
			StartJitterMs:      set.StartJitterMs,
			HeartbeatTimeoutMs: set.HeartbeatTimeoutMs,
		},
		Targets: []ConfigTarget{},
	}

	for _, path := range ExpandPaths(pathsOf(mc), mat) {
		for _, item := range mat.Items(path) {
			if !itemFor(item, mc.Id) {
				continue
			}
			key := TargetKey{InboundKind: item.Kind, InboundID: item.InboundId, Path: path}
			doc.Targets = append(doc.Targets, ConfigTarget{
				InboundKind: item.Kind,
				InboundID:   item.InboundId,
				Path:        path,
				Protocol:    protocolOf(key, protocols),
				// Verbatim (spec §5): the panel has already rendered the
				// right host for this path, so any rewriting here could
				// only introduce a way to get it wrong.
				Link: item.Link,
				Conf: item.Conf,
			})
		}
	}
	// A stable order is what makes the revision a function of content
	// rather than of the order two paths happened to be iterated in.
	slices.SortFunc(doc.Targets, func(x, y ConfigTarget) int {
		if c := strings.Compare(x.InboundKind, y.InboundKind); c != 0 {
			return c
		}
		if x.InboundID != y.InboundID {
			return x.InboundID - y.InboundID
		}
		return strings.Compare(x.Path, y.Path)
	})

	rev, err := revisionOf(doc)
	if err != nil {
		return nil, err
	}
	doc.ConfigRevision = rev
	return doc, nil
}

// DefaultPaths is spec §5.1's default paths vocabulary, given at approval
// (admin UI and ansible's auto-approval alike) and to a mon-client with
// none stored: edges — every edge front probed every cycle, the rest of the
// chain kept for the diagnostic sweep (decision #100). A mon-client stored
// with an explicit vocabulary keeps it.
func DefaultPaths() []string { return []string{store.PathEdges} }

// PathsOf is a mon-client's paths vocabulary with the default applied to a
// row that has none (or an unreadable column), so no caller has to decide
// what an empty list means.
func PathsOf(mc *store.MonClient) []string {
	paths := mc.PathsList()
	if len(paths) == 0 {
		return DefaultPaths()
	}
	return paths
}

// pathsOf is PathsOf, for the builder's own call sites.
func pathsOf(mc *store.MonClient) []string { return PathsOf(mc) }

// ExpandPaths turns a paths vocabulary into the paths a mon-client probes
// every cycle on the panel mat describes (spec §5.1): direct is direct;
// hops is every probed hop of the chain, including hops that joined after
// the mon-client was approved — or proxy on a panel without one; edges is
// every probed edge of the chain, active and standby, likewise including
// later ones — or proxy on a panel without one (decision #100); a hop by
// name is that hop while the panel probes it, and nothing otherwise. A
// path reached twice (hops and a name) is one path. The order is the
// vocabulary's, then the chain's; the document sorts its targets anyway.
func ExpandPaths(vocab []string, mat panel.Material) []string {
	served := make(map[string]bool)
	for _, p := range mat.Served() {
		served[p] = true
	}
	chained := mat.Chained()
	out := make([]string, 0, len(vocab))
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, v := range vocab {
		switch {
		case v == store.PathDirect:
			add(store.PathDirect)
		case v == store.PathHops && chained:
			for _, p := range mat.HopPaths() {
				add(p)
			}
		case v == store.PathEdges && chained:
			for _, h := range mat.Chain.ProbedHops() {
				if h.Role == store.HopRoleEdge {
					add(h.Path())
				}
			}
		case v == store.PathHops || v == store.PathEdges:
			add(store.PathProxy)
		case chained && store.IsHopPath(v) && served[v]:
			add(v)
		}
		// Anything else — a hop the panel does not probe, a hop by name on
		// a panel without a chain, or a word validatePaths would have
		// refused — expands into nothing.
	}
	return out
}

// MonitoredVocab is the paths vocabulary of every path a mon-client holds
// targets on: the vocabulary itself, with edges standing for the whole
// chain — direct and every hop (decision #100: probe accounts and AWG
// probe peers are kept for every path of the chain, so a diagnostic sweep
// has them). A vocabulary without edges is its own: it is probed in full
// every cycle. The ensure snapshot carries this (spec §4 step 2), in the
// words the panel expands: it knows direct, hops and names, not edges.
func MonitoredVocab(vocab []string) []string {
	if !slices.Contains(vocab, store.PathEdges) {
		return slices.Clone(vocab)
	}
	out := make([]string, 0, len(vocab)+1)
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, v := range vocab {
		if v == store.PathEdges {
			add(store.PathDirect)
			add(store.PathHops)
			continue
		}
		add(v)
	}
	return out
}

// MonitoredPaths are the paths a mon-client holds targets on, on the panel
// mat describes: ExpandPaths of MonitoredVocab. They include every path
// ExpandPaths gives; the ones it does not are probed only in a diagnostic
// sweep.
func MonitoredPaths(vocab []string, mat panel.Material) []string {
	return ExpandPaths(MonitoredVocab(vocab), mat)
}

// itemFor reports whether item belongs in monClientID's document (decision
// #80 п. 1, 7). An xray item is everybody's: its probe account is shared.
// An AWG item is a probe peer of one mon-client on this path, and only that
// mon-client may use it — two boxes on one WireGuard peer steal its
// endpoint and session from each other. An AWG item naming nobody is the
// shared peer of a contract-1 panel, which the poller never accepts
// material from; it is dropped here too rather than handed to everyone.
func itemFor(item panel.ProbeItem, monClientID string) bool {
	if item.Kind != store.InboundKindAwg {
		return true
	}
	return item.MonClientId == monClientID
}

// protocolOf answers the document's `protocol` field (protocol §4.2). AWG
// has no protocol of its own in the panel's inbound list, so it is spelled
// "awg" — the same string the kind uses — rather than left empty. An xray
// inbound mon-server has not yet seen in GET /state yields "", which is
// honest: the field is informational for the admin UI and mon-client's
// logs, and inventing a protocol would be worse than admitting we have not
// been told one.
func protocolOf(key TargetKey, protocols map[TargetKey]string) string {
	if key.InboundKind == store.InboundKindAwg {
		return store.InboundKindAwg
	}
	return protocols[TargetKey{InboundKind: key.InboundKind, InboundID: key.InboundID}]
}

// protocols reads panel_inbounds into the (kind, inboundId) → protocol map
// build joins on. It is read once per rebuild rather than per target so a
// registry with a hundred mon-clients does not issue a query per target.
func (b *ConfigBuilder) protocols(ctx context.Context) (map[TargetKey]string, error) {
	var rows []store.PanelInbound
	if err := b.st.DB.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("registry: read panel_inbounds: %w", err)
	}
	out := make(map[TargetKey]string, len(rows))
	for _, r := range rows {
		out[TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundId}] = r.Protocol
	}
	return out, nil
}

// client loads one mon-client row, mapping "no such row" onto the same
// ErrClientNotFound every other registry operation uses.
func (b *ConfigBuilder) client(ctx context.Context, id string) (*store.MonClient, error) {
	var mc store.MonClient
	if err := b.st.DB.WithContext(ctx).First(&mc, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return &mc, nil
}

// row loads the stored config for a mon-client, returning (nil, nil) when
// there is none — "not built yet" is an ordinary state here (see Current
// and CurrentRevision), not an error each caller should have to translate.
func (b *ConfigBuilder) row(ctx context.Context, monClientID string) (*store.ClientConfig, error) {
	var row store.ClientConfig
	err := b.st.DB.WithContext(ctx).First(&row, "mon_client_id = ?", monClientID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry: read client_configs for %s: %w", monClientID, err)
	}
	return &row, nil
}

// revisionOf computes spec §5's config revision: the first revisionHexLen
// hex characters of SHA-256 over the canonical JSON of the document without
// its own configRevision field. Hashing the document rather than its inputs
// is what makes the rule "the revision changes exactly when what the
// mon-client is told changes" true by construction — a panel revision that
// only renamed an inbound's remark produces byte-identical documents and
// therefore no re-fetch (protocol §4.3: a new revision costs an xray
// restart on every mon-client).
func revisionOf(doc *ConfigDoc) (string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("registry: encode config document: %w", err)
	}
	canon, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])[:revisionHexLen], nil
}

// canonicalJSON re-encodes a document as the revision's input: decoded into
// map[string]any and marshalled again, which Go's encoder emits with object
// keys sorted and no whitespace, and with the configRevision field dropped.
// Round-tripping through a map (rather than hashing the struct's own
// marshalling) is what makes the hash independent of Go struct field order
// and of any future field reordering in ConfigDoc, so two mon-servers on
// different builds agree on a revision for the same document.
func canonicalJSON(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("registry: canonicalise config document: %w", err)
	}
	delete(m, "configRevision")
	canon, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("registry: canonicalise config document: %w", err)
	}
	return canon, nil
}

// snapshotSource adapts the registry to panel.SnapshotSource — see
// (*Registry).SnapshotSource.
type snapshotSource struct{ r *Registry }

// Snapshot maps every registry row onto the panel's own mon-client shape
// (contract §4.3). A mon-client that has never heartbeated has a NULL
// last_heartbeat, which the contract spells as 0: the panel's UI reads
// State ("NEVER") for that case, and a pointer would only give it a second
// way to express the same thing.
func (s snapshotSource) Snapshot(ctx context.Context) ([]panel.MonClientSnapshot, error) {
	clients, err := s.r.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]panel.MonClientSnapshot, 0, len(clients))
	for _, mc := range clients {
		var last int64
		if mc.LastHeartbeat != nil {
			last = *mc.LastHeartbeat
		}
		out = append(out, panel.MonClientSnapshot{
			Id:            mc.Id,
			Name:          mc.Name,
			Region:        mc.Region,
			State:         mc.State,
			LastHeartbeat: last,
			// Every path the mon-client holds targets on, not only the
			// ones it probes every cycle: the panel keeps AWG probe peers
			// for exactly these (decision #100).
			Paths: MonitoredVocab(pathsOf(&mc)),
		})
	}
	return out, nil
}

// SaveUnallocated files the panel's answer to the snapshot (contract §4.3,
// spec §3): each mon-client's unallocated column becomes the pairs list
// names for it, in the panel's order, and [] for one it does not name — the
// panel lists every pair it could not serve on every ensure, so a
// mon-client missing from the list has none. A pair of a mon-client that is
// not in the registry (deleted since the snapshot) has nowhere to go and is
// dropped. One transaction, so the admin UI never sees half an answer.
func (s snapshotSource) SaveUnallocated(ctx context.Context, list []panel.Unallocated) error {
	byClient := make(map[string][]store.UnallocatedPeer)
	for _, u := range list {
		byClient[u.MonClientId] = append(byClient[u.MonClientId], store.UnallocatedPeer{Path: u.Path, Reason: u.Reason})
	}
	return s.r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var clients []store.MonClient
		if err := tx.Select("id", "unallocated").Find(&clients).Error; err != nil {
			return fmt.Errorf("registry: read unallocated: %w", err)
		}
		for i := range clients {
			var next store.MonClient
			next.SetUnallocated(byClient[clients[i].Id])
			if next.Unallocated == clients[i].Unallocated {
				continue
			}
			if err := tx.Model(&store.MonClient{}).Where("id = ?", clients[i].Id).
				Update("unallocated", next.Unallocated).Error; err != nil {
				return fmt.Errorf("registry: save unallocated of %s: %w", clients[i].Id, err)
			}
		}
		return nil
	})
}

// SnapshotSource returns the registry as the poller's snapshot source (spec
// §4 step 2). It is an adapter rather than a method on Registry itself
// because Registry.Snapshot returns store rows — what the admin UI and the
// rest of registry want — and only the poller needs them in the panel's
// wire shape.
func (r *Registry) SnapshotSource() panel.SnapshotSource {
	return snapshotSource{r: r}
}
