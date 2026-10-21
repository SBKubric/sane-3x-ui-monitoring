// Package panel is mon-server's whole relationship with the real server's
// panel: the typed client for the contract under <webBasePath>mon/v1
// (docs/spec/monitoring-contract.md in the panel repo), the once-a-minute
// poll cycle (spec §4), the outbox flush and the PANEL_DOWN mode (spec
// §4.1). Nothing else in mon-server speaks HTTP to the panel — a package
// that needs panel material asks the Poller for it, and a package that
// needs the panel told about something enqueues an event in the outbox.
//
// The types below mirror the panel's own service types field-for-field,
// including their JSON tags and their Go spellings (InboundId, SubId), so
// that a change on either side shows up as a mismatch a reader can see
// rather than a silent rename. They deliberately do NOT carry validation
// tags: the contract (§1) requires mon-server to tolerate fields it does
// not know, so every response is decoded leniently and anything unexpected
// is ignored, never rejected.
package panel

import "github.com/SBKubric/3ax-ui-monitoring/internal/store"

// RequiredContract is the monitoring contract version mon-server speaks,
// matched exactly (decisions #80 п. 9, #61 п. 5): the panel and mon-server
// are updated together, and a panel on any other version builds no targets.
// Contract 2 is the per-peer probe set (an AWG probe peer per mon-client ×
// path); contract 3 adds the proxy chain — chain in GET /state and its
// revision, ?hop= on GET /probe/configs, paths in the ensure snapshot and
// unallocated reasons — without which the per-hop targets of spec §5.1
// cannot be built. An older panel would be probed without its hops, a
// newer one by rules this build does not know.
const RequiredContract = 3

// Inbound is one sanitised inbound from GET /state (contract §4.1): the
// panel never sends settings, stream settings or keys here, only what
// mon-server needs to name a target and show it to an operator. An AWG
// server arrives as Kind "awg" with InboundId 0, which is why InboundId is
// a plain int with no "absent" value — every inbound has one.
type Inbound struct {
	Kind      string `json:"kind"`
	InboundId int    `json:"inboundId"`
	Tag       string `json:"tag"`
	Remark    string `json:"remark"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Enable    bool   `json:"enable"`
}

// InboundRef names an inbound without describing it — the form POST
// /probe/ensure answers with in its "created" list (contract §4.3).
type InboundRef struct {
	Kind      string `json:"kind"`
	InboundId int    `json:"inboundId"`
}

// Override is the panel's host override (CONTEXT.md: the global setting that
// swaps the real server's address for the proxy front's in every config the
// panel hands out). Host is an empty string while Enabled is false, and the
// pair decides whether mon-server has a "proxy" path to probe at all
// (spec §4 step 3).
type Override struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
}

// Probe is the state of the panel's probe account set (contract §4.1).
// SubId is a pointer because it is null until the first POST /probe/ensure
// creates the set — "not created yet" and "created with an empty id" are
// different things, and only the first is legal.
type Probe struct {
	SubId       *string `json:"subId"`
	LastEnsured int64   `json:"lastEnsured"`
}

// Hop is one hop of the proxy chain in GET /state (contract 3 §4.1,
// CONTEXT.md: Hop): its name in the chain registry, its role — "edge" or
// "inner" — the address the panel renders its probe links with, and its
// registry state. The panel lists only joined and legacy hops, the ones
// that are probed.
//
// Next and NextHopCheck are the compatible contract-3 addition of decision
// #100: the name of the hop's next hop towards the panel ("" for the real
// server itself), and the hop's own last host reachability check of it.
// Both are optional — an older panel sends neither, and NextHopCheck is
// absent until the hop has reported once — and nil means "not said".
type Hop struct {
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	Host         string    `json:"host"`
	State        string    `json:"state"`
	Next         *string   `json:"next,omitempty"`
	NextHopCheck *HopCheck `json:"nextHopCheck,omitempty"`
}

// HopCheck is a hop's host reachability check of its next hop (decision
// #100, CONTEXT.md: Host reachability check): when it was measured, how
// many ICMP echoes were sent, the loss and the average round trip — nil
// when every echo was lost. It is not part of the panel's revision.
type HopCheck struct {
	At       int64  `json:"at"`
	Sent     int    `json:"sent"`
	LossPct  int    `json:"lossPct"`
	RttAvgMs *int64 `json:"rttAvgMs"`
}

// NextName is the hop's next hop: Next when the panel says it, otherwise
// what the chain's order implies (an older panel): the inner hops are
// listed from the panel outwards and the edges sit outside the last of
// them, so an inner hop's next is the inner one before it ("" — the real
// server — for the first), and an edge's is the last inner hop.
func (c *Chain) NextName(h Hop) string {
	if h.Next != nil {
		return *h.Next
	}
	var inner []string
	for _, o := range c.ProbedHops() {
		if o.Role == store.HopRoleInner {
			inner = append(inner, o.Name)
		}
	}
	if h.Role == store.HopRoleEdge {
		if len(inner) == 0 {
			return ""
		}
		return inner[len(inner)-1]
	}
	for i, name := range inner {
		if name == h.Name && i > 0 {
			return inner[i-1]
		}
	}
	return ""
}

// Path is the hop's path, edge:<name> or inner:<name> (spec §5.1).
func (h Hop) Path() string { return store.HopPath(h.Role, h.Name) }

// Hop registry states the panel probes (contract 3 §4.1); pending and
// draining hops are not in GET /state at all.
const (
	HopJoined = "joined"
	HopLegacy = "legacy"
)

// Chain is the panel's chain registry as GET /state reports it (contract 3
// §4.1). Revision is the registry's own counter, separate from the
// contract revision; mon-server does not track it, because the contract
// revision covers the active edge and the hops already (spec §4 step 3).
// ActiveEdge is nil when no edge is active, and may name an edge that is
// not among Hops (an active edge pending after reissueToken — the known gap
// of spec §5.1).
type Chain struct {
	Revision   int64   `json:"revision"`
	ActiveEdge *string `json:"activeEdge"`
	Hops       []Hop   `json:"hops"`
}

// ProbedHops is the hops mon-server probes, in the panel's order (inner
// ones from the panel outwards, then the edges by name): the joined and
// legacy ones whose role and name are by the grammar. The panel sends no
// others; anything else is skipped rather than turned into a path the
// admin UI and the panel would disagree on. A nil chain has none.
func (c *Chain) ProbedHops() []Hop {
	if c == nil {
		return nil
	}
	out := make([]Hop, 0, len(c.Hops))
	for _, h := range c.Hops {
		if (h.State != HopJoined && h.State != HopLegacy) || !store.IsHopPath(h.Path()) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// Active is the active edge's name, "" when there is none.
func (c *Chain) Active() string {
	if c == nil || c.ActiveEdge == nil {
		return ""
	}
	return *c.ActiveEdge
}

// State is the GET /state body (contract §4.1): the panel's whole
// configuration as far as monitoring is concerned, plus the Revision that
// tells mon-server whether anything it cares about has changed since the
// last poll. Chain is nil while the panel's chain registry is empty.
type State struct {
	Contract     int       `json:"contract"`
	PanelVersion string    `json:"panelVersion"`
	ServerTime   int64     `json:"serverTime"`
	Revision     string    `json:"revision"`
	Override     Override  `json:"override"`
	Chain        *Chain    `json:"chain,omitempty"`
	Probe        Probe     `json:"probe"`
	Inbounds     []Inbound `json:"inbounds"`
	Stale        struct {
		ThresholdMinutes int `json:"thresholdMinutes"`
	} `json:"stale"`
}

// MonClientSnapshot is one mon-client as the panel caches it for its own UI
// (contract §4.3, the panel's MonClient). The panel treats State as opaque:
// it never recomputes it, so this is purely mon-server reporting what it
// believes, and a full snapshot replaces the panel's cache on every ensure.
//
// Paths is the paths vocabulary of every path the mon-client holds
// targets on (contract 3, spec §5.1: direct, hops, explicit hops — a stored
// edges is sent as direct and hops, decision #100): the panel expands it by
// its probed path set and keeps an AWG probe peer only for those pairs.
type MonClientSnapshot struct {
	Id            string   `json:"id"`
	Name          string   `json:"name"`
	Region        string   `json:"region"`
	State         string   `json:"state"`
	LastHeartbeat int64    `json:"lastHeartbeat"`
	Paths         []string `json:"paths"`
}

// Unallocated is one pair POST /probe/ensure left without an AWG probe peer
// (contract 3 §4.3): the mon-client, the path and the panel's reason —
// store.UnallocatedPoolExhausted or store.UnallocatedLimit.
type Unallocated struct {
	MonClientId string `json:"monClientId"`
	Path        string `json:"path"`
	Reason      string `json:"reason"`
}

// EnsureResult is the POST /probe/ensure body (contract §4.3). Created is
// normally empty — ensure is idempotent and only does work the first time
// an inbound appears — and Present is the size of the probe set afterwards,
// which an operator can compare against the inbound count.
//
// Unallocated (contract 3, decisions #80 п. 10, #61 п. 12) lists the
// mon-client × path pairs the panel gave no AWG probe peer, with the
// reason: its address pool is exhausted, or the pair is past its
// monProbePeerLimit. The ensure still succeeds; those pairs simply get no
// AWG item from GET /probe/configs, and their AWG targets go PAUSED
// no_probe_link. The field may be absent, which means none.
type EnsureResult struct {
	SubId       string        `json:"subId"`
	Revision    string        `json:"revision"`
	LastEnsured int64         `json:"lastEnsured"`
	Created     []InboundRef  `json:"created"`
	Present     int           `json:"present"`
	Unallocated []Unallocated `json:"unallocated,omitempty"`
}

// ProbeItem is the material for one inbound on one path (contract §4.4):
// either an xray subscription Link or an AWG Filename plus Conf. mon-server
// passes whichever it got through to the mon-client verbatim (spec §5) —
// the panel has already applied the host override or the direct host, so
// rewriting anything here would only introduce a way to get it wrong.
//
// MonClientId is set on AWG items only (contract 2, decision #80 п. 7): the
// panel keeps one AWG probe peer per mon-client × path, so one path's
// answer carries one AWG item per mon-client, and each one belongs to the
// mon-client it names. xray items leave it empty: an xray probe account is
// shared by every mon-client.
type ProbeItem struct {
	Kind        string `json:"kind"`
	InboundId   int    `json:"inboundId"`
	MonClientId string `json:"monClientId,omitempty"`
	Link        string `json:"link,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Conf        string `json:"conf,omitempty"`
}

// ProbeConfigs is the GET /probe/configs body (contract §4.4). Revision is
// what makes the answer safe to use: the panel may have changed between the
// GET /state that reported a revision and this call, and an answer carrying
// a different revision is discarded rather than mixed with the state it does
// not belong to (spec §4 step 3).
type ProbeConfigs struct {
	Revision string      `json:"revision"`
	Path     string      `json:"path"`
	Items    []ProbeItem `json:"items"`
}

// StatPayload is one 5-minute aggregate for POST /stats (contract §4.7, the
// panel's MonStatIn). Every latency field is a pointer because the contract
// spells "no measurement" as JSON null, which a plain int64 would flatten
// into a very believable zero.
type StatPayload struct {
	MonClientId  string `json:"monClientId"`
	InboundKind  string `json:"inboundKind"`
	InboundId    int    `json:"inboundId"`
	Path         string `json:"path"`
	BucketStart  int64  `json:"bucketStart"`
	NOk          int    `json:"nOk"`
	NFail        int    `json:"nFail"`
	LatencyMinMs *int64 `json:"latencyMinMs"`
	LatencyAvgMs *int64 `json:"latencyAvgMs"`
	LatencyMaxMs *int64 `json:"latencyMaxMs"`
	HandshakeMs  *int64 `json:"handshakeMs"`
}

// Ignored is one record the panel accepted the batch but did not apply
// (contract §3: an event or stat for an inbound the panel has since
// deleted). It is reported, not retried — the panel holds nothing for an
// unknown inbound, so resending would only produce the same answer.
type Ignored struct {
	Id    string `json:"id,omitempty"`
	Key   string `json:"key,omitempty"`
	Error string `json:"error"`
}

// Rejected is one batch element the panel refused on its own (decision
// #50, contract §4.6/§4.7): the element failed validation, its neighbours
// in the batch did not, and the panel answered 200 for the rest. Index is
// the element's position in the batch as sent; Id is the event id and is
// only present on POST /events. A rejected element would be refused the
// same way on every resend, so the sender drops it rather than retrying.
type Rejected struct {
	Index int    `json:"index"`
	Id    string `json:"id,omitempty"`
	Error string `json:"error"`
}

// EventsResult is the POST /events body (contract §4.6). Duplicates is not
// an error: the outbox may legitimately resend a batch whose confirmation
// was lost, and the panel deduplicates by event id. Rejected lists the
// elements the panel refused; everything else in the batch is accepted.
//
// A panel from before per-element answers replies with a bare 200 and no
// body, which the client decodes as the zero value — nothing rejected, so
// the whole batch counts as accepted (decision #50).
type EventsResult struct {
	Accepted   int        `json:"accepted"`
	Duplicates int        `json:"duplicates"`
	Ignored    []Ignored  `json:"ignored"`
	Rejected   []Rejected `json:"rejected"`
}

// StatsResult is the POST /stats body (contract §4.7). There is no
// Duplicates counter because stats are upserted by key, so a resend
// overwrites rather than collides. Rejected and the empty-body rule are the
// same as EventsResult's.
//
// Resync is the panel asking for a state resync (CONTEXT.md: State resync,
// decision SBKubric/sane-3x-ui#151): the targets it holds no state for —
// in UNKNOWN and without a single event since the panel created them. It is
// an optional field (contract §1), absent from an older panel's answer and
// allowed to be omitted when empty, so nil means "nothing asked".
type StatsResult struct {
	Accepted int         `json:"accepted"`
	Ignored  []Ignored   `json:"ignored"`
	Rejected []Rejected  `json:"rejected"`
	Resync   []TargetRef `json:"resync,omitempty"`
}

// TargetRef names one target the way the panel keys it, with the same
// field names as a POST /stats element (contract §4.7): the form of
// StatsResult.Resync.
type TargetRef struct {
	MonClientId string `json:"monClientId"`
	InboundKind string `json:"inboundKind"`
	InboundId   int    `json:"inboundId"`
	Path        string `json:"path"`
}
