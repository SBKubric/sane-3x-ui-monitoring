package store

import "encoding/json"

// Inbound kinds a target or panel inbound points at, mirroring the panel's
// own MonInboundKind* constants (docs/spec/mon-server.md §3) so the two
// sides never disagree on spelling.
const (
	InboundKindXray = "xray"
	InboundKindAwg  = "awg"
)

// Paths a target is probed over (CONTEXT.md: Path). Besides these two a
// path names a chain hop, edge:<name> or inner:<name> (HopPath, spec §5.1).
const (
	PathDirect = "direct"
	PathProxy  = "proxy"
)

// Target states, the state machine's vocabulary (spec §7.2).
const (
	TargetUp       = "UP"
	TargetDown     = "DOWN"
	TargetFlapping = "FLAPPING"
	TargetUnknown  = "UNKNOWN"
	TargetPaused   = "PAUSED"
)

// mon-client states (spec §7.3).
const (
	MonClientOnline  = "ONLINE"
	MonClientOffline = "OFFLINE"
	MonClientNever   = "NEVER"
)

// Registration request lifecycle (spec §6).
const (
	RegistrationPending  = "pending"
	RegistrationApproved = "approved"
	RegistrationRejected = "rejected"
	RegistrationExpired  = "expired"
)

// Setting is one row of the settings key/value table (spec §9.4): every
// bootstrap-adjacent knob an admin can change without a restart lives here,
// not in internal/config. See Settings/LoadSettings/SaveSettings for the
// typed view most callers should use instead of touching this table by hand.
type Setting struct {
	Key   string `json:"key" gorm:"column:key;primaryKey;size:64"`
	Value string `json:"value" gorm:"column:value"`
}

// TableName pins the name explicitly, as every model here does (spec §3),
// so a future gorm default-naming change can never silently rename a table
// out from under a running install.
func (Setting) TableName() string { return "settings" }

// Admin is mon-server's single administrator account (spec §2, §3: "одна
// строка"). Id is always 1: `mon-server admin set` upserts this one row by
// primary key rather than tracking multiple accounts, since v1 has exactly
// one admin UI login. UpdatedAt is plain int64 ms UTC (spec §3), written
// explicitly by SetAdmin through Store.Clock — autoUpdateTime:false stops
// gorm from also stamping it with a bare time.Now() in Unix seconds on every
// Updates call, which would silently disagree with every other timestamp in
// the schema.
type Admin struct {
	Id           int    `json:"id" gorm:"column:id;primaryKey"`
	Username     string `json:"username" gorm:"column:username;not null"`
	PasswordHash string `json:"-" gorm:"column:password_hash;not null"`
	UpdatedAt    int64  `json:"updatedAt" gorm:"column:updated_at;not null;autoUpdateTime:false"`
}

func (Admin) TableName() string { return "admin" }

// adminRowId is the fixed primary key of the single Admin row (see Admin's
// doc comment).
const adminRowId = 1

// AdminSession is one admin UI login, keyed by the random value stored in the
// mon_session cookie (spec §9.1). ExpiresAt is checked on every request;
// idx_ms_admin_sessions_expires_at lets the hourly retention job (spec §3)
// find expired rows without a table scan. CreatedAt is plain int64 ms UTC
// (spec §3) supplied by the caller; autoCreateTime:false stops gorm from
// instead stamping it itself via a bare time.Now() in Unix seconds, which
// would bypass internal/clock and disagree with every other stored time.
type AdminSession struct {
	Id        string `json:"id" gorm:"column:id;primaryKey;size:64"`
	CreatedAt int64  `json:"createdAt" gorm:"column:created_at;not null;autoCreateTime:false"`
	ExpiresAt int64  `json:"expiresAt" gorm:"column:expires_at;not null;index:idx_ms_admin_sessions_expires_at"`
	Ip        string `json:"ip" gorm:"column:ip;size:64"`
}

func (AdminSession) TableName() string { return "admin_sessions" }

// LoginAttempt tracks failed admin logins per source IP (spec §9.1): five
// failures locks that IP out for fifteen minutes. Keyed on Ip itself rather
// than an autoincrement id because a lookup by IP is the only query this
// table ever serves.
type LoginAttempt struct {
	Ip          string `json:"ip" gorm:"column:ip;primaryKey;size:64"`
	Failures    int    `json:"failures" gorm:"column:failures;not null;default:0"`
	LockedUntil int64  `json:"lockedUntil" gorm:"column:locked_until;not null;default:0"`
}

func (LoginAttempt) TableName() string { return "login_attempts" }

// RegistrationRequest is a mon-client's unauthenticated bid to join the
// registry (spec §6, CONTEXT.md: Registration request). It lives five
// minutes as "pending" and is only ever turned into a MonClient by an
// administrator approving it in the admin UI — mon-server never
// self-approves a request. idx_ms_registration_requests_status_created backs
// both the pending-count badge (status='pending') and the hourly retention
// sweep (non-pending rows older than 7 days).
type RegistrationRequest struct {
	RequestId string `json:"requestId" gorm:"column:request_id;primaryKey;size:32"`

	PairingCode string `json:"pairingCode" gorm:"column:pairing_code;size:8;not null"`
	Hostname    string `json:"hostname" gorm:"column:hostname;not null"`
	Version     string `json:"version" gorm:"column:version"`
	PublicIp    string `json:"publicIp" gorm:"column:public_ip"`
	RemoteIp    string `json:"remoteIp" gorm:"column:remote_ip;not null"`

	// Status is one of the Registration* constants.
	Status string `json:"status" gorm:"column:status;size:16;not null;index:idx_ms_registration_requests_status_created,priority:1"`
	// CreatedAt is plain int64 ms UTC (spec §3), supplied by the caller;
	// autoCreateTime:false stops gorm from stamping it itself via a bare
	// time.Now() in Unix seconds instead of internal/clock.
	CreatedAt int64 `json:"createdAt" gorm:"column:created_at;not null;autoCreateTime:false;index:idx_ms_registration_requests_status_created,priority:2"`
	ExpiresAt int64 `json:"expiresAt" gorm:"column:expires_at;not null"`

	// ApprovedToken holds the plaintext client token from the moment of
	// approval until the mon-client's first GET /v1/register/<id> poll picks
	// it up (spec §6: "одноразовая выдача"), then is cleared. It is the only
	// place a token is ever stored in the clear; MonClient keeps only its hash.
	ApprovedToken string `json:"-" gorm:"column:approved_token"`
	// MonClientId is set once this request has been approved, pointing at the
	// MonClient it created or replaced.
	MonClientId string `json:"monClientId" gorm:"column:mon_client_id;size:64"`
}

func (RegistrationRequest) TableName() string { return "registration_requests" }

// MonClient is one entry of the mon-client registry (spec §3, §6). Paths is
// stored as a JSON array of the paths vocabulary (`["edges"]`, `["direct","hops"]`,
// spec §5.1); use PathsList/SetPaths
// rather than touching the column directly so every caller agrees on the
// encoding. TokenHash is a SHA-256 hex digest — the plaintext token exists
// only for the instant it is issued (see RegistrationRequest.ApprovedToken)
// and is never written to this table.
type MonClient struct {
	Id string `json:"id" gorm:"column:id;primaryKey;size:64"`

	Name   string `json:"name" gorm:"column:name;not null"`
	Region string `json:"region" gorm:"column:region"`
	// Paths is JSON-encoded; see PathsList/SetPaths.
	Paths string `json:"-" gorm:"column:paths;not null;default:'[]'"`

	// TokenHash is empty once revoked (spec §6: Revoke clears it but keeps the
	// row). Indexed, not unique: two revoked clients both have an empty hash.
	TokenHash string `json:"-" gorm:"column:token_hash;size:64;index:idx_ms_mon_clients_token_hash"`
	// Enabled clients are the ones offered to the panel in ProbeEnsure's
	// snapshot; indexed for that lookup (registry.Snapshot, step 4). No
	// gorm default: a bool column defaulting to true means gorm's create
	// callback silently rewrites an explicit false to true (Go's zero value
	// for bool is indistinguishable from "not set"), so a disabled client
	// could never actually be inserted disabled. Callers that want true set
	// it explicitly.
	Enabled bool `json:"enabled" gorm:"column:enabled;not null;index:idx_ms_mon_clients_enabled"`
	// State is one of the MonClient* constants.
	State         string `json:"state" gorm:"column:state;size:16;not null;default:NEVER"`
	LastHeartbeat *int64 `json:"lastHeartbeat" gorm:"column:last_heartbeat"`

	Version     string `json:"version" gorm:"column:version"`
	XrayVersion string `json:"xrayVersion" gorm:"column:xray_version"`

	// AppliedRevision is the configRevision this mon-client last acknowledged
	// via heartbeat; compared against client_configs.revision to show a
	// lagging mon-client in the admin UI (spec §9.3).
	AppliedRevision string `json:"appliedRevision" gorm:"column:applied_revision"`
	ConfigError     string `json:"configError" gorm:"column:config_error"`
	ConfigErrorAt   *int64 `json:"configErrorAt" gorm:"column:config_error_at"`
	// RejectedTargets is the JSON list of targets the mon-client's last
	// heartbeat reported as rejected from its applied revision (protocol
	// §5.3 client.rejectedTargets); see RejectedList/SetRejected.
	RejectedTargets string `json:"-" gorm:"column:rejected_targets;not null;default:'[]'"`
	// Unallocated is the JSON list of this mon-client's paths the panel's
	// last POST /probe/ensure gave no AWG probe peer, each with the panel's
	// reason (spec §4 step 2, contract §4.3); see UnallocatedList/
	// SetUnallocated. Their AWG targets are PAUSED no_probe_link, and this
	// is where the admin UI finds out why (spec §9.3).
	Unallocated string `json:"-" gorm:"column:unallocated;not null;default:'[]'"`

	RemoteIp         string `json:"remoteIp" gorm:"column:remote_ip"`
	ApprovedAt       int64  `json:"approvedAt" gorm:"column:approved_at"`
	MissedHeartbeats int    `json:"missedHeartbeats" gorm:"column:missed_heartbeats;not null;default:0"`

	// LastAckSeq is the highest probe-cycle seq this mon-client's
	// heartbeats have been acknowledged for (protocol §5.3: "ackSeq
	// подтверждает всё до него включительно"). It lives on the row rather
	// than in memory because it is what makes a resend idempotent: after a
	// restart, cycles the mon-client is still buffering must not be applied
	// to the state machine a second time (spec §7.1 step 3).
	LastAckSeq int64 `json:"lastAckSeq" gorm:"column:last_ack_seq;not null;default:0"`
}

func (MonClient) TableName() string { return "mon_clients" }

// RejectedTarget is one entry of MonClient.RejectedTargets: a target key
// as "<kind>:<inboundId>:<path>" and the mon-client's reason for rejecting
// it.
type RejectedTarget struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// RejectedList decodes RejectedTargets. An empty or malformed column is no
// rejections.
func (m *MonClient) RejectedList() []RejectedTarget {
	if m.RejectedTargets == "" {
		return nil
	}
	var out []RejectedTarget
	if err := json.Unmarshal([]byte(m.RejectedTargets), &out); err != nil {
		return nil
	}
	return out
}

// SetRejected encodes list into RejectedTargets, nil as "[]".
func (m *MonClient) SetRejected(list []RejectedTarget) {
	if list == nil {
		list = []RejectedTarget{}
	}
	b, err := json.Marshal(list)
	if err != nil {
		panic("store: marshal rejected targets: " + err.Error())
	}
	m.RejectedTargets = string(b)
}

// Reasons the panel gives for a pair without an AWG probe peer (contract
// §4.3 unallocated[].reason).
const (
	// UnallocatedPoolExhausted: the AWG server's address pool ran out.
	UnallocatedPoolExhausted = "pool_exhausted"
	// UnallocatedLimit: the pair is past the panel's monProbePeerLimit.
	UnallocatedLimit = "limit"
)

// UnallocatedPeer is one entry of MonClient.Unallocated: a path of this
// mon-client the panel gave no AWG probe peer, and the panel's reason.
type UnallocatedPeer struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// UnallocatedList decodes Unallocated. An empty or malformed column is no
// unallocated pairs.
func (m *MonClient) UnallocatedList() []UnallocatedPeer {
	if m.Unallocated == "" {
		return nil
	}
	var out []UnallocatedPeer
	if err := json.Unmarshal([]byte(m.Unallocated), &out); err != nil {
		return nil
	}
	return out
}

// SetUnallocated encodes list into Unallocated, nil as "[]".
func (m *MonClient) SetUnallocated(list []UnallocatedPeer) {
	if list == nil {
		list = []UnallocatedPeer{}
	}
	b, err := json.Marshal(list)
	if err != nil {
		panic("store: marshal unallocated: " + err.Error())
	}
	m.Unallocated = string(b)
}

// PathsList decodes Paths into a []string. A malformed or empty column
// (e.g. a row created before Paths was set) decodes to nil rather than
// panicking — callers that need a default should ask for one explicitly.
func (m *MonClient) PathsList() []string {
	if m.Paths == "" {
		return nil
	}
	var paths []string
	if err := json.Unmarshal([]byte(m.Paths), &paths); err != nil {
		return nil
	}
	return paths
}

// SetPaths encodes paths into Paths. A nil slice is stored as "[]", never as
// SQL NULL, so PathsList never has to distinguish "no paths" from "not yet
// set".
func (m *MonClient) SetPaths(paths []string) {
	if paths == nil {
		paths = []string{}
	}
	b, err := json.Marshal(paths)
	if err != nil {
		// Marshalling a []string cannot fail; a panic here would mean the
		// type changed under us.
		panic("store: marshal paths: " + err.Error())
	}
	m.Paths = string(b)
}

// Target is one (mon-client, inbound, path) probe and the state machine's
// current opinion of it (spec §7.2, CONTEXT.md: Target). The four-column
// unique key is what a heartbeat's probe results and the config builder both
// address it by; Id only exists because SQLite composite primary keys are
// awkward with gorm's AutoMigrate, not because anything else references it.
type Target struct {
	Id int `json:"id" gorm:"column:id;primaryKey;autoIncrement"`

	MonClientId string `json:"monClientId" gorm:"column:mon_client_id;not null;size:64;uniqueIndex:idx_ms_targets_key,priority:1"`
	InboundKind string `json:"inboundKind" gorm:"column:inbound_kind;not null;size:16;uniqueIndex:idx_ms_targets_key,priority:2"`
	InboundId   int    `json:"inboundId" gorm:"column:inbound_id;not null;uniqueIndex:idx_ms_targets_key,priority:3"`
	Path        string `json:"path" gorm:"column:path;not null;uniqueIndex:idx_ms_targets_key,priority:4"`

	// State is one of the Target* constants.
	State           string `json:"state" gorm:"column:state;size:16;not null;default:UNKNOWN"`
	Since           int64  `json:"since" gorm:"column:since;not null;default:0"`
	Reason          string `json:"reason" gorm:"column:reason"`
	ConsecutiveFail int    `json:"consecutiveFail" gorm:"column:consecutive_fail;not null;default:0"`
	ConsecutiveOk   int    `json:"consecutiveOk" gorm:"column:consecutive_ok;not null;default:0"`
	// Transitions is a JSON array of the ms timestamps of recent UP<->DOWN
	// transitions, the sliding window FLAPPING is detected from (spec §7.2).
	Transitions   string `json:"transitions" gorm:"column:transitions;not null;default:'[]'"`
	FlappingUntil *int64 `json:"flappingUntil" gorm:"column:flapping_until"`
	LastResultAt  *int64 `json:"lastResultAt" gorm:"column:last_result_at"`
}

func (Target) TableName() string { return "targets" }

// PanelInbound mirrors the panel's last-known inbound list (spec §3, filled
// by GET /state). It exists so mon-server can detect an inbound disappearing
// or being disabled between polls without holding the whole /state response
// in memory. Id exists for the same AutoMigrate reason as Target.Id.
type PanelInbound struct {
	Id int `json:"id" gorm:"column:id;primaryKey;autoIncrement"`

	InboundKind string `json:"inboundKind" gorm:"column:inbound_kind;not null;size:16;uniqueIndex:idx_ms_panel_inbounds_key,priority:1"`
	InboundId   int    `json:"inboundId" gorm:"column:inbound_id;not null;uniqueIndex:idx_ms_panel_inbounds_key,priority:2"`

	Protocol string `json:"protocol" gorm:"column:protocol"`
	Port     int    `json:"port" gorm:"column:port"`
	Remark   string `json:"remark" gorm:"column:remark"`
	// Enable has no gorm default for the same reason MonClient.Enabled does
	// not: a bool column defaulting to true makes an explicit false
	// unrepresentable via Create, since gorm cannot tell "false" from
	// "unset" on Go's zero value.
	Enable       bool   `json:"enable" gorm:"column:enable;not null"`
	SeenRevision string `json:"seenRevision" gorm:"column:seen_revision"`
}

func (PanelInbound) TableName() string { return "panel_inbounds" }

// ClientConfig is the config document built for one mon-client (spec §5),
// keyed by mon-client id since each one has at most one current document.
// Document is the protocol §4.2 JSON body verbatim; Revision is its
// configRevision.
type ClientConfig struct {
	MonClientId string `json:"monClientId" gorm:"column:mon_client_id;primaryKey;size:64"`
	Revision    string `json:"revision" gorm:"column:revision;not null"`
	Document    string `json:"document" gorm:"column:document;not null"`
	BuiltAt     int64  `json:"builtAt" gorm:"column:built_at;not null"`
}

func (ClientConfig) TableName() string { return "client_configs" }

// EventOutbox is the durable queue of events bound for the panel's POST
// /events (contract §4.6), and mon-server's own PANEL_DOWN buffer when the
// panel cannot be reached (spec §4.1). SentAt is nil until the panel
// confirms the batch; idx_ms_events_outbox_sent_at backs both the "still to
// send" query and the 7-day retention sweep.
type EventOutbox struct {
	Id string `json:"id" gorm:"column:id;primaryKey;size:36"`

	Ts       int64  `json:"ts" gorm:"column:ts;not null"`
	Payload  string `json:"payload" gorm:"column:payload;not null"`
	Notified bool   `json:"notified" gorm:"column:notified;not null;default:false"`
	SentAt   *int64 `json:"sentAt" gorm:"column:sent_at;index:idx_ms_events_outbox_sent_at"`

	// Dropped marks a row that left the queue without reaching the panel:
	// the panel rejected it (per element, or the whole batch with a 4xx),
	// and resending would be refused the same way. SentAt is stamped too,
	// so the row is out of every later flush and ages out with the
	// retention sweep; Dropped is what tells it apart from a delivered one.
	Dropped bool `json:"dropped" gorm:"column:dropped;not null;default:false"`
}

func (EventOutbox) TableName() string { return "events_outbox" }

// StatsBucket is one 5-minute aggregate of probe results for one target
// (spec §7.4), kept until POST /stats confirms it and for 7 days after in
// case the panel needs a resend. The five-column key matches the bucket a
// heartbeat's probe cycles fold into; idx_ms_stats_buckets_sent_at backs the
// flush query and the retention sweep, same as EventOutbox.
type StatsBucket struct {
	Id int `json:"id" gorm:"column:id;primaryKey;autoIncrement"`

	MonClientId string `json:"monClientId" gorm:"column:mon_client_id;not null;size:64;uniqueIndex:idx_ms_stats_buckets_key,priority:1"`
	InboundKind string `json:"inboundKind" gorm:"column:inbound_kind;not null;size:16;uniqueIndex:idx_ms_stats_buckets_key,priority:2"`
	InboundId   int    `json:"inboundId" gorm:"column:inbound_id;not null;uniqueIndex:idx_ms_stats_buckets_key,priority:3"`
	Path        string `json:"path" gorm:"column:path;not null;uniqueIndex:idx_ms_stats_buckets_key,priority:4"`
	BucketStart int64  `json:"bucketStart" gorm:"column:bucket_start;not null;uniqueIndex:idx_ms_stats_buckets_key,priority:5"`

	NOk   int `json:"nOk" gorm:"column:n_ok;not null;default:0"`
	NFail int `json:"nFail" gorm:"column:n_fail;not null;default:0"`

	LatMin      *int64 `json:"latMin" gorm:"column:lat_min"`
	LatAvg      *int64 `json:"latAvg" gorm:"column:lat_avg"`
	LatMax      *int64 `json:"latMax" gorm:"column:lat_max"`
	HandshakeMs *int64 `json:"handshakeMs" gorm:"column:handshake_ms"`

	// LatSum and LatN are the bookkeeping behind LatAvg, not part of the
	// wire form (contract §4.7 sends only min/avg/max). A bucket is built
	// incrementally — a heartbeat five minutes late adds cycles to a bucket
	// that already holds others (spec §7.4) — and an average cannot be
	// merged from an average alone: recomputing it from the stored mean
	// would need the sample count, and keeping only the mean would drift
	// with every rounding. Storing the exact sum and the number of samples
	// makes LatAvg = LatSum/LatN exact at every step, no matter how the
	// cycles arrive. LatN counts only successful probes that actually
	// carried a tlsMs, which is why it is not simply NOk.
	LatSum int64 `json:"-" gorm:"column:lat_sum;not null;default:0"`
	LatN   int   `json:"-" gorm:"column:lat_n;not null;default:0"`

	SentAt *int64 `json:"sentAt" gorm:"column:sent_at;index:idx_ms_stats_buckets_sent_at"`

	// Dropped is EventOutbox.Dropped for a bucket: the panel rejected it,
	// sent_at is stamped so it is not offered again, and new data for the
	// window clears both, the same as for a delivered bucket (spec §7.4).
	Dropped bool `json:"dropped" gorm:"column:dropped;not null;default:false"`
}

func (StatsBucket) TableName() string { return "stats_buckets" }

// ProbeSeen logs one tunnel probe arrival (spec §7.5) for diagnostics —
// "is this target's tunnel reaching mon-server at all" — separate from the
// state machine, which never derives state from these rows.
// idx_ms_probe_seen_seen_at backs the 24h retention sweep.
type ProbeSeen struct {
	Id int `json:"id" gorm:"column:id;primaryKey;autoIncrement"`

	MonClientId string `json:"monClientId" gorm:"column:mon_client_id;not null;size:64"`
	InboundKind string `json:"inboundKind" gorm:"column:inbound_kind;not null;size:16"`
	InboundId   int    `json:"inboundId" gorm:"column:inbound_id;not null"`
	Path        string `json:"path" gorm:"column:path;not null"`
	EgressIp    string `json:"egressIp" gorm:"column:egress_ip"`
	SeenAt      int64  `json:"seenAt" gorm:"column:seen_at;not null;index:idx_ms_probe_seen_seen_at"`
	// UnknownTarget marks a probe whose (inboundKind, inboundId, path) is
	// not among the targets this mon-client's current config document
	// names (spec §7.5). It never blocks the probe response — a mon-client
	// only needs to hear back "the tunnel reached mon-server" — it is only
	// a diagnostic flag for a config that has drifted out from under a
	// running mon-client.
	UnknownTarget bool `json:"unknownTarget" gorm:"column:unknown_target;not null;default:false"`
}

func (ProbeSeen) TableName() string { return "probe_seen" }
