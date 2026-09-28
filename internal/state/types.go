// Package state owns everything mon-server concludes from what mon-clients
// report: the heartbeat handler's body (spec §7.1), the per-target state
// machine (§7.2), the mon-client ONLINE/OFFLINE rules (§7.3) and — from
// step 7 on — the 5-minute stats buckets (§7.4).
//
// Two invariants shape the package. First, mon-server's own clock is the
// authority for state: a cycle's `ts` is a mon-client's opinion and is only
// ever used to file statistics, never to decide whether a target is up (a
// box with a skewed clock must not be able to rewrite history). Second,
// every conclusion leaves exactly one durable trace — a row in `targets` or
// `mon_clients` plus an event in `events_outbox` — so a crash between
// "decided" and "told the panel" loses nothing (spec §4 step 4).
package state

import "github.com/SBKubric/3ax-ui-monitoring/internal/registry"

// HeartbeatRequest is the POST /v1/heartbeat body (protocol §5.3). Unknown
// fields are tolerated on decode, as the protocol requires of both sides;
// nullable numbers and strings are pointers so that "the mon-client did not
// measure this" (nil) stays distinguishable from a measured zero.
type HeartbeatRequest struct {
	MonClientID    string     `json:"monClientId"`
	ConfigRevision string     `json:"configRevision"`
	Client         ClientInfo `json:"client"`
	Cycles         []Cycle    `json:"cycles"`
}

// ClientInfo is the mon-client's self-report (protocol §5.3). ConfigError is
// a pointer because null ("my config is fine") and "" are the same thing on
// the wire but a mon-client may send either, and spec §7.1 step 2 turns the
// transition between "absent" and "present" into a Telegram message — so the
// distinction has to survive decoding.
//
// RejectedTargets are the targets of the applied revision the mon-client
// could not turn into probes (decision #53 п. 3); absent or empty means
// all of them are probed. Each goes PAUSED with reason config_error.
type ClientInfo struct {
	Version         string           `json:"version"`
	XrayVersion     string           `json:"xrayVersion"`
	UptimeMs        int64            `json:"uptimeMs"`
	ConfigError     *string          `json:"configError"`
	RejectedTargets []RejectedTarget `json:"rejectedTargets"`
}

// RejectedTarget is one entry of client.rejectedTargets (protocol §5.3):
// the target as "<kind>:<inboundId>:<path>" and why the mon-client rejected
// it (first line, ≤ 256 characters).
type RejectedTarget struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// Cycle is one probe round of a mon-client (protocol §5.1, §5.3). Seq is the
// mon-client's own monotonic counter and is what ackSeq acknowledges;
// Unverified marks a cycle whose heartbeat was never acknowledged, whose
// failures therefore say nothing (the probe's target is mon-server itself,
// so "mon-server was unreachable" and "the tunnel is down" look identical —
// protocol §5.3).
type Cycle struct {
	Seq        int64    `json:"seq"`
	Ts         int64    `json:"ts"`
	Unverified bool     `json:"unverified"`
	Results    []Result `json:"results"`
}

// Result is one target's probe outcome inside a cycle (protocol §5.3).
// Reason is the contract's diagnosis dictionary (spec §7.2) and is what a
// DOWN event carries; Detail is free text kept for mon-server's own logs
// and never forwarded to the panel.
type Result struct {
	InboundKind string  `json:"inboundKind"`
	InboundID   int     `json:"inboundId"`
	Path        string  `json:"path"`
	Ok          bool    `json:"ok"`
	ConnectMs   *int64  `json:"connectMs"`
	TlsMs       *int64  `json:"tlsMs"`
	TtfbMs      *int64  `json:"ttfbMs"`
	HandshakeMs *int64  `json:"handshakeMs"`
	EgressIp    *string `json:"egressIp"`
	Reason      *string `json:"reason"`
	Detail      *string `json:"detail"`
}

// HeartbeatResponse is the 200 body (protocol §5.3): the revision the
// mon-client should converge on, mon-server's receive time, and the highest
// cycle seq mon-server has now taken responsibility for — everything at or
// below AckSeq may be dropped from the mon-client's resend buffer.
type HeartbeatResponse struct {
	ConfigRevision string `json:"configRevision"`
	ServerTs       int64  `json:"serverTs"`
	AckSeq         int64  `json:"ackSeq"`
}

// Reason dictionary (spec §7.2). Every event this package enqueues carries
// one of these strings: the panel renders them, so an ad-hoc reason would
// show up as an unlabelled transition in somebody's Telegram chat.
const (
	// ReasonHTTPError is also the fallback for a failing result whose own
	// reason is null — a mon-client that reports a failure without saying
	// why still has to produce a DOWN event with something in the field.
	ReasonHTTPError = "http_error"
	// ReasonRecovered marks every transition into UP (spec §7.2: the "UP"
	// row), including the one out of FLAPPING.
	ReasonRecovered = "recovered"
	// ReasonFlapping marks the transition into FLAPPING.
	ReasonFlapping = "flapping"
	// ReasonConfigDisabled marks a target paused because its inbound was
	// disabled or dropped out of the panel's config (spec §4 step 3).
	ReasonConfigDisabled = "config_disabled"
	// ReasonConfigEnabled marks a paused target coming back to UNKNOWN
	// because its inbound is live again.
	ReasonConfigEnabled = "config_enabled"
	// ReasonMonClientOffline marks a target driven to UNKNOWN because the
	// mon-client that probes it stopped heartbeating (spec §7.3).
	ReasonMonClientOffline = "mon_client_offline"
	// ReasonMonClientDisabled marks the same thing for an administrator
	// disabling the mon-client (spec §6).
	ReasonMonClientDisabled = "mon_client_disabled"
	// ReasonHeartbeatMissed is the mon_client OFFLINE event's reason
	// (spec §7.3).
	ReasonHeartbeatMissed = "heartbeat_missed"
	// ReasonTokenRevoked is the mon_client OFFLINE event's reason when an
	// administrator revoked the token (decision #51 §2, contract §4.6).
	ReasonTokenRevoked = "token_revoked"
	// ReasonMonClientRevoked marks a target driven to UNKNOWN because its
	// mon-client's token was revoked.
	ReasonMonClientRevoked = "mon_client_revoked"

	// Config pauses (decision #51 §3, contract §4.6): a target PAUSED
	// because it fell out of its mon-client's config for a reason that is
	// not its inbound. The strings are registry's, which decides them.
	ReasonOverrideDisabled = registry.PauseOverrideDisabled
	ReasonPathRemoved      = registry.PausePathRemoved
	ReasonNoProbeLink      = registry.PauseNoProbeLink
	// ReasonConfigError marks a target PAUSED because its mon-client
	// rejected it when applying the revision — its link or .conf would not
	// parse, or the AWG device refused it (decision #53 п. 3). The
	// mon-client says so in client.rejectedTargets, not the builder.
	ReasonConfigError = "config_error"

	// ReasonResync marks a state resync (CONTEXT.md: State resync, decision
	// SBKubric/sane-3x-ui#151): not a transition but mon-server confirming a
	// target's current state, from = to, because the panel said it holds
	// none for it.
	ReasonResync = "resync"
)

// configPauseReasons are the PAUSED reasons a heartbeat owns: it sets them
// (reconcilePauses) and it alone releases them, when the target is back in
// the config. config_disabled is deliberately not here — SyncInbounds owns
// that one, and each side releasing only its own pauses is what keeps an
// inbound coming back from un-pausing a target whose path was removed.
// A new config pause is one line here plus its source in configPause.
var configPauseReasons = map[string]bool{
	ReasonOverrideDisabled: true,
	ReasonPathRemoved:      true,
	ReasonNoProbeLink:      true,
	ReasonConfigError:      true,
}

// Event kinds of the panel contract (§4.6). mon-server emits "target" and
// "mon_client" from this package; "panel" belongs to internal/panel.
const (
	eventKindTarget    = "target"
	eventKindMonClient = "mon_client"
)
