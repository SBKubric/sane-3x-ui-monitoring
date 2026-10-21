package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// maxClockSkew is how far a cycle's own `ts` may sit from mon-server's
// receive time before it is clamped to it (spec §7.1 step 1, protocol
// §5.3: "клампится к времени приёма при расхождении > 5 мин"). A
// mon-client with a broken clock would otherwise scatter its statistics
// across buckets hours away from when the probes actually ran; state is
// never derived from `ts` at all, so this only protects §7.4's buckets.
const maxClockSkew = 5 * time.Minute

// ConfigSource is the part of registry.ConfigBuilder the engine needs
// (brief §3.3): which targets this mon-client was actually handed, and
// which revision it should be converging on. It is an interface so the
// engine's tests can answer both from a literal instead of building real
// config documents.
type ConfigSource interface {
	TargetKeys(ctx context.Context, monClientID string) ([]registry.TargetKey, error)
	CurrentRevision(ctx context.Context, monClientID string) (string, error)
	// Exclusions says why a target is not in the mon-client's config, so
	// the heartbeat can PAUSE it with the right reason (decision #51 §3).
	Exclusions(ctx context.Context, monClientID string) (registry.Exclusions, error)
}

// StatsSink receives every cycle the engine accepted, for the 5-minute
// buckets of spec §7.4 (step 7 implements it; nil is allowed and simply
// drops statistics, which is what step 6 runs with). What it gets is
// already filtered: only cycles with seq above the last ack, `ts` clamped
// to mon-server's receive time, and results for targets that are not in
// this mon-client's config removed. Cycle.Unverified is preserved, because
// only the sink can apply §7.4's rule that an unverified failure counts as
// a gap rather than as nFail. The live cycle has already been applied to
// the state machine by the time Record is called.
//
// tx is the heartbeat's own transaction and every write the sink makes must
// go through it: the buckets are part of the same all-or-nothing mutation
// as the ack that lets the mon-client forget those cycles (see Heartbeat).
// A sink that reached for its own *store.Store handle instead would both
// escape that guarantee and deadlock — spec §3 keeps exactly one write
// connection, and the transaction is holding it.
type StatsSink interface {
	Record(ctx context.Context, tx *gorm.DB, monClientID string, cycles []Cycle) error
}

// Deps are the engine's collaborators. Store and Clock are required;
// Notifier, PanelDown, Configs and Stats all degrade gracefully so the
// engine can be built before the packages that provide them (and so its
// own tests can leave out what they are not exercising).
type Deps struct {
	Store    *store.Store
	Clock    clock.Clock
	Notifier tg.Notifier
	// PanelDown reports whether the panel is currently unreachable
	// (*panel.Poller.PanelDown). While it is true mon-server sends
	// transitions to Telegram itself and marks the events notified, so the
	// panel does not send them a second time when it comes back (spec
	// §4.1). A nil func means "the panel is fine".
	PanelDown func() bool
	Configs   ConfigSource
	Stats     StatsSink
}

// Engine is mon-server's whole opinion-forming machinery: it applies
// heartbeats (spec §7.1), runs the target state machine (§7.2), marks
// silent mon-clients OFFLINE (§7.3) and reacts to the panel's inbound list
// (§4 step 3). One process has exactly one, shared by every request
// goroutine; it keeps no mutable state of its own — every fact lives in
// the database — so that sharing needs no locking.
type Engine struct {
	st       *store.Store
	clk      clock.Clock
	notifier tg.Notifier

	panelDown func() bool
	configs   ConfigSource
	stats     StatsSink
}

// New wires an Engine, filling in the harmless defaults (a Nop notifier, a
// panel that is assumed up, no stats sink) so a partially built mon-server
// still answers heartbeats.
func New(d Deps) *Engine {
	e := &Engine{
		st:        d.Store,
		clk:       d.Clock,
		notifier:  d.Notifier,
		panelDown: d.PanelDown,
		configs:   d.Configs,
		stats:     d.Stats,
	}
	if e.clk == nil {
		e.clk = clock.Real{}
	}
	if e.notifier == nil {
		e.notifier = tg.Nop{}
	}
	if e.panelDown == nil {
		e.panelDown = func() bool { return false }
	}
	return e
}

// Heartbeat applies one POST /v1/heartbeat (spec §7.1) and answers the
// protocol's body. In order: mon-server's own receive time becomes the
// authority for everything state-related; the mon-client row is refreshed
// (ONLINE, versions, applied revision, configError); cycles at or below the
// last acknowledged seq are dropped as duplicates; the remaining cycles are
// clamped in time and stripped of results for targets this mon-client was
// never handed; the newest cycle that arrived with its own heartbeat drives
// the state machine, and all of them go to statistics.
//
// Only that one live cycle moves state: resent cycles describe a past
// mon-server has already judged, and replaying them would produce
// transitions backwards in time (protocol §5.3: "переходы задним числом не
// переигрываются"). Unverified cycles cannot be trusted for failures at
// all, since the probe's own destination is mon-server.
//
// Everything that mutates runs inside one transaction, and that is a
// correctness requirement, not tidiness: answering with ackSeq is a promise
// that the mon-client may drop those cycles from its resend buffer forever,
// and last_ack_seq records the promise. If the ack were written and the
// process then died before the live cycle reached the targets, the resent
// heartbeat would find seq ≤ last_ack_seq, discard the cycle as a duplicate
// and lose that transition — and its statistics — with nothing left to
// replay. Committing the mon-client row, the target rows, the outbox events
// and the stats buckets together makes the ack mean exactly what it says.
// Telegram is the one thing that cannot join a transaction, so the messages
// are collected while it runs and sent only after it commits: a rolled-back
// heartbeat must not have announced an outage that never happened.
func (e *Engine) Heartbeat(ctx context.Context, mc *store.MonClient, hb *HeartbeatRequest) (*HeartbeatResponse, error) {
	now := e.clk.Now()
	nowMs := clock.Ms(now)

	// Settings and the config document are read before the transaction
	// opens. Both go through handles of their own (*store.Store,
	// *registry.ConfigBuilder) that know nothing about tx, and spec §3's
	// single write connection means a read issued while the transaction
	// holds it would wait for a connection that only the transaction can
	// release.
	set, err := e.st.LoadSettings()
	if err != nil {
		return nil, fmt.Errorf("state: load settings: %w", err)
	}
	th := ThresholdsFrom(set)

	keys, err := e.targetKeys(ctx, mc.Id)
	if err != nil {
		return nil, err
	}
	excl, err := e.exclusions(ctx, mc.Id)
	if err != nil {
		return nil, err
	}

	var (
		ack    int64
		notify notices
	)
	err = e.st.DB.Transaction(func(tx *gorm.DB) error {
		tx = tx.WithContext(ctx)

		// The caller's row came out of authentication, which may have
		// happened against a copy that has since been overtaken by the 20s
		// offline job or by an admin action. Everything below branches on
		// the row's current state and last ack, so it is re-read here (and
		// handed back to the caller) rather than trusted: applying a
		// heartbeat against a stale OFFLINE/ONLINE would silently swallow
		// the ONLINE transition.
		var fresh store.MonClient
		if err := tx.First(&fresh, "id = ?", mc.Id).Error; err != nil {
			return fmt.Errorf("state: read mon-client %s: %w", mc.Id, err)
		}
		*mc = fresh

		// ackSeq is the highest seq mon-server has seen from this
		// mon-client, never a lower one: a resend that only carries old
		// cycles must still be told that everything up to the previous ack
		// is safely filed (protocol §5.3: "ackSeq подтверждает всё до него
		// включительно").
		ack = mc.LastAckSeq
		cycles := make([]Cycle, 0, len(hb.Cycles))
		for _, c := range hb.Cycles {
			if c.Seq > ack {
				ack = c.Seq
			}
			if c.Seq <= mc.LastAckSeq {
				continue
			}
			c.Ts = clampTs(c.Ts, nowMs)
			c.Results = keepKnown(c.Results, keys)
			cycles = append(cycles, c)
		}

		if err := e.applyClientInfo(tx, &notify, mc, hb, ack, now); err != nil {
			return err
		}

		// A PAUSED target whose key has now disappeared from the config is
		// retired here rather than the moment it vanished: spec §4 step 3
		// wants the deletion confirmed by a heartbeat that no longer
		// mentions it, so a target is never dropped while its mon-client
		// might still be probing it.
		if err := e.retirePaused(tx, mc.Id, keys); err != nil {
			return err
		}
		rejected := rejectedKeys(keys, hb.Client.RejectedTargets)
		if err := e.reconcilePauses(tx, mc.Id, keys, rejected, excl, clock.Ms(now)); err != nil {
			return err
		}

		if live := liveCycle(cycles); live != nil {
			if err := e.applyLive(tx, &notify, mc, *live, th, now); err != nil {
				return err
			}
		}

		if e.stats != nil && len(cycles) > 0 {
			// A failing sink rolls the heartbeat back rather than being
			// logged and shrugged off. These cycles are acknowledged in the
			// same commit, so a swallowed error would trade the statistics
			// for an ack that tells the mon-client to throw away the only
			// copy of them; failing instead makes it resend, which is
			// exactly what the resend buffer is for (protocol §5.3).
			if err := e.stats.Record(ctx, tx, mc.Id, cycles); err != nil {
				return fmt.Errorf("state: record statistics for %s: %w", mc.Id, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	e.flush(ctx, &notify)

	return &HeartbeatResponse{
		ConfigRevision: e.revisionFor(ctx, mc.Id, hb.ConfigRevision),
		ServerTs:       nowMs,
		AckSeq:         ack,
	}, nil
}

// MarkOffline is spec §7.3's job body, run every 20 s by internal/app: a
// mon-client that has been silent for longer than clientOfflineAfter whole
// heartbeat intervals (plus the heartbeat timeout, so a heartbeat that is
// merely slow does not count as missed) goes OFFLINE, and all of its
// targets fall back to UNKNOWN — mon-server has no information about them
// any more, and pretending the last known state still holds is how a
// monitoring system quietly stops monitoring.
//
// Only ONLINE mon-clients are considered: one that has never heartbeated is
// NEVER (spec §3), a state that says "waiting for the box to come up for
// the first time" and must not be overwritten with the alarm-worthy
// OFFLINE.
//
// Silence is counted from max(last_heartbeat, readyAt), readyAt being the
// moment this process's listener started completing TLS handshakes
// (ServerReady; decision #84). Heartbeats that went unanswered while
// mon-server itself was down are not the mon-client's fault: without this,
// the first sweep after a long enough restart saw the stale last_heartbeat,
// filed ONLINE → OFFLINE, and the mon-client's next heartbeat filed OFFLINE
// → ONLINE a minute later — two false Telegram lines and a needless UNKNOWN
// for every target. A mon-client that really died during the downtime still
// goes OFFLINE, clientOfflineAfter intervals after readyAt.
//
// Each mon-client is swept in its own transaction, so a crash between "the
// row says OFFLINE" and "its targets say UNKNOWN" cannot leave a mon-client
// that is offline while its targets still claim to be up — nothing would
// ever revisit that half-applied sweep, since the next pass only looks at
// ONLINE rows. One transaction per mon-client rather than one for the whole
// sweep: they are independent, and a single failure should not undo the
// mon-clients already handled.
func (e *Engine) MarkOffline(ctx context.Context, readyAt time.Time) error {
	set, err := e.st.LoadSettings()
	if err != nil {
		return fmt.Errorf("state: load settings: %w", err)
	}
	now := e.clk.Now()
	nowMs := clock.Ms(now)
	silence := int64(atLeast(set.ClientOfflineAfter, 1))*set.IntervalMs + set.HeartbeatTimeoutMs
	if nowMs-clock.Ms(readyAt) <= silence {
		// max(last_heartbeat, readyAt) is readyAt for every row that could
		// qualify, and the server has not been up long enough to have
		// seen that much silence from anyone.
		return nil
	}

	var clients []store.MonClient
	if err := e.st.DB.WithContext(ctx).
		Where("state = ? AND last_heartbeat IS NOT NULL AND ? - last_heartbeat > ?",
			store.MonClientOnline, nowMs, silence).
		Find(&clients).Error; err != nil {
		return fmt.Errorf("state: find silent mon-clients: %w", err)
	}

	for i := range clients {
		mc := &clients[i]
		var notify notices
		err := e.st.DB.Transaction(func(tx *gorm.DB) error {
			tx = tx.WithContext(ctx)
			if err := tx.Model(&store.MonClient{}).
				Where("id = ?", mc.Id).
				Updates(map[string]any{
					"state":             store.MonClientOffline,
					"missed_heartbeats": atLeast(set.ClientOfflineAfter, 1),
				}).Error; err != nil {
				return fmt.Errorf("state: mark %s offline: %w", mc.Id, err)
			}
			mc.State = store.MonClientOffline

			if err := e.emitMonClient(tx, &notify, mc, store.MonClientOnline, store.MonClientOffline, ReasonHeartbeatMissed, nowMs); err != nil {
				return err
			}
			return e.targetsToUnknown(tx, mc.Id, ReasonMonClientOffline, nowMs)
		})
		if err != nil {
			return err
		}
		e.flush(ctx, &notify)
	}
	return nil
}

// ServerReady is called once by internal/app, when the listener starts
// completing TLS handshakes (after the ACME certificate is in place), and
// returns that moment as serverReadyAt for every later MarkOffline. It also
// writes mon-server's only report of its own downtime (decision #84 §3): one
// log line with the age of the freshest last_heartbeat of any mon-client.
// There is no event and no Telegram — the panel's STALE and "monitoring
// back" already tell the operator — and no line at all on an install no
// mon-client has ever heartbeated to. A failed read only costs the line.
func (e *Engine) ServerReady(ctx context.Context) time.Time {
	now := e.clk.Now()

	var last *int64
	if err := e.st.DB.WithContext(ctx).Model(&store.MonClient{}).
		Select("MAX(last_heartbeat)").Scan(&last).Error; err != nil {
		slog.Warn("state: reading the last heartbeat at start failed", "err", err)
		return now
	}
	if last != nil {
		ago := now.Sub(clock.FromMs(*last)).Round(time.Second)
		slog.Info(fmt.Sprintf("started; last heartbeat seen %s ago", ago))
	}
	return now
}

// SyncInbounds reacts to the panel's inbound list on every poll
// (panel.InboundSync, spec §4 step 3): an inbound the panel disabled, and
// one that stopped being offered altogether, both park their targets in
// PAUSED — the state that means "not being probed, and that is correct",
// as opposed to UNKNOWN's "should be probed, no idea". An inbound that
// comes back releases its targets to UNKNOWN so the next result can decide
// afresh.
//
// The difference between the two is which one is allowed to be forgotten: a
// disabled inbound keeps its panel_inbounds row and its targets, since the
// panel is still telling mon-server about it. One that vanished loses that
// row here, which is exactly the "retiring" mark the next heartbeat reads
// to delete the target for good (see retirePaused).
//
// An empty list is ignored. The poller's own savePanelInbounds skips it too
// (a contract response with no inbounds is far more likely a panel that
// answered with nothing useful than an install that genuinely deleted every
// inbound), and the two must not disagree about what mon-server knows.
//
// The whole sync is one transaction. Forgetting a vanished inbound is the
// reason: that panel_inbounds row is the only record that its targets still
// need pausing, so a crash between deleting it and moving them would leave
// the targets stuck in whatever they last were, with nothing left to notice
// — the next poll no longer has the row to act on.
func (e *Engine) SyncInbounds(ctx context.Context, inbounds []panel.Inbound) error {
	if len(inbounds) == 0 {
		return nil
	}
	nowMs := clock.Ms(e.clk.Now())

	live := make(map[inboundKey]bool, len(inbounds))
	for _, in := range inbounds {
		live[inboundKey{InboundKind: in.Kind, InboundID: in.InboundId}] = in.Enable
	}

	// No notices are collected here: every transition this makes ends in
	// PAUSED or UNKNOWN, which spec §7.2 marks "Telegram нет".
	return e.st.DB.Transaction(func(tx *gorm.DB) error {
		tx = tx.WithContext(ctx)

		var known []store.PanelInbound
		if err := tx.Find(&known).Error; err != nil {
			return fmt.Errorf("state: read panel_inbounds: %w", err)
		}

		for _, row := range known {
			key := inboundKey{InboundKind: row.InboundKind, InboundID: row.InboundId}
			if _, ok := live[key]; ok {
				continue
			}
			if err := e.pauseTargets(tx, key, nowMs); err != nil {
				return err
			}
			if err := tx.
				Where("inbound_kind = ? AND inbound_id = ?", key.InboundKind, key.InboundID).
				Delete(&store.PanelInbound{}).Error; err != nil {
				return fmt.Errorf("state: forget vanished inbound %s: %w", key, err)
			}
		}

		for key, enabled := range live {
			var err error
			if enabled {
				err = e.resumeTargets(tx, key, nowMs)
			} else {
				err = e.pauseTargets(tx, key, nowMs)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// SyncPaths is panel.PathSync (spec §5.1, decision #61 п. 6, 9): served
// is the panel's probed path set of a newly accepted material, and every
// target of any mon-client on a path outside it — a hop that was removed,
// renamed or left joined/legacy, or proxy once the chain has a probed hop —
// is deleted. Silently: no event, no Telegram. The panel drops its own
// mon_targets rows for those paths in the same transaction as the registry
// change, so an event about them would only be refused or resurrect a row;
// and removing a hop is the operator's act, not an incident. A hop that
// comes back starts over with new UNKNOWN targets. An empty set is not an
// answer (a material always serves direct) and removes nothing.
func (e *Engine) SyncPaths(ctx context.Context, served []string) error {
	if len(served) == 0 {
		return nil
	}
	res := e.st.DB.WithContext(ctx).Where("path NOT IN ?", served).Delete(&store.Target{})
	if res.Error != nil {
		return fmt.Errorf("state: remove targets of paths the panel no longer serves: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		slog.Info("state: removed the targets of paths the panel no longer serves",
			"count", res.RowsAffected, "served", served)
	}
	return nil
}

// MonClientDisabled is registry Hooks.Disabled (spec §6): an administrator
// turning a mon-client off stops its probes, so its targets go UNKNOWN with
// reason mon_client_disabled rather than freezing on whatever they last
// were. PAUSED targets are left alone — they are paused by the panel's
// config, a fact that outlives this mon-client being switched off, and
// their retirement depends on staying PAUSED.
//
// The move runs in one transaction so the targets and the events that
// explain them commit together: the registry has already disabled the
// mon-client by the time this hook runs, and nothing revisits it, so a
// half-applied move would be permanent.
func (e *Engine) MonClientDisabled(ctx context.Context, monClientID string) error {
	nowMs := clock.Ms(e.clk.Now())
	return e.st.DB.Transaction(func(tx *gorm.DB) error {
		return e.targetsToUnknown(tx.WithContext(ctx), monClientID, ReasonMonClientDisabled, nowMs)
	})
}

// MonClientRevoked is registry Hooks.Revoked (decision #51 §2): a revoke
// is an OFFLINE like the timeout's, only with its own reasons — the
// mon_client event says token_revoked, the targets go UNKNOWN with
// mon_client_revoked, and Telegram follows the same PANEL_DOWN rule as
// MarkOffline's. PAUSED targets stay PAUSED, as for every liveness move
// (see targetsToUnknown).
//
// It runs inside the registry's revoke transaction, on mc as it stood
// before the revoke, so the from-state is real and the registry row, the
// targets and the events commit together; the registry writes the row's
// own state=OFFLINE. A mon-client that is OFFLINE already (the timeout got
// there first) makes no second mon_client transition — its targets are
// UNKNOWN already, which the move below then finds nothing to do about.
// The returned function sends the Telegram message and must only be run
// after the commit.
func (e *Engine) MonClientRevoked(ctx context.Context, tx *gorm.DB, mc store.MonClient) (func(context.Context), error) {
	tx = tx.WithContext(ctx)
	nowMs := clock.Ms(e.clk.Now())
	var notify notices
	if mc.State != store.MonClientOffline {
		if err := e.emitMonClient(tx, &notify, &mc, mc.State, store.MonClientOffline, ReasonTokenRevoked, nowMs); err != nil {
			return nil, err
		}
	}
	if err := e.targetsToUnknown(tx, mc.Id, ReasonMonClientRevoked, nowMs); err != nil {
		return nil, err
	}
	return func(ctx context.Context) { e.flush(ctx, &notify) }, nil
}

// Resync answers the panel's resync request (decision SBKubric/sane-3x-ui#151
// Q3, CONTEXT.md: State resync): for each named target it files an ordinary
// target event with from = to = the target's current state, reason resync
// and notified = true — the panel applies it silently, and there is no
// transition for Telegram to announce. A target mon-server does not know,
// or holds in UNKNOWN itself, gets nothing: there is no state to confirm.
//
// The event's ts is mon-server's time now, not the target's since. The
// panel keeps its rule that an event older than the target's since does
// not move it (contract §4.6), and a target it re-created from statistics
// has a since newer than the state mon-server has held all along — the
// very case resync exists for — so a ts of the old since would be ignored.
//
// Resync is Resyncer for Buckets; it does not throttle — that is the
// caller's per-stats-cycle concern.
func (e *Engine) Resync(ctx context.Context, refs []panel.TargetRef) error {
	nowMs := clock.Ms(e.clk.Now())
	return e.st.DB.Transaction(func(tx *gorm.DB) error {
		tx = tx.WithContext(ctx)
		for _, ref := range refs {
			var t store.Target
			err := tx.Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ?",
				ref.MonClientId, ref.InboundKind, ref.InboundId, ref.Path).Take(&t).Error
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				continue
			case err != nil:
				return fmt.Errorf("state: read target to resync: %w", err)
			}
			if t.State == store.TargetUnknown {
				continue
			}
			if _, err := e.enqueueTarget(tx, t, t.State, t.State, ReasonResync, nowMs, true); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------
// heartbeat internals
// ---------------------------------------------------------------------

// applyClientInfo is spec §7.1 step 2: the registry row catches up with
// what the mon-client just said about itself, in one write. The applied
// revision is stored verbatim — the admin UI compares it against the
// current one to show a mon-client that has not picked up its config yet
// (spec §9.3) — and last_ack_seq is persisted here so a crash right after
// answering cannot make mon-server re-apply cycles it already judged.
func (e *Engine) applyClientInfo(tx *gorm.DB, notify *notices, mc *store.MonClient, hb *HeartbeatRequest, ack int64, now time.Time) error {
	nowMs := clock.Ms(now)
	updates := map[string]any{
		"last_heartbeat":    nowMs,
		"missed_heartbeats": 0,
		"version":           hb.Client.Version,
		"xray_version":      hb.Client.XrayVersion,
		"applied_revision":  hb.ConfigRevision,
		"last_ack_seq":      ack,
	}
	// The rejections are stored as reported, whatever the config says of
	// them: they are the box's own account of its revision, for the admin
	// UI, like configError.
	var reportedRejected store.MonClient
	reportedRejected.SetRejected(rejectedList(hb.Client.RejectedTargets))
	updates["rejected_targets"] = reportedRejected.RejectedTargets

	from := mc.State
	online := from != store.MonClientOnline
	if online {
		updates["state"] = store.MonClientOnline
	}

	reported := ""
	if hb.Client.ConfigError != nil {
		reported = *hb.Client.ConfigError
	}
	// A configError that appears (or changes text) is always worth a
	// Telegram message, PANEL_DOWN or not — spec §8 lists it among the few
	// things mon-server says itself, because a mon-client that cannot load
	// its config is invisible to the panel's own alerting.
	appeared := reported != "" && reported != mc.ConfigError
	switch {
	case appeared:
		updates["config_error"] = reported
		updates["config_error_at"] = nowMs
	case reported == "" && mc.ConfigError != "":
		updates["config_error"] = ""
		updates["config_error_at"] = nil
	}

	if err := tx.Model(&store.MonClient{}).
		Where("id = ?", mc.Id).Updates(updates).Error; err != nil {
		return fmt.Errorf("state: update mon-client %s: %w", mc.Id, err)
	}

	mc.LastHeartbeat = &nowMs
	mc.MissedHeartbeats = 0
	mc.Version = hb.Client.Version
	mc.XrayVersion = hb.Client.XrayVersion
	mc.AppliedRevision = hb.ConfigRevision
	mc.LastAckSeq = ack
	mc.RejectedTargets = reportedRejected.RejectedTargets
	if online {
		mc.State = store.MonClientOnline
	}
	if appeared {
		mc.ConfigError = reported
		mc.ConfigErrorAt = &nowMs
		notify.add(store.EventPayload{}, tg.MsgConfigError(mc.Name, reported))
	} else if reported == "" {
		mc.ConfigError = ""
		mc.ConfigErrorAt = nil
	}

	if online {
		// A first heartbeat leaves every target UNKNOWN until a result
		// arrives (spec §7.3): being reachable says nothing about the
		// tunnels.
		return e.emitMonClient(tx, notify, mc, from, store.MonClientOnline, "", nowMs)
	}
	return nil
}

// applyLive runs the live cycle's results through the state machine, one
// target at a time. A result for a target that has no row yet creates it
// UNKNOWN first (spec §7.2: "новый target"), so the very first success
// still shows up as a real UNKNOWN → UP transition in the panel's feed
// rather than appearing out of nowhere already UP.
func (e *Engine) applyLive(tx *gorm.DB, notify *notices, mc *store.MonClient, cycle Cycle, th Thresholds, now time.Time) error {
	for _, res := range cycle.Results {
		target, err := e.targetRow(tx, mc.Id, res, clock.Ms(now))
		if err != nil {
			return err
		}
		next, transitions := Step(*target, th, OutcomeOf(res), now)
		if next.State == store.TargetPaused {
			// Step returned the row untouched: a PAUSED target's results
			// are stale by definition (spec §4 step 3), so there is
			// nothing to write.
			continue
		}
		if err := tx.Save(&next).Error; err != nil {
			return fmt.Errorf("state: save target %d: %w", next.Id, err)
		}
		for _, tr := range transitions {
			if err := e.emitTarget(tx, notify, mc, next, tr, clock.Ms(now)); err != nil {
				return err
			}
		}
	}
	return nil
}

// targetRow finds (or creates UNKNOWN) the row one result belongs to.
func (e *Engine) targetRow(tx *gorm.DB, monClientID string, res Result, nowMs int64) (*store.Target, error) {
	var t store.Target
	err := tx.
		Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ?",
			monClientID, res.InboundKind, res.InboundID, res.Path).
		First(&t).Error
	if err == nil {
		return &t, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("state: read target: %w", err)
	}

	t = store.Target{
		MonClientId: monClientID,
		InboundKind: res.InboundKind,
		InboundId:   res.InboundID,
		Path:        res.Path,
		State:       store.TargetUnknown,
		Since:       nowMs,
		Transitions: "[]",
	}
	if err := tx.Create(&t).Error; err != nil {
		return nil, fmt.Errorf("state: create target: %w", err)
	}
	return &t, nil
}

// retirePaused deletes the PAUSED targets of one mon-client whose inbound
// is gone for good — not in the config document any more, and no longer in
// panel_inbounds either (SyncInbounds drops that row when an inbound
// vanishes). A target whose inbound is merely disabled keeps its row and
// its history: the panel still knows about it and may enable it again.
func (e *Engine) retirePaused(tx *gorm.DB, monClientID string, keys map[registry.TargetKey]bool) error {
	var paused []store.Target
	if err := tx.
		Where("mon_client_id = ? AND state = ?", monClientID, store.TargetPaused).
		Find(&paused).Error; err != nil {
		return fmt.Errorf("state: read paused targets: %w", err)
	}
	if len(paused) == 0 {
		return nil
	}

	var known []store.PanelInbound
	if err := tx.Find(&known).Error; err != nil {
		return fmt.Errorf("state: read panel_inbounds: %w", err)
	}
	stillKnown := make(map[inboundKey]bool, len(known))
	for _, row := range known {
		stillKnown[inboundKey{InboundKind: row.InboundKind, InboundID: row.InboundId}] = true
	}

	for _, t := range paused {
		if keys[registry.TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path}] {
			continue
		}
		if stillKnown[inboundKey{InboundKind: t.InboundKind, InboundID: t.InboundId}] {
			continue
		}
		if err := tx.Delete(&store.Target{}, t.Id).Error; err != nil {
			return fmt.Errorf("state: retire target %d: %w", t.Id, err)
		}
	}
	return nil
}

// reconcilePauses is decision #51 §3, run on every heartbeat against the
// config the mon-client is on: a target of this mon-client that fell out of
// its config for a reason other than its inbound goes PAUSED with that
// reason (override_disabled, path_removed, no_probe_link) — the row and its
// history are kept — and one PAUSED for such a reason that is back in the
// config goes UNKNOWN (config_enabled), so the next result decides. A
// target out of the config because its inbound is disabled or gone gets no
// reason here; SyncInbounds pauses it (config_disabled) and releases it.
//
// A target in the config that the mon-client rejected (decision #53 п. 3)
// goes PAUSED with config_error the same way, and is released the same way
// once a heartbeat no longer lists it. A rejected target that has never
// produced a result has no row yet; it gets one here, UNKNOWN like any new
// target, so its pause reaches the panel as UNKNOWN → PAUSED. So does an
// AWG target of an enabled AWG server the panel gave this mon-client no
// probe peer for (decision #80 п. 10): it is PAUSED no_probe_link from the
// first heartbeat, and released like any no_probe_link once its item
// appears.
//
// A target whose path the panel no longer serves (excl.Retired, spec §5.1)
// is not paused but deleted, without an event — SyncPaths does the same for
// every mon-client when the material changes; doing it here as well catches
// a row a heartbeat racing that change re-created.
//
// It runs in the heartbeat for the same reason retirePaused does: this is
// where mon-server knows which config the mon-client was actually handed.
func (e *Engine) reconcilePauses(tx *gorm.DB, monClientID string, keys, rejected map[registry.TargetKey]bool, excl registry.Exclusions, nowMs int64) error {
	var all []store.Target
	if err := tx.Where("mon_client_id = ?", monClientID).Order("id").Find(&all).Error; err != nil {
		return fmt.Errorf("state: read targets of %s: %w", monClientID, err)
	}
	rows := all[:0]
	for _, t := range all {
		key := registry.TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path}
		if keys[key] || !excl.Retired(key) {
			rows = append(rows, t)
			continue
		}
		if err := tx.Delete(&store.Target{}, t.Id).Error; err != nil {
			return fmt.Errorf("state: remove target %d of a path the panel no longer serves: %w", t.Id, err)
		}
	}
	have := make(map[registry.TargetKey]bool, len(rows))
	for _, t := range rows {
		have[registry.TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path}] = true
	}
	// Targets that must be PAUSED but have never produced a result have no
	// row to pause yet: a rejected one (decision #53 п. 3), and an AWG
	// target the panel gave this mon-client no probe peer for (decision #80
	// п. 10). Each gets an UNKNOWN row here, which the loop below pauses.
	missing := sortedKeys(rejected)
	for _, key := range excl.Expected(store.InboundKindAwg) {
		if !keys[key] && !rejected[key] && excl.Reason(key) == ReasonNoProbeLink {
			missing = append(missing, key)
		}
	}
	for _, key := range missing {
		if have[key] {
			continue
		}
		t, err := e.targetRow(tx, monClientID, Result{InboundKind: key.InboundKind, InboundID: key.InboundID, Path: key.Path}, nowMs)
		if err != nil {
			return err
		}
		have[key] = true
		rows = append(rows, *t)
	}
	for _, t := range rows {
		key := registry.TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path}
		reason := configPause(key, keys, rejected, excl)
		var err error
		switch {
		case reason != "" && t.State != store.TargetPaused:
			err = e.moveRows(tx, []store.Target{t}, store.TargetPaused, reason, nowMs)
		case reason == "" && t.State == store.TargetPaused && configPauseReasons[t.Reason] && keys[key]:
			err = e.moveRows(tx, []store.Target{t}, store.TargetUnknown, ReasonConfigEnabled, nowMs)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// configPause is why one target must be PAUSED by its mon-client's config,
// or "" when it must not be (it is in the config and was not rejected, or
// it is out because of its inbound, or nothing is known yet). Every reason
// it can return is in configPauseReasons.
func configPause(key registry.TargetKey, keys, rejected map[registry.TargetKey]bool, excl registry.Exclusions) string {
	if rejected[key] {
		return ReasonConfigError
	}
	if keys[key] {
		return ""
	}
	return excl.Reason(key)
}

// rejectedKeys is the part of client.rejectedTargets that names targets of
// the mon-client's current config. The rest — a key of a revision the
// config has since moved past, or a string that is no target key at all —
// is dropped here like a result for an unknown target (spec §7.1 step 3):
// it could only create state nobody asked to be probed.
func rejectedKeys(keys map[registry.TargetKey]bool, rejected []RejectedTarget) map[registry.TargetKey]bool {
	if len(rejected) == 0 {
		return nil
	}
	named := make(map[string]bool, len(rejected))
	for _, r := range rejected {
		named[r.Target] = true
	}
	out := make(map[registry.TargetKey]bool)
	for k := range keys {
		if named[fmt.Sprintf("%s:%d:%s", k.InboundKind, k.InboundID, k.Path)] {
			out[k] = true
		}
	}
	return out
}

// sortedKeys orders a key set so rows created from it get ids — and their
// events outbox positions — in a stable order.
func sortedKeys(set map[registry.TargetKey]bool) []registry.TargetKey {
	out := make([]registry.TargetKey, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.InboundKind != b.InboundKind {
			return a.InboundKind < b.InboundKind
		}
		if a.InboundID != b.InboundID {
			return a.InboundID < b.InboundID
		}
		return a.Path < b.Path
	})
	return out
}

// rejectedList is the wire list in the store's shape.
func rejectedList(in []RejectedTarget) []store.RejectedTarget {
	out := make([]store.RejectedTarget, 0, len(in))
	for _, r := range in {
		out = append(out, store.RejectedTarget{Target: r.Target, Error: r.Error})
	}
	return out
}

// exclusions reads what the config builder knows about targets outside this
// mon-client's config. No builder wired means nothing is known, which names
// no reason and so pauses nothing.
func (e *Engine) exclusions(ctx context.Context, monClientID string) (registry.Exclusions, error) {
	if e.configs == nil {
		return registry.Exclusions{}, nil
	}
	x, err := e.configs.Exclusions(ctx, monClientID)
	if err != nil {
		return registry.Exclusions{}, fmt.Errorf("state: read config exclusions for %s: %w", monClientID, err)
	}
	return x, nil
}

// targetKeys is the set of targets this mon-client's config document names
// (spec §7.1 step 3: results for anything else are dropped). A mon-server
// with no config builder wired, or a mon-client with no document yet, has
// an empty set — which drops every result, the safe direction: a target
// nobody was told to probe must not create state.
func (e *Engine) targetKeys(ctx context.Context, monClientID string) (map[registry.TargetKey]bool, error) {
	if e.configs == nil {
		return nil, nil
	}
	keys, err := e.configs.TargetKeys(ctx, monClientID)
	if err != nil {
		return nil, fmt.Errorf("state: read config targets for %s: %w", monClientID, err)
	}
	set := make(map[registry.TargetKey]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set, nil
}

// revisionFor answers the heartbeat with the revision the mon-client should
// be on. A mon-server that has not built a document yet (no panel material)
// echoes what the mon-client sent, so the mon-client does not churn through
// GET /v1/config against a server that has nothing to give it.
func (e *Engine) revisionFor(ctx context.Context, monClientID, reported string) string {
	if e.configs == nil {
		return reported
	}
	rev, err := e.configs.CurrentRevision(ctx, monClientID)
	if err != nil {
		slog.Warn("state: reading the current config revision failed", "monClientId", monClientID, "err", err)
		return reported
	}
	if rev == "" {
		return reported
	}
	return rev
}

// ---------------------------------------------------------------------
// bulk target moves (PAUSED / UNKNOWN)
// ---------------------------------------------------------------------

// inboundKey names one panel inbound. Its fields are spelled like
// registry.TargetKey's so the two read the same at every call site that
// converts between them. It is comparable so both SyncInbounds and
// retirePaused can use it as a set key.
type inboundKey struct {
	InboundKind string
	InboundID   int
}

func (k inboundKey) String() string { return fmt.Sprintf("%s:%d", k.InboundKind, k.InboundID) }

// pauseTargets moves every non-PAUSED target of one inbound, across all
// mon-clients, into PAUSED with reason config_disabled (spec §4 step 3).
func (e *Engine) pauseTargets(tx *gorm.DB, key inboundKey, nowMs int64) error {
	return e.moveTargets(tx,
		tx.Where("inbound_kind = ? AND inbound_id = ? AND state <> ?", key.InboundKind, key.InboundID, store.TargetPaused),
		store.TargetPaused, ReasonConfigDisabled, nowMs)
}

// resumeTargets releases an inbound's PAUSED targets back to UNKNOWN with
// reason config_enabled: the config is live again, and the next result
// decides what they really are. Only the targets the inbound itself paused
// (config_disabled) are released: one paused because its mon-client's config
// left it out (reconcilePauses) is still out, whatever its inbound does.
func (e *Engine) resumeTargets(tx *gorm.DB, key inboundKey, nowMs int64) error {
	return e.moveTargets(tx,
		tx.Where("inbound_kind = ? AND inbound_id = ? AND state = ? AND reason = ?",
			key.InboundKind, key.InboundID, store.TargetPaused, ReasonConfigDisabled),
		store.TargetUnknown, ReasonConfigEnabled, nowMs)
}

// targetsToUnknown drives a mon-client's targets to UNKNOWN because the
// mon-client itself stopped being a source of truth (spec §6, §7.3).
//
// Deliberate deviation from spec §7.3's "все его targets → UNKNOWN": PAUSED
// targets are left where they are. PAUSED is not a statement about the
// tunnel but about the panel's config — the inbound is disabled or gone, so
// nothing should be probing that target at all (spec §4 step 3), and that
// stays true whatever the mon-client is doing. Moving it to UNKNOWN would
// claim mon-server merely lacks information, would make the admin UI show
// an inbound the operator switched off as an unknown, and would break
// retirement outright: retirePaused only deletes rows that are still
// PAUSED, so a vanished inbound's targets would linger forever. They are
// released by SyncInbounds when the inbound comes back, which is the only
// event that can legitimately end PAUSED.
func (e *Engine) targetsToUnknown(tx *gorm.DB, monClientID, reason string, nowMs int64) error {
	return e.moveTargets(tx,
		tx.Where("mon_client_id = ? AND state NOT IN ?", monClientID, []string{store.TargetUnknown, store.TargetPaused}),
		store.TargetUnknown, reason, nowMs)
}

// moveTargets is the one place a config- or liveness-driven bulk move
// happens: it reads the matching rows, writes the new state and files one
// event per row. It reads first and updates row by row rather than issuing
// a single UPDATE because every moved target owes the panel its own event
// with its own from-state (contract §4.6), which a bulk UPDATE cannot
// produce. None of these transitions ever reaches Telegram — they all end
// in UNKNOWN or PAUSED, which spec §7.2 marks "Telegram нет".
func (e *Engine) moveTargets(tx *gorm.DB, q *gorm.DB, to, reason string, nowMs int64) error {
	var rows []store.Target
	if err := q.Find(&rows).Error; err != nil {
		return fmt.Errorf("state: read targets to move to %s: %w", to, err)
	}
	return e.moveRows(tx, rows, to, reason, nowMs)
}

// moveRows is moveTargets' body for rows the caller has already read.
func (e *Engine) moveRows(tx *gorm.DB, rows []store.Target, to, reason string, nowMs int64) error {
	for _, t := range rows {
		from := t.State
		t.State = to
		t.Since = nowMs
		t.Reason = reason
		t.ConsecutiveOk = 0
		t.ConsecutiveFail = 0
		t.FlappingUntil = nil
		if err := tx.Save(&t).Error; err != nil {
			return fmt.Errorf("state: move target %d to %s: %w", t.Id, to, err)
		}
		if _, err := e.enqueueTarget(tx, t, from, to, reason, nowMs, false); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// events and Telegram
// ---------------------------------------------------------------------

// emitTarget publishes one state machine transition: the outbox row that
// tells the panel, plus — only while PANEL_DOWN, and never for the
// transitions spec §7.2 excludes — a Telegram message queued for after the
// transaction commits. The row records whether a message is going out, so
// the panel does not send a second one (contract §4.6's notified flag).
//
// notified is therefore written as an intent rather than as a fact: the
// send has not happened yet when the row is inserted, and it cannot, since
// a rolled-back transaction must not have announced anything. flush repairs
// the row if the send then fails, so a broken bot token still leaves the
// panel free to notify.
func (e *Engine) emitTarget(tx *gorm.DB, notify *notices, mc *store.MonClient, t store.Target, tr Transition, nowMs int64) error {
	text, worthy := e.telegramText(mc, t, tr, nowMs)
	ev, err := e.enqueueTarget(tx, t, tr.From, tr.To, tr.Reason, nowMs, worthy)
	if err != nil {
		return err
	}
	if worthy {
		notify.add(ev, text)
	}
	return nil
}

// telegramText picks the wording for one target transition and reports
// whether it is to be sent at all. Spec §7.2 words the "UP" row
// differently from the rest — «UP» с длительностью простоя (только из
// DOWN) — so a recovery out of DOWN carries how long the target was down,
// measured from Target.Since as it stood before this transition (see
// Transition.SinceMs) to mon-server's receive time.
//
// A target that went through FLAPPING therefore reports the length of its
// last uninterrupted DOWN spell, not of the whole unstable period: leaving
// FLAPPING restarts Since, and a FLAPPING target produces no UP/DOWN
// transitions at all (stepFlapping). That is the honest reading of
// "длительность простоя" for a flapping target — the alternative, dating
// the outage from the first failure of a target that has been up half the
// time since, would overstate it.
func (e *Engine) telegramText(mc *store.MonClient, t store.Target, tr Transition, nowMs int64) (string, bool) {
	if !e.telegramWorthy(tr) {
		return "", false
	}
	if tr.From == store.TargetDown && tr.To == store.TargetUp {
		return tg.MsgTargetRecovered(mc.Name, mc.Region, t.InboundKind, t.InboundId, t.Path,
			time.Duration(nowMs-tr.SinceMs)*time.Millisecond), true
	}
	return tg.MsgTargetTransition(
		mc.Name, mc.Region, t.InboundKind, t.InboundId, t.Path, tr.From, tr.To, tr.Reason), true
}

// telegramWorthy applies spec §7.2's exclusion: mon-server never announces
// a transition into or out of UNKNOWN/PAUSED (they are bookkeeping, not
// outages). The flips inside FLAPPING need no exclusion here: the machine
// does not produce them (one event on entering and one on leaving is the
// whole promise of that state). Everything else is announced only while
// the panel cannot do it itself (spec §4.1).
func (e *Engine) telegramWorthy(tr Transition) bool {
	if !e.panelDown() {
		return false
	}
	return isUpDown(tr.From) || isUpDown(tr.To) || tr.From == store.TargetFlapping || tr.To == store.TargetFlapping
}

// enqueueTarget writes one kind:"target" event into the outbox (contract
// §4.6). InboundID is taken by address because AWG's inbound id is a
// legitimate 0 that must survive the wire (see store.EventPayload).
func (e *Engine) enqueueTarget(tx *gorm.DB, t store.Target, from, to, reason string, nowMs int64, notified bool) (store.EventPayload, error) {
	inboundID := t.InboundId
	return e.enqueue(tx, store.EventPayload{
		Ts:          nowMs,
		Kind:        eventKindTarget,
		MonClientID: t.MonClientId,
		InboundKind: t.InboundKind,
		InboundID:   &inboundID,
		Path:        t.Path,
		From:        from,
		To:          to,
		Reason:      reason,
		Notified:    notified,
	})
}

// emitMonClient publishes a mon-client's own ONLINE/OFFLINE transition
// (spec §7.3), with the same PANEL_DOWN rule — and the same deferred send —
// as a target's.
//
// A first transition out of NEVER goes to the panel with an empty from
// (decision #50, spec §7.1): NEVER is the registry's own "never heard from"
// state, the panel's dictionary for mon_client is ONLINE/OFFLINE, and it
// rejects anything else. mon-server's own Telegram message keeps the real
// from — that text never reaches the panel.
func (e *Engine) emitMonClient(tx *gorm.DB, notify *notices, mc *store.MonClient, from, to, reason string, nowMs int64) error {
	wireFrom := from
	if wireFrom == store.MonClientNever {
		wireFrom = ""
	}
	worthy := e.panelDown()
	ev, err := e.enqueue(tx, store.EventPayload{
		Ts:          nowMs,
		Kind:        eventKindMonClient,
		MonClientID: mc.Id,
		From:        wireFrom,
		To:          to,
		Reason:      reason,
		Notified:    worthy,
	})
	if err != nil {
		return err
	}
	if worthy {
		notify.add(ev, tg.MsgMonClientTransition(mc.Name, mc.Region, from, to))
	}
	return nil
}

// enqueue stamps an event with a fresh UUID v7 (brief §1) and files it in
// the outbox — the only route to the panel — through the caller's
// transaction, and returns the stamped payload so the caller can tie a
// Telegram message to the row it backs.
func (e *Engine) enqueue(tx *gorm.DB, ev store.EventPayload) (store.EventPayload, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return ev, fmt.Errorf("state: event id: %w", err)
	}
	ev.ID = id.String()
	if err := store.EnqueueEventTx(tx, ev); err != nil {
		return ev, fmt.Errorf("state: enqueue event: %w", err)
	}
	return ev, nil
}

// ---------------------------------------------------------------------
// deferred Telegram
// ---------------------------------------------------------------------

// notice is one Telegram message a transaction decided to send, held until
// that transaction commits. Ev is the outbox event the message backs, or
// the zero value for a message that stands alone (a configError, spec §8,
// which is not a transition and files no event).
type notice struct {
	ev   store.EventPayload
	text string
}

// notices is one call's queue of them. It is a plain value passed down the
// call chain rather than a field on Engine: one Engine serves every request
// goroutine, and a shared queue would need a lock and would let one
// heartbeat send another's messages.
type notices struct{ list []notice }

func (n *notices) add(ev store.EventPayload, text string) {
	n.list = append(n.list, notice{ev: ev, text: text})
}

// flush sends what the committed transaction decided to say. Telegram is
// the one side effect that cannot be rolled back, so it happens here,
// after the commit: an announced outage that the database then forgot would
// be worse than a late message.
//
// A failed send is logged, never propagated — a broken bot token must not
// fail a heartbeat — and the event it backed is put back to notified=false
// so the panel sends it once it is reachable again (contract §4.6).
func (e *Engine) flush(ctx context.Context, n *notices) {
	for _, msg := range n.list {
		if err := e.notifier.Send(ctx, msg.text); err == nil {
			continue
		} else {
			slog.Warn("state: telegram send failed", "text", msg.text, "err", err)
		}
		if msg.ev.ID != "" {
			e.unnotify(ctx, msg.ev)
		}
	}
}

// unnotify clears the notified flag mon-server set optimistically on an
// outbox event whose Telegram message then failed, in both the column the
// outbox filters on and the payload the panel receives. Failing to do so is
// logged and otherwise ignored: the event itself is already safely filed,
// and the worst case is one transition the operator hears about only in the
// panel.
func (e *Engine) unnotify(ctx context.Context, ev store.EventPayload) {
	ev.Notified = false
	payload, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("state: re-marshalling an event failed", "eventId", ev.ID, "err", err)
		return
	}
	if err := e.st.DB.WithContext(ctx).Model(&store.EventOutbox{}).
		Where("id = ?", ev.ID).
		Updates(map[string]any{"notified": false, "payload": string(payload)}).Error; err != nil {
		slog.Warn("state: clearing the notified flag failed", "eventId", ev.ID, "err", err)
	}
}

// ---------------------------------------------------------------------
// small pure helpers
// ---------------------------------------------------------------------

// clampTs applies spec §7.1 step 1's clock-skew rule.
func clampTs(ts, nowMs int64) int64 {
	skew := ts - nowMs
	if skew < 0 {
		skew = -skew
	}
	if skew > maxClockSkew.Milliseconds() {
		return nowMs
	}
	return ts
}

// keepKnown drops results for targets that are not in this mon-client's
// config (spec §7.1 step 3). An empty key set drops everything.
func keepKnown(results []Result, keys map[registry.TargetKey]bool) []Result {
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if keys[registry.TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundID, Path: r.Path}] {
			out = append(out, r)
		}
	}
	return out
}

// liveCycle picks the cycle that drives the state machine: the
// highest-seq one that is not unverified (spec §7.1 step 3). nil means this
// heartbeat carried nothing but resends and unverified cycles, which are
// statistics only.
func liveCycle(cycles []Cycle) *Cycle {
	var live *Cycle
	for i := range cycles {
		c := &cycles[i]
		if c.Unverified {
			continue
		}
		if live == nil || c.Seq > live.Seq {
			live = c
		}
	}
	return live
}
