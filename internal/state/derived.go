package state

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// applyDerived keeps the targets a mon-client holds without probing them
// every cycle (registry.Exclusions.Derived, decision #100): it gives each
// one a row — UNKNOWN, like any new target, so the Monitoring page keeps
// its line — and moves an inner one to its derived state (CONTEXT.md:
// Derived state). An inner:* target is UP while at least one edge-path of
// the same inbound kind of this mon-client is UP, since every edge-path
// goes through that hop; with none UP it is left as it is, for the
// diagnostic sweep to settle. direct has no derived state: it is a
// separate network path, and outside a sweep it keeps the last sweep's
// result (UNKNOWN before the first).
//
// A move is filed as an ordinary target event with reason derived and
// notified = true — the panel shows it on the page and in the feed, and
// nobody sends Telegram: a hop the edge-paths already vouch for is not
// news. A PAUSED target stays PAUSED (its pause belongs to the config or
// the inbound), as does one already UP.
//
// It runs in the heartbeat, after the live cycle, so the edge-paths it
// reads are the ones that cycle just decided.
func (e *Engine) applyDerived(tx *gorm.DB, monClientID string, excl registry.Exclusions, nowMs int64) error {
	if !excl.Known || len(excl.Derived) == 0 {
		return nil
	}
	var rows []store.Target
	if err := tx.Where("mon_client_id = ?", monClientID).Find(&rows).Error; err != nil {
		return fmt.Errorf("state: read targets of %s: %w", monClientID, err)
	}
	edgeUp := map[string]bool{}
	have := make(map[registry.TargetKey]store.Target, len(rows))
	for _, t := range rows {
		if store.IsEdgePath(t.Path) && t.State == store.TargetUp {
			edgeUp[t.InboundKind] = true
		}
		have[registry.TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundId, Path: t.Path}] = t
	}

	for _, key := range sortedKeys(excl.Derived) {
		t, ok := have[key]
		if !ok {
			row, err := e.targetRow(tx, monClientID, Result{InboundKind: key.InboundKind, InboundID: key.InboundID, Path: key.Path}, nowMs)
			if err != nil {
				return err
			}
			t = *row
		}
		if !store.IsInnerPath(key.Path) || !edgeUp[key.InboundKind] {
			continue
		}
		if t.State == store.TargetUp || t.State == store.TargetPaused {
			continue
		}
		if err := e.moveQuiet(tx, t, store.TargetUp, ReasonDerived, "", nowMs); err != nil {
			return err
		}
	}
	return nil
}

// moveQuiet moves one target to a state that was not decided by its own
// probe results — derived state, and the diagnostic sweep's verdict — and
// files the event with notified = true: the panel records it, nobody sends
// Telegram for it (decision #100). The row keeps rowReason — a DOWN
// target's diagnosis, nothing for UP. The streak counters and the FLAPPING
// hold restart with it, as for every move the machine did not make itself.
func (e *Engine) moveQuiet(tx *gorm.DB, t store.Target, to, reason, rowReason string, nowMs int64) error {
	from := t.State
	t.State = to
	t.Since = nowMs
	t.Reason = rowReason
	t.ConsecutiveOk = 0
	t.ConsecutiveFail = 0
	t.FlappingUntil = nil
	if err := tx.Save(&t).Error; err != nil {
		return fmt.Errorf("state: move target %d to %s: %w", t.Id, to, err)
	}
	_, err := e.enqueueTarget(tx, t, from, to, reason, nowMs, true)
	return err
}
