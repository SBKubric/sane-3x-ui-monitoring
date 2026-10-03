package store

import (
	"encoding/json"

	"gorm.io/gorm"
)

// EventPayload is the contract's event body (docs/spec/mon-protocol.md and
// the panel contract §4.6), the exact JSON EnqueueEvent stores in
// events_outbox.payload and POST /events later sends verbatim. InboundID is
// a pointer, not a plain int, because AWG's inbound id is 0 and
// `omitempty` on a bare int would drop that legitimate zero from the wire —
// a pointer round-trips "no inbound" (nil) and "inbound 0" (AWG)
// differently.
type EventPayload struct {
	ID   string `json:"id"`
	Ts   int64  `json:"ts"`
	Kind string `json:"kind"` // "target" | "mon_client" | "panel" | "sweep"

	MonClientID string `json:"monClientId,omitempty"`
	InboundKind string `json:"inboundKind,omitempty"`
	InboundID   *int   `json:"inboundId,omitempty"`
	Path        string `json:"path,omitempty"`

	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`

	// Notified is true once a Telegram message for this transition has gone
	// out (via the panel normally, or directly from mon-server in
	// PANEL_DOWN, spec §4.1) — the panel must not send a second one.
	Notified bool `json:"notified"`

	// Phase and Report belong to kind "sweep" only (decision #100, contract
	// §4.6): which moment of a diagnostic sweep this is — start, change or
	// end — and what the sweep found. Both are absent from every other kind.
	Phase  string       `json:"phase,omitempty"`
	Report *SweepReport `json:"report,omitempty"`
}

// EnqueueEvent durably queues one event for the panel (spec §4 step 4) by
// marshalling it exactly as the wire form and inserting it into
// events_outbox with SentAt left nil. The outbox is the only path an event
// takes to the panel, including mon-server's own PANEL_DOWN/PANEL_UP
// transitions (spec §4.1) — there is no direct-send shortcut, so a crash
// between "decided" and "sent" never loses an event.
func (s *Store) EnqueueEvent(ev EventPayload) error {
	return EnqueueEventTx(s.DB, ev)
}

// EnqueueEventTx is EnqueueEvent against a caller-supplied handle, which is
// what lets a caller file an event in the same transaction as the row the
// event describes. internal/state needs this: a heartbeat's whole mutation
// — the mon-client's last_ack_seq, the target rows it moves and the events
// those moves owe the panel — has to commit or roll back as one, or a crash
// in the middle leaves an acknowledged cycle whose transition was never
// recorded and can never be resent (the mon-client drops everything at or
// below the ack). Pass a *gorm.DB from DB.Transaction; passing Store.DB
// itself is the same as calling EnqueueEvent.
func EnqueueEventTx(tx *gorm.DB, ev EventPayload) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	row := EventOutbox{
		Id:       ev.ID,
		Ts:       ev.Ts,
		Payload:  string(payload),
		Notified: ev.Notified,
	}
	return tx.Create(&row).Error
}
