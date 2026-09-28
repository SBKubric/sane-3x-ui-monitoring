package state

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

const (
	// bucketWindow is the statistics window of spec §7.4 ("Бакет 5 мин"),
	// and bucketWindowMs is the same number in the milliseconds every stored
	// and wire timestamp uses — the contract's bucketStart must be a
	// multiple of exactly 300000 (§4.7).
	bucketWindow   = 5 * time.Minute
	bucketWindowMs = int64(bucketWindow / time.Millisecond)

	// bucketCloseDelay is the grace spec §7.4 leaves after a window ends
	// before the bucket is sent ("закрывается через 1 мин после конца
	// окна"): a heartbeat carrying the window's last cycles is itself up to
	// a probe interval late, and a bucket sent the instant its window ended
	// would report a hole the panel would have to un-learn on the resend.
	bucketCloseDelay   = 1 * time.Minute
	bucketCloseDelayMs = int64(bucketCloseDelay / time.Millisecond)

	// maxStatsPerBatch is the contract's cap on one POST /stats body (§3:
	// "stats ≤ 2000"; spec §4 step 4). A larger batch is not an error the
	// panel retries — it is a 413 — so the backlog is split here rather
	// than discovered on the wire.
	maxStatsPerBatch = 2000
)

// Buckets is the 5-minute statistics aggregate of spec §7.4: the sink the
// heartbeat engine hands every accepted cycle to (Record), and the flusher
// the panel poller drives at the end of each cycle (Flush). It owns no
// state of its own beyond its collaborators — everything it knows lives in
// `stats_buckets` — so a restart mid-window loses nothing and a bucket
// keeps accumulating exactly where it left off.
//
// The POST /stats answer is also where the panel asks for a state resync
// (StatsResult.Resync); Flush hands the named targets to the Resyncer, if
// one is set.
type Buckets struct {
	st  *store.Store
	clk clock.Clock

	resyncer Resyncer

	// resyncMu guards the resync throttle (decision #151 Q5: at most one
	// resync per target per stats cycle). It lives in memory only — after a
	// restart a target may be resynced once more, which costs the panel one
	// silent update. resyncCycle is the stats cycle resynced holds keys
	// for; entering a new one starts the set over, so it never grows past
	// one cycle's worth.
	resyncMu    sync.Mutex
	resyncCycle int64
	resynced    map[panel.TargetRef]bool
}

// Resyncer answers the panel's resync request (decision
// SBKubric/sane-3x-ui#151 Q3): it files a state resync event for each named
// target mon-server holds a state for. The Engine implements it; it is an
// interface here only because the Engine takes Buckets as a dependency and
// is built after them.
type Resyncer interface {
	Resync(ctx context.Context, refs []panel.TargetRef) error
}

// SetResyncer sets who answers the panel's resync requests. Without one
// they are ignored, which is also what an older mon-server did.
func (b *Buckets) SetResyncer(r Resyncer) { b.resyncer = r }

// NewBuckets wires the aggregate to the database it lives in and the clock
// that decides when a bucket has closed. The clock is injected for the same
// reason it is everywhere else in mon-server: a test must be able to step
// past a bucket's close time without waiting six real minutes.
func NewBuckets(st *store.Store, clk clock.Clock) *Buckets {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Buckets{st: st, clk: clk}
}

// Record folds one heartbeat's cycles into their buckets (spec §7.4). It
// implements StatsSink, so the engine has already guaranteed what arrives:
// only cycles above the mon-client's last acknowledged seq, `ts` clamped
// against mon-server's own clock, and results for targets this mon-client
// was actually handed. What is left for this package is §7.4's counting
// rules.
//
// An unverified cycle's *failures* are a gap, not failures: its probes are
// aimed at mon-server itself, so "the tunnel is down" and "mon-server was
// unreachable" produce the same result and counting them would invent an
// outage out of mon-server's own downtime (protocol §5.3). Its *successes*
// are kept — a reply that came back proves the tunnel carried it.
//
// A bucket that the panel already has (sent_at set) and that receives new
// data has sent_at cleared, so the next Flush sends it again; the panel
// upserts by key, so the resend replaces the row rather than duplicating it
// (contract §4.7).
//
// tx is the caller's transaction, not one Buckets opens itself, because
// Record runs inside the heartbeat's own transaction (Engine.Heartbeat):
// the bucket writes must commit or roll back together with the ack that
// lets the mon-client forget these cycles, and mon-server keeps exactly one
// write connection (spec §3), so a second *store.Store-rooted transaction
// opened from in here would block forever waiting for the connection the
// caller's transaction is already holding. An error returned here therefore
// rolls the whole heartbeat back and reaches the mon-client as a failed
// request it will resend — which is why Record must never swallow one.
func (b *Buckets) Record(ctx context.Context, tx *gorm.DB, monClientID string, cycles []Cycle) error {
	if monClientID == "" || len(cycles) == 0 {
		return nil
	}
	tx = tx.WithContext(ctx)

	// Sorted by seq so that "the latest successful cycle" — the one whose
	// handshakeMs the bucket keeps — is simply the last one applied.
	// Across calls the order holds for free: the engine drops everything at
	// or below the last ack and acks the highest seq it saw, so a cycle can
	// never reach Record after a higher-seq one already has.
	ordered := make([]Cycle, len(cycles))
	copy(ordered, cycles)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Seq < ordered[j].Seq })

	deltas := map[bucketKey]*bucketDelta{}
	order := make([]bucketKey, 0, len(ordered))
	for _, c := range ordered {
		start := bucketStart(c.Ts)
		for _, r := range c.Results {
			if !r.Ok && c.Unverified {
				continue
			}
			k := bucketKey{
				monClientID: monClientID,
				inboundKind: r.InboundKind,
				inboundID:   r.InboundID,
				path:        r.Path,
				bucketStart: start,
			}
			d := deltas[k]
			if d == nil {
				d = &bucketDelta{}
				deltas[k] = d
				order = append(order, k)
			}
			d.add(r)
		}
	}
	if len(deltas) == 0 {
		return nil
	}

	// All-or-nothing comes from the caller's transaction (see the doc
	// comment above): a crash must not leave half a heartbeat's cycles
	// counted, because nothing will ever resend them once the engine has
	// acked them, and applying them one at a time on tx already gets that
	// for free.
	for _, k := range order {
		if err := applyDelta(tx, k, deltas[k]); err != nil {
			return err
		}
	}
	return nil
}

// Flush sends every closed, unsent bucket to POST /stats (spec §4 step 4)
// and implements panel.StatsFlusher, which is why it takes the client
// rather than owning one: internal/panel is the only package that knows how
// to reach the panel and how to retry.
//
// The batch rules mirror the poller's own outbox drain, because the failure
// modes are the same (contract §3): at most maxStatsPerBatch rows per call,
// oldest window first, sent_at stamped only on a 200 and only for the rows
// that 200 accepted. The panel answers each row on its own (decision #50):
// a rejected row would be rejected again on every resend, so it is logged
// with the panel's reason and dropped — sent_at stamped, dropped set —
// while the rest of the batch counts as delivered; an empty answer (an
// older panel) rejects nothing. A non-retryable answer to the whole batch
// (4xx) drops the whole batch the same way. A retryable failure (5xx,
// transport, timeout) leaves every row untouched and is returned: the
// poller logs it and the next cycle tries again.
//
// The returned error deliberately does not feed the PANEL_DOWN accounting
// of spec §4.1 — that lives in the poller's observe, around the call that
// produced the error — so a panel that is down is detected by the same
// cycle's GET /state, one endpoint earlier, rather than twice.
func (b *Buckets) Flush(ctx context.Context, c panel.Client) error {
	if c == nil {
		return nil
	}
	closedBefore := clock.Ms(b.clk.Now()) - bucketWindowMs - bucketCloseDelayMs

	for {
		var rows []store.StatsBucket
		err := b.st.DB.WithContext(ctx).
			Where("sent_at IS NULL AND bucket_start <= ?", closedBefore).
			Order("bucket_start, id").
			Limit(maxStatsPerBatch).
			Find(&rows).Error
		if err != nil {
			return fmt.Errorf("state: reading stats buckets: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}

		payloads := make([]panel.StatPayload, 0, len(rows))
		ids := make([]int, 0, len(rows))
		for _, row := range rows {
			payloads = append(payloads, payloadOf(row))
			ids = append(ids, row.Id)
		}

		res, err := c.PostStats(ctx, payloads)
		if err != nil {
			if panel.IsRetryable(err) {
				return err
			}
			var apiErr *panel.APIError
			if errors.As(err, &apiErr) {
				slog.Warn("state: dropping stats batch the panel rejected",
					"status", apiErr.Status, "code", apiErr.Code, "message", apiErr.Message, "count", len(ids))
			} else {
				slog.Warn("state: dropping stats batch the panel would never accept",
					"err", err, "count", len(ids))
			}
			if err := b.markDropped(ctx, ids); err != nil {
				return err
			}
			continue
		}

		rejected := panel.Rejections(len(ids), res.Rejected, nil)
		sent := make([]int, 0, len(ids))
		var refused []int
		for i, id := range ids {
			r, ok := rejected[i]
			if !ok {
				sent = append(sent, id)
				continue
			}
			p := payloads[i]
			slog.Warn("state: dropping stats bucket the panel rejected",
				"monClientId", p.MonClientId, "inboundKind", p.InboundKind, "inboundId", p.InboundId,
				"path", p.Path, "bucketStart", p.BucketStart, "error", r.Error)
			refused = append(refused, id)
		}
		if len(res.Ignored) > 0 {
			// Contract §3: a bucket for an inbound the panel has since
			// deleted is skipped, not retried. It is worth a log line and
			// nothing more.
			slog.Info("state: stats accepted with ignored rows",
				"accepted", res.Accepted, "ignored", len(res.Ignored))
		}
		if err := b.markSent(ctx, sent); err != nil {
			return err
		}
		if err := b.markDropped(ctx, refused); err != nil {
			return err
		}
		b.resync(ctx, res.Resync)
	}
}

// resync passes the panel's resync request on, minus the targets already
// resynced in this stats cycle: the panel names a target in every answer
// until an event arrives, and one flush may post several batches, or post
// again when a late heartbeat reopens a sent bucket. A failure is logged,
// not returned: the stats themselves went in, and the panel names the same
// targets again in the next cycle's answer.
func (b *Buckets) resync(ctx context.Context, refs []panel.TargetRef) {
	if b.resyncer == nil || len(refs) == 0 {
		return
	}
	fresh := b.throttleResync(refs)
	if len(fresh) == 0 {
		return
	}
	if err := b.resyncer.Resync(ctx, fresh); err != nil {
		slog.Warn("state: answering the panel's resync request", "err", err, "count", len(fresh))
	}
}

// throttleResync returns the refs not yet resynced in the current stats
// cycle and marks them resynced. The stats cycle is the 5-minute window
// whose close the flush is reporting (spec §7.4): every flush between one
// window's close and the next's falls in the same one.
func (b *Buckets) throttleResync(refs []panel.TargetRef) []panel.TargetRef {
	cycle := (clock.Ms(b.clk.Now()) - bucketCloseDelayMs) / bucketWindowMs
	b.resyncMu.Lock()
	defer b.resyncMu.Unlock()
	if b.resynced == nil || cycle != b.resyncCycle {
		b.resyncCycle = cycle
		b.resynced = map[panel.TargetRef]bool{}
	}
	var fresh []panel.TargetRef
	for _, r := range refs {
		if b.resynced[r] {
			continue
		}
		b.resynced[r] = true
		fresh = append(fresh, r)
	}
	return fresh
}

// markSent stamps sent_at on the rows one POST /stats accepted, which is
// what takes them out of every later flush. It runs only after a 200, never
// on a batch the panel may yet accept.
func (b *Buckets) markSent(ctx context.Context, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	now := clock.Ms(b.clk.Now())
	if err := b.st.DB.WithContext(ctx).
		Model(&store.StatsBucket{}).
		Where("id IN ?", ids).
		Update("sent_at", now).Error; err != nil {
		return fmt.Errorf("state: marking stats buckets sent: %w", err)
	}
	return nil
}

// markDropped takes rows the panel rejected out of the flush: sent_at is
// stamped like markSent's, and dropped records that they were given up on
// rather than delivered. New data for the window clears both (applyDelta).
func (b *Buckets) markDropped(ctx context.Context, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	now := clock.Ms(b.clk.Now())
	if err := b.st.DB.WithContext(ctx).
		Model(&store.StatsBucket{}).
		Where("id IN ?", ids).
		Updates(map[string]any{"sent_at": now, "dropped": true}).Error; err != nil {
		return fmt.Errorf("state: marking stats buckets dropped: %w", err)
	}
	return nil
}

// bucketKey is one row of `stats_buckets` addressed the way spec §7.4 keys
// it, comparable so a heartbeat's results can be grouped in a map before
// any of them touches the database.
type bucketKey struct {
	monClientID string
	inboundKind string
	inboundID   int
	path        string
	bucketStart int64
}

// bucketDelta is what one heartbeat adds to one bucket. It exists so the
// database sees one read-modify-write per (key, window) per heartbeat
// instead of one per probe result.
type bucketDelta struct {
	nOk, nFail int

	latSum int64
	latN   int
	latMin int64
	latMax int64

	// handshakeSet distinguishes "no successful AWG cycle in this delta"
	// from "the latest successful AWG cycle reported no handshake": only
	// the second may overwrite what the bucket already holds.
	handshakeSet bool
	handshake    *int64
}

// add folds one probe result into the delta (spec §7.4). The caller has
// already dropped unverified failures; everything that reaches here counts.
func (d *bucketDelta) add(r Result) {
	if !r.Ok {
		d.nFail++
		return
	}
	d.nOk++
	if r.TlsMs != nil {
		v := *r.TlsMs
		if d.latN == 0 || v < d.latMin {
			d.latMin = v
		}
		if d.latN == 0 || v > d.latMax {
			d.latMax = v
		}
		d.latSum += v
		d.latN++
	}
	if r.InboundKind == store.InboundKindAwg {
		// Results are applied in seq order, so the last assignment is the
		// latest successful cycle's handshake — spec §7.4's rule.
		d.handshakeSet = true
		d.handshake = r.HandshakeMs
	}
}

// applyDelta merges one delta into its stored bucket, creating the row on
// first sight of the key. Latency is merged through the stored sum and
// sample count rather than through the stored average (see
// store.StatsBucket.LatSum), so a bucket built from five heartbeats has
// exactly the average it would have had from one.
func applyDelta(tx *gorm.DB, k bucketKey, d *bucketDelta) error {
	var row store.StatsBucket
	err := tx.Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ? AND bucket_start = ?",
		k.monClientID, k.inboundKind, k.inboundID, k.path, k.bucketStart).
		Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		row = store.StatsBucket{
			MonClientId: k.monClientID,
			InboundKind: k.inboundKind,
			InboundId:   k.inboundID,
			Path:        k.path,
			BucketStart: k.bucketStart,
		}
	case err != nil:
		return fmt.Errorf("state: reading stats bucket: %w", err)
	}

	row.NOk += d.nOk
	row.NFail += d.nFail

	if d.latN > 0 {
		if row.LatMin == nil || d.latMin < *row.LatMin {
			v := d.latMin
			row.LatMin = &v
		}
		if row.LatMax == nil || d.latMax > *row.LatMax {
			v := d.latMax
			row.LatMax = &v
		}
		row.LatSum += d.latSum
		row.LatN += d.latN
		// Rounded to the nearest millisecond: the wire form is an integer
		// (contract §4.7), and truncating would bias every average down.
		avg := (row.LatSum + int64(row.LatN)/2) / int64(row.LatN)
		row.LatAvg = &avg
	}
	if d.handshakeSet {
		row.HandshakeMs = d.handshake
	}
	if row.NOk == 0 {
		// Contract §4.7: "при nOk=0 все latency — null". Nothing above can
		// set them without a success, but the invariant is cheap to state
		// and this is the one place that could ever break it.
		row.LatMin, row.LatAvg, row.LatMax, row.HandshakeMs = nil, nil, nil, nil
	}

	// New data invalidates whatever the panel was told about this window:
	// clearing sent_at is what puts it back in the next Flush (spec §7.4,
	// "досланные циклы … отправляют его повторно"). A dropped window is
	// reopened the same way — the rejection was of the old content.
	row.SentAt = nil
	row.Dropped = false

	if err := tx.Save(&row).Error; err != nil {
		return fmt.Errorf("state: saving stats bucket: %w", err)
	}
	return nil
}

// payloadOf renders one stored bucket as the contract's MonStatIn (§4.7).
// The latency fields are already NULL-correct in the row (applyDelta keeps
// the nOk = 0 invariant), so this is a pure rename of columns to wire
// names.
func payloadOf(row store.StatsBucket) panel.StatPayload {
	return panel.StatPayload{
		MonClientId:  row.MonClientId,
		InboundKind:  row.InboundKind,
		InboundId:    row.InboundId,
		Path:         row.Path,
		BucketStart:  row.BucketStart,
		NOk:          row.NOk,
		NFail:        row.NFail,
		LatencyMinMs: row.LatMin,
		LatencyAvgMs: row.LatAvg,
		LatencyMaxMs: row.LatMax,
		HandshakeMs:  row.HandshakeMs,
	}
}

// bucketStart floors a cycle's timestamp to its 5-minute window (spec §7.4:
// "bucketStart = ts − ts % 300000"). ts has already been clamped to
// mon-server's own receive time by the engine, so it is always a sane epoch
// value; the negative branch only exists so a hypothetical pre-1970
// timestamp still floors downward instead of into the future.
func bucketStart(ts int64) int64 {
	rem := ts % bucketWindowMs
	if rem < 0 {
		rem += bucketWindowMs
	}
	return ts - rem
}
