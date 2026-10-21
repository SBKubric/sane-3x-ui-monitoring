// Package heartbeat owns the cycles a mon-client owes mon-server: the
// on-disk buffer they wait in until a heartbeat is acknowledged (spec §6,
// protocol §5.3) and the one-line wrapper that sends them.
//
// The buffer is the reason a mon-client keeps probing while mon-server is
// unreachable (spec §6: "Пробы при этом продолжаются"): a cycle is
// written to cycles.json *before* the heartbeat that carries it, so a
// delivery that never lands costs nothing but a flag on the cycle, and a
// mon-client that is restarted mid-outage still owes exactly the cycles it
// owed before — as long as the write itself worked. That is the whole of
// the guarantee: what survives a restart is what reached the disk, so a
// cycle whose save failed (a full or read-only state directory) lives in
// memory only, and is owed to mon-server until some later save succeeds.
package heartbeat

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// MaxCycles is spec §6's buffer bound ("≤ 60 циклов, старые вытесняются").
// At one cycle a minute that is an hour of outage kept in full; past it
// the oldest cycle is dropped, because a mon-server that has been down for
// two hours cares about the last hour, and an unbounded buffer on a box
// with no disk quota is worse than a gap in the statistics.
const MaxCycles = 60

// fileMode is cycles.json's permission. It holds no secret (only probe
// results), but it lives in the same 0700 state directory as state.json
// and there is no reason for it to be more readable than its neighbours.
const fileMode = 0o600

// bufferFile is cycles.json's content. NextSeq is persisted alongside the
// cycles — not derived from them — because spec §6 wants seq monotonic
// across restarts ("seq (монотонный, в state)"), and a buffer whose cycles
// were all acknowledged is empty: derived from an empty list, the next seq
// would restart at 1 and mon-server would see a mon-client replaying seqs
// it had already acknowledged.
type bufferFile struct {
	NextSeq int64         `json:"nextSeq"`
	Cycles  []proto.Cycle `json:"cycles"`
}

// Buffer is the opened cycles.json: the cycles not yet acknowledged, in
// the order they were produced, plus the seq counter. Every mutation is
// persisted before it is visible to the caller, and every method that
// persists reports whether it managed to — a buffer that could not write
// keeps working from memory, which is a degraded mon-client rather than a
// stopped one, but the caller is the one that decides how loudly to say
// so.
//
// It is safe for concurrent use. The run loop is single-goroutine today,
// but the buffer is the one piece of mon-client state a future shutdown
// path or signal handler would plausibly want to flush from elsewhere.
type Buffer struct {
	path string

	mu      sync.Mutex
	nextSeq int64
	cycles  []proto.Cycle
}

// OpenBuffer reads path (state.Dir.Path("cycles.json")) into a Buffer. A
// missing file is not an error — it is a mon-client's first boot, and the
// answer is an empty buffer whose first cycle gets seq 1. A file that
// exists but cannot be read or decoded *is* an error: silently starting
// over would reuse seqs mon-server has already seen, and only the caller
// can decide that losing the buffer is preferable to refusing to start.
func OpenBuffer(path string) (*Buffer, error) {
	b := &Buffer{path: path, nextSeq: 1}

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return b, nil
		}
		return nil, fmt.Errorf("heartbeat: read %s: %w", filepath.Base(path), err)
	}

	var f bufferFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("heartbeat: decode %s: %w", filepath.Base(path), err)
	}
	b.cycles = f.Cycles
	if f.NextSeq > b.nextSeq {
		b.nextSeq = f.NextSeq
	}
	// A file written by an older version (or truncated by a full disk)
	// could carry cycles beyond its own nextSeq; the counter must never
	// hand out a seq that is already in the buffer.
	for _, c := range b.cycles {
		if c.Seq >= b.nextSeq {
			b.nextSeq = c.Seq + 1
		}
	}
	return b, nil
}

// Add appends one finished cycle, assigns it the next seq and persists the
// buffer before returning it, so that the cycle exists on disk before any
// heartbeat can claim to have delivered it (spec §6: "цикл добавляется до
// отправки"). Adding the 61st cycle evicts the oldest (MaxCycles).
//
// The returned error is the persist error, and it is deliberately not
// fatal: the cycle is in the buffer either way and the very next heartbeat
// will carry it, so the run loop logs it and keeps probing (spec §6). It
// is returned rather than logged here because this package has no logger
// of its own and the loop does — and because a caller that wanted to stop
// on a state directory it cannot write should be able to.
func (b *Buffer) Add(ts int64, results []proto.Result) (proto.Cycle, error) {
	return b.AddCycle(ts, results, nil)
}

// AddCycle is Add for a cycle that may also carry a diagnostic sweep run
// (decision #100, protocol §5.3), buffered and resent with it like the
// rest of the cycle.
func (b *Buffer) AddCycle(ts int64, results []proto.Result, sweep *proto.CycleSweep) (proto.Cycle, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	c := proto.Cycle{Seq: b.nextSeq, Ts: ts, Results: results, Sweep: sweep}
	if c.Results == nil {
		c.Results = []proto.Result{}
	}
	b.nextSeq++
	b.cycles = append(b.cycles, c)
	if len(b.cycles) > MaxCycles {
		b.cycles = b.cycles[len(b.cycles)-MaxCycles:]
	}
	return c, b.save()
}

// ContinueAfter makes the next cycle's seq at least ackSeq + 1 (decision
// #51 §1). It is how a buffer that starts empty — cycles.json lost, or
// corrupt and discarded — picks up after the last ack mon-server gave
// (state.File.LastAckSeq) instead of at 1, which mon-server would drop as
// already seen. The counter never moves backwards. Nothing is persisted
// here: the next Add saves the counter together with its cycle.
func (b *Buffer) ContinueAfter(ackSeq int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.continueAfter(ackSeq)
}

func (b *Buffer) continueAfter(ackSeq int64) {
	if ackSeq >= b.nextSeq {
		b.nextSeq = ackSeq + 1
	}
}

// Pending returns the cycles owed to mon-server, oldest first — exactly
// the list that goes into the next heartbeat's cycles[] (protocol §5.3:
// unacknowledged cycles are resent together with the new one). The slice
// is a copy; the caller may hand it straight to json.Marshal while the
// loop keeps running.
func (b *Buffer) Pending() []proto.Cycle {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]proto.Cycle(nil), b.cycles...)
}

// Ack drops every cycle with seq ≤ ackSeq and persists what is left
// (protocol §5.3: "ackSeq подтверждает всё до него включительно"). A
// heartbeat that was answered acknowledges everything it carried, so after
// a successful send the buffer is normally empty — which is exactly why
// nextSeq is persisted separately.
//
// An ackSeq at or above the counter means mon-server remembers seqs this box
// has forgotten (both its files were lost): the counter jumps past it, so
// the next cycle is not dropped as a duplicate as well (decision #51 §1).
func (b *Buffer) Ack(ackSeq int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.continueAfter(ackSeq)

	kept := b.cycles[:0]
	for _, c := range b.cycles {
		if c.Seq > ackSeq {
			kept = append(kept, c)
		}
	}
	b.cycles = kept
	return b.save()
}

// MarkUnverified flags every pending cycle unverified and persists them —
// spec §6's answer to a heartbeat that was never acknowledged (network
// error, 5xx, timeout). The flag travels with the cycle to mon-server,
// which counts an unverified cycle's successes but not its failures
// (protocol §5.3): mon-server being unreachable is indistinguishable from
// every tunnel to it being down, since it is the probe's destination too.
func (b *Buffer) MarkUnverified() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range b.cycles {
		b.cycles[i].Unverified = true
	}
	return b.save()
}

// save writes the buffer atomically, the same temp-file-plus-rename
// state.Dir.Save uses: a crash between two cycles must leave the previous
// cycles.json intact rather than a half-written one that OpenBuffer would
// then refuse to decode.
func (b *Buffer) save() error {
	raw, err := json.Marshal(bufferFile{NextSeq: b.nextSeq, Cycles: b.cycles})
	if err != nil {
		return fmt.Errorf("heartbeat: encode cycles: %w", err)
	}

	dir := filepath.Dir(b.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(b.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("heartbeat: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("heartbeat: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("heartbeat: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("heartbeat: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("heartbeat: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, b.path); err != nil {
		return fmt.Errorf("heartbeat: rename into place: %w", err)
	}
	success = true
	return nil
}
