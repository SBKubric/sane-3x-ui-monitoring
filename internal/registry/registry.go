// Package registry is mon-server's registration desk and mon-client
// directory (architecture brief §2, spec §6): it turns an unauthenticated
// pairing-code bid into a pending RegistrationRequest, lets an administrator
// approve or reject it, mints and hashes client tokens, and answers every
// later `/v1/*` handler's "who is this client token" question. Nothing here
// talks HTTP — internal/api's register.go and RequireClientToken middleware
// are the only callers, and internal/app is the only place that constructs
// one.
package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

const (
	// requestTTL is how long a registration request stays "pending" before
	// Poll answers 410 request_expired (protocol §2.1: "живёт 5 минут"). An
	// approved request reuses the same TTL for a second purpose: the window
	// an admin-approved, not-yet-collected client token may sit in
	// ApprovedToken before it too is treated as expired (spec §6) — see
	// Poll and Approve/ApproveAsReplacement's ExpiresAt reset.
	requestTTL = 5 * time.Minute
	// pollAfterMs is the interval Register tells a mon-client to wait
	// between polls (protocol §2.1: "pollAfter: 10000").
	pollAfterMs int64 = 10000
	// requestIDBytes is the entropy of a requestId before base64url
	// encoding (protocol §2.1: "128 бит, base64url").
	requestIDBytes = 16
	// tokenBytes is the entropy of a client token before base64url
	// encoding (spec §6: "32 случайных байта").
	tokenBytes = 32
	// slugMaxLen bounds a mon-client id (spec §6: "≤ 32"): the panel names
	// the mon-client's AWG probe peers after it and refuses a longer id in
	// POST /probe/ensure (decision #80).
	slugMaxLen = 32

	// rateLimitWindow is the per-IP registration throttle (spec §6: "1
	// заявка/мин на IP").
	rateLimitWindow = time.Minute
	// maxPendingPerIP is the cap on simultaneously pending requests from one
	// IP (spec §6: "≤ 3 pending с IP").
	maxPendingPerIP = 3
	// maxPendingGlobal is the cap on simultaneously pending requests across
	// every IP (spec §6: "≤ 20 pending глобально").
	maxPendingGlobal = 20
	// globalRetryAfter is the fallback Retry-After mon-server quotes when
	// the ≤3-per-IP or ≤20-global cap is hit and, for some reason, no
	// blocking pending row can be found to derive a real value from (should
	// never happen: the caller just counted at least one). Ordinarily
	// pendingCapRetryAfter answers with the earliest blocking row's own
	// expiry instead of this fixed number.
	globalRetryAfter = 60 * time.Second

	// slugSuffixAttempts bounds how many "-2", "-3", ... suffixes
	// uniqueSlug tries before giving up; a real install never has anywhere
	// near this many mon-clients sharing a name, so hitting it means
	// something else is wrong (e.g. the DB query itself is broken) and
	// looping forever would be worse than a clear error.
	slugSuffixAttempts = 10000
)

// pairingCodeRe is the pairing code's exact wire form (protocol §2.1:
// "[A-Z2-9]{6}") — digits 0/1 and letters O/I are excluded because a
// mon-client operator reads this code off a log and types it into the
// admin UI, and those pairs are the classic transcription mistake.
var pairingCodeRe = regexp.MustCompile(`^[A-Z2-9]{6}$`)

// slugInvalidRun matches any run of characters that isn't part of a
// mon-client id's allowed alphabet (spec §6: "[A-Za-z0-9_-]", the panel's
// probe-peer name alphabet, decision #80), so slugify
// can collapse a whole run of spaces/punctuation into a single "-" instead
// of leaving "amsterdam---1".
var slugInvalidRun = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// Sentinel errors Poll, Approve, ApproveAsReplacement and Reject return so
// internal/api's handlers can map them to the right HTTP status without
// registry knowing anything about HTTP.
var (
	// ErrRequestNotFound means requestId matches no row at all — handler:
	// 404 with no further detail (protocol §2.1: "без деталей", so a probe
	// for someone else's requestId can't be told apart from a typo).
	ErrRequestNotFound = errors.New("registry: registration request not found")
	// ErrRequestExpired means the row's TTL has passed: either a "pending"
	// request nobody approved in time, or an "approved" one whose token sat
	// uncollected past its own hand-off window (spec §6) — either way
	// loadPendingRequest (or Poll's sibling check for the latter case) has
	// already flipped the row to "expired" by the time this is returned.
	// Handler: 410 request_expired.
	ErrRequestExpired = errors.New("registry: registration request expired")
	// ErrInvalidPairingCode means Register's input failed pairingCodeRe —
	// handler: 400 invalid_body.
	ErrInvalidPairingCode = errors.New("registry: pairing code must match [A-Z2-9]{6}")
	// ErrInvalidPath means Approve/ApproveAsReplacement's/Update's paths
	// argument contained something outside the paths vocabulary of spec
	// §5.1 — direct, hops, edge:<name>, inner:<name> — handler: 400
	// invalid_body. Never reachable from /v1/register* (that surface never
	// validates paths), only from the admin API (step 10).
	ErrInvalidPath = errors.New("registry: paths are \"direct\", \"edges\", \"hops\", \"edge:<name>\" or \"inner:<name>\"")
	// ErrRequestNotPending means Approve/ApproveAsReplacement/Reject was
	// called on a request that is not (or no longer) pending — an admin UI
	// bug (double-click, stale page), not a mon-client-facing error.
	ErrRequestNotPending = errors.New("registry: registration request is not pending")
	// ErrClientNotFound means an operation named a mon-client id that has no
	// row (Get, Update, SetEnabled, Revoke, Delete, ApproveAsReplacement's
	// existingID).
	ErrClientNotFound = errors.New("registry: mon-client not found")

	// ErrTokenRevoked is Authenticate's answer when the client token is
	// unknown or has been revoked (protocol §3) — handler: 401
	// token_revoked. Also used directly by internal/api's RequireClientToken
	// for a missing/malformed Authorization header, since protocol §3
	// defines no third code for that case.
	ErrTokenRevoked = errors.New("token_revoked")
	// ErrDisabled is Authenticate's answer when the token is valid but the
	// mon-client has been disabled in the admin UI (protocol §3) — handler:
	// 403 disabled.
	ErrDisabled = errors.New("disabled")
)

// RateLimitError is Register's answer when spec §6's per-IP or global
// pending caps are hit, or its 1/minute-per-IP throttle trips. It carries
// how long the caller should wait so internal/api's handler can echo it as
// the Retry-After header (protocol §2.1) — a plain sentinel error couldn't
// carry a per-call value, and a shared package-level instance would race
// across concurrent registrations with different remaining waits.
type RateLimitError struct {
	// RetryAfter is how long to wait before the next attempt might succeed,
	// always rounded up to a whole number of seconds and never zero (see
	// ceilSeconds) — Retry-After is a whole-seconds HTTP header, and
	// truncating instead of rounding up could tell a caller it may retry
	// before it actually can.
	RetryAfter time.Duration
}

// Error satisfies the error interface with a message meant for logs, not
// for a mon-client to parse (that's the handler's "too_many_requests" code).
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("registry: rate limited, retry after %s", e.RetryAfter)
}

// Hooks are the callbacks later steps install so registry's own DB work
// (paths changing, a mon-client being disabled or approved) triggers their side of the
// system, without registry importing those packages and creating an import
// cycle (architecture brief §3.5). Every field is nil-safe: a Registry with
// no hooks set (as in this step's own tests, and briefly at process start
// before internal/app wires them) just skips the callback.
type Hooks struct {
	// PathsChanged is called after Update persists a paths change for
	// monClientID, so step 5's config builder can rebuild that mon-client's
	// document and bump its config revision (protocol §4.1).
	PathsChanged func(ctx context.Context, monClientID string) error
	// Disabled is called after SetEnabled(id, false) persists, so step 6's
	// state engine can drive that mon-client's targets to UNKNOWN with
	// reason "mon_client_disabled" (spec §6).
	Disabled func(ctx context.Context, monClientID string) error
	// Approved is called after Approve or ApproveAsReplacement commits, so
	// step 5's config builder can give the brand-new (or re-tokened)
	// mon-client a config document straight away (spec §5). Without it a
	// freshly approved mon-client's very first GET /v1/config would depend
	// on whenever the next panel revision happens to land.
	Approved func(ctx context.Context, monClientID string) error
	// Revoked is called inside Revoke's transaction, before the registry
	// clears the token and sets state=OFFLINE, with the mon-client row as it
	// stood until then — so the state engine can file the mon_client
	// transition from its real from-state and move the targets (decision
	// #51 §2) in the same commit as the revoke itself. The function it
	// returns, if any, runs after the commit: that is where Telegram goes,
	// which must never announce a revoke that was rolled back. An error
	// rolls the whole revoke back.
	Revoked func(ctx context.Context, tx *gorm.DB, mc store.MonClient) (after func(context.Context), err error)
}

// Registry is mon-server's registration desk and mon-client directory. It
// holds no state of its own beyond its collaborators — every fact it
// answers a question with comes straight out of st — so a Registry is cheap
// to construct and safe to share across every request goroutine.
type Registry struct {
	st    *store.Store
	clock clock.Clock
	hooks Hooks
}

// New builds a Registry over st, reading the current time through clk
// rather than time.Now() (architecture brief §1) so every TTL, rate-limit
// window and "approved at" timestamp is exercised deterministically in
// tests via clock.NewFake.
func New(st *store.Store, clk clock.Clock) *Registry {
	return &Registry{st: st, clock: clk}
}

// SetHooks installs the callbacks internal/app wires up once the later
// steps' packages exist. Called once at startup, before the HTTP listener
// accepts anything, so there is no need to guard it against concurrent use
// alongside the request-handling methods below.
func (r *Registry) SetHooks(h Hooks) {
	r.hooks = h
}

// ---------------------------------------------------------------------
// Registration requests (protocol §2, spec §6)
// ---------------------------------------------------------------------

// RegisterInput is everything a mon-client's POST /v1/register body plus
// its connection carries into Register.
type RegisterInput struct {
	PairingCode string
	Hostname    string
	Version     string
	PublicIP    string
	// RemoteIP is the TCP peer address (gin's c.ClientIP()), which the rate
	// limits and the admin UI's "same IP as an existing client" hint key on
	// — never the client-supplied PublicIP, which a hostile caller controls.
	RemoteIP string
}

// RegisterOutput is Register's success value, the exact shape of the
// protocol's 202 body (§2.1).
type RegisterOutput struct {
	RequestID   string
	PollAfterMs int64
	ExpiresAt   int64
}

// Register admits one registration request: validates the pairing code,
// enforces spec §6's rate limits, and inserts a pending row good for
// requestTTL. The rate-limit checks and the insert all run inside a single
// DB.Transaction: with the store's SetMaxOpenConns(1), that serialises the
// whole check-then-insert sequence across concurrent callers, so two
// registrations racing each other (from the same IP, or from enough
// distinct IPs to contend the global cap) can never both pass the same
// check before either has committed its row — the classic check-then-act
// race a bare sequence of separate statements would allow.
func (r *Registry) Register(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	if !pairingCodeRe.MatchString(in.PairingCode) {
		return nil, ErrInvalidPairingCode
	}

	id, err := randRequestID()
	if err != nil {
		return nil, err
	}

	var out *RegisterOutput
	err = r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := r.clock.Now()
		nowMs := clock.Ms(now)

		// 1 request/minute per IP (spec §6), regardless of that request's
		// current status — this throttles the *rate of asking*, not how
		// many are outstanding (that's the pending caps below).
		var last store.RegistrationRequest
		err := tx.Where("remote_ip = ?", in.RemoteIP).
			Order("created_at DESC").
			First(&last).Error
		switch {
		case err == nil:
			age := now.Sub(clock.FromMs(last.CreatedAt))
			if age < rateLimitWindow {
				return &RateLimitError{RetryAfter: ceilSeconds(rateLimitWindow - age)}
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			// first request ever seen from this IP: nothing to throttle
			// against.
		default:
			return err
		}

		// Both pending counts ignore expired rows without needing a sweep
		// first (item 2/3): a row past its own expires_at simply no longer
		// matches "status = pending AND expires_at > now", whether or not
		// anything has ever flipped its status column.
		var pendingFromIP int64
		if err := tx.Model(&store.RegistrationRequest{}).
			Where("remote_ip = ? AND status = ? AND expires_at > ?", in.RemoteIP, store.RegistrationPending, nowMs).
			Count(&pendingFromIP).Error; err != nil {
			return err
		}
		if pendingFromIP >= maxPendingPerIP {
			retry, err := pendingCapRetryAfter(tx, nowMs,
				"remote_ip = ? AND status = ? AND expires_at > ?", in.RemoteIP, store.RegistrationPending, nowMs)
			if err != nil {
				return err
			}
			return &RateLimitError{RetryAfter: retry}
		}

		var pendingGlobal int64
		if err := tx.Model(&store.RegistrationRequest{}).
			Where("status = ? AND expires_at > ?", store.RegistrationPending, nowMs).
			Count(&pendingGlobal).Error; err != nil {
			return err
		}
		if pendingGlobal >= maxPendingGlobal {
			retry, err := pendingCapRetryAfter(tx, nowMs,
				"status = ? AND expires_at > ?", store.RegistrationPending, nowMs)
			if err != nil {
				return err
			}
			return &RateLimitError{RetryAfter: retry}
		}

		req := store.RegistrationRequest{
			RequestId:   id,
			PairingCode: in.PairingCode,
			Hostname:    in.Hostname,
			Version:     in.Version,
			PublicIp:    in.PublicIP,
			RemoteIp:    in.RemoteIP,
			Status:      store.RegistrationPending,
			CreatedAt:   nowMs,
			ExpiresAt:   clock.Ms(now.Add(requestTTL)),
		}
		if err := tx.Create(&req).Error; err != nil {
			return err
		}

		out = &RegisterOutput{RequestID: id, PollAfterMs: pollAfterMs, ExpiresAt: req.ExpiresAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ceilSeconds rounds d up to the nearest whole second, never below one
// second — Retry-After is a whole-seconds HTTP header (protocol §2.1), and
// truncating (as a naive Duration/time.Second would) could tell a caller it
// may retry a fraction of a second before it actually can.
func ceilSeconds(d time.Duration) time.Duration {
	secs := math.Ceil(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs) * time.Second
}

// pendingCapRetryAfter answers spec §6's Retry-After when a pending-count
// cap (per-IP or global) is hit: the moment the cap can next possibly free
// up is the earliest expiry among the rows the caller just counted, not an
// arbitrary fixed delay. where/args must be the exact same filter the
// caller used to reach maxPendingPerIP/maxPendingGlobal, so the row this
// picks is genuinely one of the ones blocking the request. Falls back to
// globalRetryAfter only if that filter somehow now matches nothing (it just
// matched at least one row moments earlier in the same transaction).
func pendingCapRetryAfter(tx *gorm.DB, nowMs int64, where string, args ...any) (time.Duration, error) {
	var expiresAt []int64
	if err := tx.Model(&store.RegistrationRequest{}).
		Where(where, args...).
		Order("expires_at ASC").
		Limit(1).
		Pluck("expires_at", &expiresAt).Error; err != nil {
		return 0, err
	}
	if len(expiresAt) == 0 {
		return globalRetryAfter, nil
	}
	return ceilSeconds(time.Duration(expiresAt[0]-nowMs) * time.Millisecond), nil
}

// PollOutput is Poll's success value, the exact shape of one of the
// protocol's GET /v1/register/<id> 200 bodies (§2.2). MonClientID and Token
// are only populated for Status == "approved", and Token only on the first
// poll after approval.
type PollOutput struct {
	Status      string
	MonClientID string
	Token       string
}

// Poll answers a mon-client's registration status check (protocol §2.2).
// Two things are bounded by requestTTL here, both handled by loadPendingRequest
// or the sibling check right below it: a "pending" row nobody approved in
// time, and an "approved" row whose token nobody collected in time (spec
// §6) — Approve/ApproveAsReplacement reset ExpiresAt to now+requestTTL for
// exactly this second purpose. The one-time token hand-off itself (spec §6:
// "одноразовая выдача") is a single atomic conditional UPDATE keyed on the
// exact token value just read, not a read-then-clear inside an enclosing
// transaction: of two concurrent polls, only the one whose UPDATE still
// finds that value in place succeeds, so mon-server never needs a broader
// lock to guarantee the token is handed out exactly once.
func (r *Registry) Poll(ctx context.Context, requestID string) (*PollOutput, error) {
	db := r.st.DB.WithContext(ctx)
	now := r.clock.Now()
	nowMs := clock.Ms(now)

	req, err := loadPendingRequest(db, requestID, now)
	if err != nil {
		return nil, err
	}

	switch req.Status {
	case store.RegistrationPending:
		return &PollOutput{Status: "pending"}, nil
	case store.RegistrationRejected:
		return &PollOutput{Status: "rejected"}, nil
	case store.RegistrationExpired:
		return nil, ErrRequestExpired
	case store.RegistrationApproved:
		if req.ExpiresAt <= nowMs {
			if err := db.Model(&store.RegistrationRequest{}).
				Where("request_id = ? AND status = ?", requestID, store.RegistrationApproved).
				Updates(map[string]any{
					"status":         store.RegistrationExpired,
					"approved_token": "",
				}).Error; err != nil {
				return nil, err
			}
			return nil, ErrRequestExpired
		}

		out := &PollOutput{Status: "approved", MonClientID: req.MonClientId}
		if req.ApprovedToken != "" {
			res := db.Model(&store.RegistrationRequest{}).
				Where("request_id = ? AND approved_token = ? AND status = ?", requestID, req.ApprovedToken, store.RegistrationApproved).
				Update("approved_token", "")
			if res.Error != nil {
				return nil, res.Error
			}
			if res.RowsAffected == 1 {
				out.Token = req.ApprovedToken
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("registry: request %s has unknown status %q", requestID, req.Status)
}

// loadPendingRequest loads a registration request by id and, at the
// mechanism level, keeps its "pending" status honest: if the row is still
// marked pending but its TTL has already passed, it flips just that row to
// "expired" (spec §6) and returns ErrRequestExpired, instead of handing the
// caller a stale row. Every reader that cares whether a request is *really*
// still pending — Poll, Approve, ApproveAsReplacement, Reject — goes
// through this instead of a bare tx.First, so none of them can independently
// forget to check expiry (the bug this replaces: only Register and Poll
// used to sweep, via a table-wide ExpireRequests call, while Approve/
// ApproveAsReplacement/Reject/PendingRequests read the status column
// as-is). tx may be a real transaction or a plain *gorm.DB — Poll has no
// need for the former (see Poll's own doc comment), while Approve/
// ApproveAsReplacement/Reject call this from inside theirs so the flip
// participates in the same commit as whatever they do next.
func loadPendingRequest(tx *gorm.DB, requestID string, now time.Time) (*store.RegistrationRequest, error) {
	var req store.RegistrationRequest
	if err := tx.First(&req, "request_id = ?", requestID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRequestNotFound
		}
		return nil, err
	}
	if req.Status == store.RegistrationPending && req.ExpiresAt <= clock.Ms(now) {
		if err := tx.Model(&store.RegistrationRequest{}).
			Where("request_id = ?", requestID).
			Update("status", store.RegistrationExpired).Error; err != nil {
			return nil, err
		}
		return nil, ErrRequestExpired
	}
	return &req, nil
}

// ExpireRequests flips every "pending" row whose expiresAt has passed to
// "expired" (spec §6). It is a batch pass for the step-11 retention job's
// timer, not a hot-path dependency any more: Register's and Poll's own
// correctness never relied on this having run (see loadPendingRequest and
// the pending-count filters in Register), so it no longer runs on every
// registration and every 10-second poll from every mon-client — a
// table-wide UPDATE on that cadence, for rows nobody but the retention job
// needs promptly marked, was wasted write traffic.
func (r *Registry) ExpireRequests(ctx context.Context) (int, error) {
	nowMs := clock.Ms(r.clock.Now())
	res := r.st.DB.WithContext(ctx).Model(&store.RegistrationRequest{}).
		Where("status = ? AND expires_at <= ?", store.RegistrationPending, nowMs).
		Update("status", store.RegistrationExpired)
	if res.Error != nil {
		return 0, res.Error
	}
	return int(res.RowsAffected), nil
}

// ---------------------------------------------------------------------
// Approval (spec §6; the admin UI calls these in step 10)
// ---------------------------------------------------------------------

// ApproveInput is what an administrator supplies when approving a pending
// request (spec §9.2's Approve modal). Paths is the paths vocabulary of
// spec §5.1 and defaults to ["edges"] when empty (decision #100).
type ApproveInput struct {
	Name   string
	Region string
	Paths  []string
}

// validatePaths checks paths against the paths vocabulary of spec §5.1 —
// direct, edges, hops, or a hop by name (edge:<name>, inner:<name>) — applying the
// default when paths is empty, and returns a defensive copy without
// repeats so the caller can't mutate what gets stored after the fact.
// proxy is refused: it left the vocabulary for hops (decision #61 п. 3).
// A hop by name is checked by grammar only; whether the chain has it is the
// expansion's question, every time a config is built.
func validatePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return DefaultPaths(), nil
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p != store.PathDirect && p != store.PathHops && p != store.PathEdges && !store.IsHopPath(p) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidPath, p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// approveTx is the transaction-scoped machinery Approve and
// ApproveAsReplacement share: load and pending-check the request via
// loadPendingRequest, let mutate build the brand-new MonClient row or update
// the existing one, then stamp the request "approved" with the one-time
// token hand-off — parking token in ApprovedToken and resetting ExpiresAt to
// now+requestTTL so an uncollected hand-off later expires on its own schedule
// (see Poll). Sharing this tail is what stops the two approval paths from
// drifting on any of it again — the bug this fixes: ApproveAsReplacement
// used to stamp the request itself with a hand-rolled copy of this same
// Updates call, and it would have been easy for only one of the two copies
// to gain a future field like the expiry reset.
func approveTx(tx *gorm.DB, requestID string, now time.Time, token string, mutate func(req *store.RegistrationRequest) (*store.MonClient, error)) (*store.MonClient, error) {
	req, err := loadPendingRequest(tx, requestID, now)
	if err != nil {
		return nil, err
	}
	if req.Status != store.RegistrationPending {
		return nil, ErrRequestNotPending
	}

	mc, err := mutate(req)
	if err != nil {
		return nil, err
	}

	if err := tx.Model(&store.RegistrationRequest{}).
		Where("request_id = ?", requestID).
		Updates(map[string]any{
			"status":         store.RegistrationApproved,
			"approved_token": token,
			"mon_client_id":  mc.Id,
			"expires_at":     clock.Ms(now.Add(requestTTL)),
		}).Error; err != nil {
		return nil, err
	}
	return mc, nil
}

// Approve turns a pending request into a brand-new MonClient (spec §6): a
// slug of Name becomes its id, a fresh 32-byte token is minted and only its
// SHA-256 hash is stored, and (via approveTx) the request is stamped
// "approved" with the plaintext token parked for Poll's one-time hand-off.
// All of it — the id allocation, the MonClient insert and the request
// update — happens in one transaction so a crash mid-approval can never
// leave a MonClient row with no matching approved request, or vice versa.
func (r *Registry) Approve(ctx context.Context, requestID string, in ApproveInput) (*store.MonClient, error) {
	paths, err := validatePaths(in.Paths)
	if err != nil {
		return nil, err
	}

	now := r.clock.Now()
	token, tokenHash, err := newToken()
	if err != nil {
		return nil, err
	}

	var mc *store.MonClient
	err = r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var innerErr error
		mc, innerErr = approveTx(tx, requestID, now, token, func(req *store.RegistrationRequest) (*store.MonClient, error) {
			id, err := uniqueSlug(tx, in.Name)
			if err != nil {
				return nil, err
			}

			m := &store.MonClient{
				Id:         id,
				Name:       in.Name,
				Region:     in.Region,
				TokenHash:  tokenHash,
				Enabled:    true,
				State:      store.MonClientNever,
				LastAckSeq: 0, // decision #51 §1: a new token is a new seq generation
				ApprovedAt: clock.Ms(now),
				RemoteIp:   req.RemoteIp,
				Version:    req.Version,
			}
			m.SetPaths(paths)
			if err := tx.Create(m).Error; err != nil {
				return nil, err
			}
			return m, nil
		})
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	r.notifyApproved(ctx, mc.Id)
	return mc, nil
}

// ApproveAsReplacement turns a pending request into a token/identity reset
// for an *existing* mon-client (spec §6: "Approve as replacement") instead
// of a new row: id, name, region, paths and every historical row that
// points at existingID (targets, stats, events) survive untouched, but its
// token_hash is replaced (the old token now fails Authenticate with
// ErrTokenRevoked), remote_ip and version are refreshed from the new
// request (the box on the other end of this id may be a different physical
// machine now), and every heartbeat-derived field — last_heartbeat,
// missed_heartbeats, xray_version, config_error, config_error_at,
// applied_revision — is cleared so state=NEVER is coherent with "we know
// nothing about this box yet" rather than quietly carrying over the
// replaced box's last-known diagnostics.
func (r *Registry) ApproveAsReplacement(ctx context.Context, requestID, existingID string) (*store.MonClient, error) {
	now := r.clock.Now()
	token, tokenHash, err := newToken()
	if err != nil {
		return nil, err
	}

	var mc *store.MonClient
	err = r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var innerErr error
		mc, innerErr = approveTx(tx, requestID, now, token, func(req *store.RegistrationRequest) (*store.MonClient, error) {
			// last_ack_seq goes back to 0 (decision #51 §1): seq belongs
			// to one token generation, the box holding the new token
			// counts from 1, and an ack left over from the old one would
			// make every cycle up to it look like a duplicate.
			res := tx.Model(&store.MonClient{}).Where("id = ?", existingID).Updates(map[string]any{
				"token_hash":        tokenHash,
				"state":             store.MonClientNever,
				"last_ack_seq":      0,
				"approved_at":       clock.Ms(now),
				"remote_ip":         req.RemoteIp,
				"version":           req.Version,
				"last_heartbeat":    nil,
				"missed_heartbeats": 0,
				"xray_version":      "",
				"config_error":      "",
				"config_error_at":   nil,
				"applied_revision":  "",
			})
			if err := affectedOrNotFound(res); err != nil {
				return nil, err
			}

			var m store.MonClient
			if err := tx.First(&m, "id = ?", existingID).Error; err != nil {
				return nil, err
			}
			return &m, nil
		})
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	r.notifyApproved(ctx, mc.Id)
	return mc, nil
}

// notifyApproved runs Hooks.Approved for a mon-client whose approval has
// just committed. A hook failure is logged, not returned: the approval
// itself succeeded and the token has been minted, so reporting an error to
// the administrator would suggest it did not — and the one thing the hook
// does (build a config document) is redone by the next panel revision's
// RebuildAll anyway, as well as on demand by GET /v1/config itself.
func (r *Registry) notifyApproved(ctx context.Context, monClientID string) {
	if r.hooks.Approved == nil {
		return
	}
	if err := r.hooks.Approved(ctx, monClientID); err != nil {
		slog.Warn("registry: building the config of a newly approved mon-client failed",
			"monClientId", monClientID, "err", err)
	}
}

// Reject marks a pending request "rejected" (protocol §2.2); the
// mon-client's own retry policy — wait an hour, try again with a new
// pairing code — lives entirely on its side, mon-server just records the
// administrator's decision.
func (r *Registry) Reject(ctx context.Context, requestID string) error {
	now := r.clock.Now()
	return r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		req, err := loadPendingRequest(tx, requestID, now)
		if err != nil {
			return err
		}
		if req.Status != store.RegistrationPending {
			return ErrRequestNotPending
		}
		return tx.Model(&store.RegistrationRequest{}).
			Where("request_id = ?", requestID).
			Update("status", store.RegistrationRejected).Error
	})
}

// PendingRequests lists every request awaiting a decision, oldest first, for
// the admin UI's requests page (spec §9.2). The expires_at > now half of the
// filter is what keeps an expired-but-unswept row (nobody has polled or
// acted on it since its TTL passed) off this list without needing
// ExpireRequests to have run first.
func (r *Registry) PendingRequests(ctx context.Context) ([]store.RegistrationRequest, error) {
	var reqs []store.RegistrationRequest
	err := r.st.DB.WithContext(ctx).
		Where("status = ? AND expires_at > ?", store.RegistrationPending, clock.Ms(r.clock.Now())).
		Order("created_at ASC").
		Find(&reqs).Error
	return reqs, err
}

// SuggestReplacement implements spec §6's "подсказка": the admin UI
// highlights a pending request as a likely replacement for an existing
// mon-client. MonClient itself only remembers the remote IP it was last
// approved from (RemoteIp), not the hostname it registered with, so:
//   - a public_ip match compares req's declared PublicIp directly against
//     an existing mon-client's RemoteIp;
//   - a hostname match instead looks through RegistrationRequest history —
//     every request this mon-client has ever been approved from — for a
//     prior request with the same Hostname, and resolves that request's
//     MonClientId with one JOIN instead of two round trips. This is what
//     "история" (spec §6) is for: the hostname lives on the request rows,
//     not on the mon-client row, precisely so that history keeps working
//     across an Approve as replacement that changed the box's IP.
//
// Returns (nil, false) when neither matches, which is the common case (a
// genuinely new mon-client) and not an error.
func (r *Registry) SuggestReplacement(ctx context.Context, req *store.RegistrationRequest) (*store.MonClient, bool) {
	if req.PublicIp != "" {
		var mc store.MonClient
		err := r.st.DB.WithContext(ctx).Where("remote_ip = ?", req.PublicIp).First(&mc).Error
		if err == nil {
			return &mc, true
		}
	}

	if req.Hostname != "" {
		var mc store.MonClient
		err := r.st.DB.WithContext(ctx).Raw(`
			SELECT m.* FROM registration_requests r
			JOIN mon_clients m ON m.id = r.mon_client_id
			WHERE r.hostname = ? AND r.request_id <> ?
			ORDER BY r.created_at DESC
			LIMIT 1
		`, req.Hostname, req.RequestId).Scan(&mc).Error
		if err == nil && mc.Id != "" {
			return &mc, true
		}
	}

	return nil, false
}

// ---------------------------------------------------------------------
// Registry management (spec §6)
// ---------------------------------------------------------------------

// List returns every mon-client row for the admin UI's registry page (spec
// §9.3), ordered by id for a stable display.
func (r *Registry) List(ctx context.Context) ([]store.MonClient, error) {
	var clients []store.MonClient
	err := r.st.DB.WithContext(ctx).Order("id ASC").Find(&clients).Error
	return clients, err
}

// Get looks up one mon-client by id, for the admin UI's Edit modal (spec
// §9.3) and for later steps that need one client's current row.
func (r *Registry) Get(ctx context.Context, id string) (*store.MonClient, error) {
	var mc store.MonClient
	if err := r.st.DB.WithContext(ctx).First(&mc, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return &mc, nil
}

// Update changes a mon-client's admin-editable fields (spec §9.3's Edit
// modal: "name, region, paths правятся, id — нет"). When paths actually
// changes, it calls Hooks.PathsChanged so step 5's config builder gives
// this mon-client a new config revision; an Edit that only touches name or
// region does not trigger a rebuild, since neither affects the document
// protocol §4.2 sends.
func (r *Registry) Update(ctx context.Context, id string, name, region string, paths []string) error {
	newPaths, err := validatePaths(paths)
	if err != nil {
		return err
	}

	mc, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	pathsChanged := !samePaths(mc.PathsList(), newPaths)

	mc.SetPaths(newPaths)
	if err := r.st.DB.WithContext(ctx).Model(&store.MonClient{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"name":   name,
			"region": region,
			"paths":  mc.Paths,
		}).Error; err != nil {
		return err
	}

	if pathsChanged && r.hooks.PathsChanged != nil {
		return r.hooks.PathsChanged(ctx, id)
	}
	return nil
}

// samePaths compares two path sets order-independently: admin UI checkboxes
// and a stored JSON array have no meaningful order of their own, so
// ["direct","hops"] and ["hops","direct"] are the same set and must not
// trigger a spurious PathsChanged/config rebuild.
func samePaths(a, b []string) bool {
	as := slices.Clone(a)
	bs := slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

// affectedOrNotFound converts a gorm write result into ErrClientNotFound
// when it matched no row, and passes through any real DB error otherwise —
// the shared tail of every write here keyed by a mon-client id that the
// caller cannot otherwise be sure still exists (SetEnabled, Revoke, Delete,
// ApproveAsReplacement's MonClient update).
func affectedOrNotFound(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrClientNotFound
	}
	return nil
}

// SetEnabled flips a mon-client's Enabled flag (spec §9.3's switch). Turning
// it off calls Hooks.Disabled so step 6's state engine can drive that
// mon-client's targets to UNKNOWN with reason "mon_client_disabled" (spec
// §6); turning it back on triggers no hook — the next heartbeat simply
// starts succeeding again once Authenticate stops returning ErrDisabled.
func (r *Registry) SetEnabled(ctx context.Context, id string, enabled bool) error {
	res := r.st.DB.WithContext(ctx).Model(&store.MonClient{}).
		Where("id = ?", id).
		Update("enabled", enabled)
	if err := affectedOrNotFound(res); err != nil {
		return err
	}
	if !enabled && r.hooks.Disabled != nil {
		return r.hooks.Disabled(ctx, id)
	}
	return nil
}

// Revoke invalidates a mon-client's token without deleting it (spec §6):
// token_hash is cleared so Authenticate answers ErrTokenRevoked for the old
// token, state drops to OFFLINE, and the row (with its history) stays in
// the registry until either a new registration request is approved as a
// replacement, or an administrator deletes it outright. Any approved-but-
// uncollected token still parked on one of this client's registration
// requests is cleared too — Revoke means "this token must stop working
// right now", and a plaintext copy waiting to be handed out by a future
// Poll would defeat that.
//
// The revoke goes through the state machine (decision #51 §2): Hooks.Revoked
// files the mon_client OFFLINE event with reason token_revoked and moves the
// targets to UNKNOWN, all inside this transaction, so the registry row, the
// targets and the events commit — or roll back — together.
func (r *Registry) Revoke(ctx context.Context, id string) error {
	var after func(context.Context)
	err := r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var mc store.MonClient
		if err := tx.First(&mc, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrClientNotFound
			}
			return err
		}
		if r.hooks.Revoked != nil {
			var err error
			if after, err = r.hooks.Revoked(ctx, tx, mc); err != nil {
				return err
			}
		}
		res := tx.Model(&store.MonClient{}).
			Where("id = ?", id).
			Updates(map[string]any{
				"token_hash": "",
				"state":      store.MonClientOffline,
			})
		if err := affectedOrNotFound(res); err != nil {
			return err
		}
		return clearParkedToken(tx, id)
	})
	if err != nil {
		return err
	}
	if after != nil {
		after(ctx)
	}
	return nil
}

// Delete permanently removes a mon-client and its targets (spec §6): unlike
// Revoke, there is nothing left for a replacement approval to attach to
// afterwards — the panel picks up the removal on its next ProbeEnsure
// snapshot and drops the corresponding mon_targets rows itself. Like
// Revoke, any parked-but-uncollected approved token pointing at this id is
// cleared, since nothing will ever collect it now.
func (r *Registry) Delete(ctx context.Context, id string) error {
	return r.st.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := affectedOrNotFound(tx.Where("id = ?", id).Delete(&store.MonClient{})); err != nil {
			return err
		}
		if err := tx.Where("mon_client_id = ?", id).Delete(&store.Target{}).Error; err != nil {
			return err
		}
		return clearParkedToken(tx, id)
	})
}

// clearParkedToken blanks approved_token on any registration request that
// still has one parked for monClientID — the shared tail of Revoke and
// Delete (item 5): both mean the token must never be handed out by a future
// Poll, whether or not a mon-client ever comes back to collect it.
func clearParkedToken(tx *gorm.DB, monClientID string) error {
	return tx.Model(&store.RegistrationRequest{}).
		Where("mon_client_id = ? AND approved_token <> ''", monClientID).
		Update("approved_token", "").Error
}

// Snapshot returns every mon-client row, disabled and revoked ones
// included, for step 3's periodic POST /probe/ensure to the panel. Spec §6
// is explicit that a disabled mon-client is "не исключается" from this
// snapshot — only Delete removes a row from it — which supersedes
// architecture brief §3.5's shorthand ("all *enabled* clients"); that
// brief's wording predates §6 being written out in full, and the panel
// still needs to see (and eventually garbage-collect) a disabled client's
// rows rather than have them vanish and reappear.
func (r *Registry) Snapshot(ctx context.Context) ([]store.MonClient, error) {
	var clients []store.MonClient
	err := r.st.DB.WithContext(ctx).Find(&clients).Error
	return clients, err
}

// ---------------------------------------------------------------------
// Auth (protocol §3)
// ---------------------------------------------------------------------

// Authenticate resolves a client token (already stripped of the "Bearer "
// prefix by internal/api's RequireClientToken) to the mon-client it belongs
// to. It hashes the presented token and looks it up by that hash — the
// plaintext token is never stored (spec §6). An unknown or revoked token is
// ErrTokenRevoked; a known token whose mon-client has been disabled is
// ErrDisabled.
func (r *Registry) Authenticate(ctx context.Context, clientToken string) (*store.MonClient, error) {
	hash := hashToken(clientToken)

	var mc store.MonClient
	err := r.st.DB.WithContext(ctx).Where("token_hash = ?", hash).First(&mc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTokenRevoked
	}
	if err != nil {
		return nil, err
	}
	// No further comparison is needed here: token_hash = ? is an equality
	// lookup of a SHA-256 digest of 32 random bytes, decided by sqlite's
	// index, not by an application-level comparison whose timing could leak
	// anything — there are 2^256 possible hashes and nothing to learn from
	// how long the lookup took. Revoke clears token_hash to "" (never to
	// some other client's hash), and "" can never equal a 64-hex-char
	// digest, so a row this query returns is a genuine, current token by
	// construction.
	if !mc.Enabled {
		return nil, ErrDisabled
	}
	return &mc, nil
}

// ---------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------

// hashToken returns the hex SHA-256 digest of a secret — the only form a
// registration request's or a mon-client's token is ever compared or stored
// by (spec §6: "в БД только SHA-256").
func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// randToken mints n random bytes, base64url-encoded — the shared entropy
// source behind both a registration request's id (128 bits, protocol
// §2.1) and a client token (32 bytes, spec §6).
func randToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("registry: generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// randRequestID mints a registration request's id: 128 bits of randomness,
// base64url-encoded (protocol §2.1), long enough that guessing another
// mon-client's pending requestId is infeasible — it is the only secret a
// mon-client holds before it has a real token.
func randRequestID() (string, error) {
	return randToken(requestIDBytes)
}

// newToken mints a client token — 32 random bytes, base64url-encoded (spec
// §6) — and returns both the plaintext (for the one-time hand-off through
// ApprovedToken) and its hex SHA-256 (the only form ever written to
// mon_clients.token_hash).
func newToken() (token, tokenHash string, err error) {
	token, err = randToken(tokenBytes)
	if err != nil {
		return "", "", err
	}
	return token, hashToken(token), nil
}

// slugify turns an administrator-supplied name into the candidate id spec
// §6 describes: lowercased, every run of characters outside
// [A-Za-z0-9_.-] collapsed to a single "-", leading/trailing "-"/"."
// trimmed, capped to slugMaxLen, and "mon-client" if that leaves nothing at
// all (e.g. a name that is pure punctuation/emoji).
func slugify(name string) string {
	s := strings.ToLower(name)
	s = slugInvalidRun.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > slugMaxLen {
		s = strings.Trim(s[:slugMaxLen], "-")
	}
	if s == "" {
		s = "mon-client"
	}
	return s
}

// uniqueSlug finds a mon-client id that doesn't collide with an existing
// row: slugify(name), then "-2", "-3", ... appended (spec §6) — re-trimming
// and re-capping at slugMaxLen each time, since appending a suffix to an
// already-32-char base would otherwise overflow the column's own limit. It
// fetches every id that could possibly collide — the base itself, or the
// base plus any "-N" suffix — with one query, then picks the first free
// candidate in memory, so approving many mon-clients that all slugify to
// the same base costs one round trip instead of one per candidate tried
// (and, unlike a per-candidate existence check in a loop, never skips
// checking the very last suffix it generates). tx is passed in explicitly
// (rather than reading r.st directly) so Approve can call this from inside
// its own transaction and see requests approved moments earlier by a
// concurrent admin action.
func uniqueSlug(tx *gorm.DB, name string) (string, error) {
	base := slugify(name)

	var taken []string
	if err := tx.Model(&store.MonClient{}).
		Where("id = ? OR id LIKE ? || '-%'", base, base).
		Pluck("id", &taken).Error; err != nil {
		return "", err
	}
	if len(taken) == 0 {
		return base, nil
	}
	used := make(map[string]bool, len(taken))
	for _, id := range taken {
		used[id] = true
	}
	if !used[base] {
		return base, nil
	}

	for i := 2; i < slugSuffixAttempts; i++ {
		suffix := fmt.Sprintf("-%d", i)
		candidate := base
		if len(candidate)+len(suffix) > slugMaxLen {
			candidate = strings.TrimRight(candidate[:slugMaxLen-len(suffix)], "-")
		}
		candidate += suffix
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("registry: could not find a unique slug for %q after %d attempts", name, slugSuffixAttempts)
}
