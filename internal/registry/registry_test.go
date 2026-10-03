package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// newTestRegistry opens a fresh temp-file store with a Fake clock (so TTLs
// and the per-IP rate window are driven deterministically, never by
// sleeping) and returns a Registry over it.
func newTestRegistry(t *testing.T) (*Registry, *store.Store, *clock.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	st.Clock = clk
	return New(st, clk), st, clk
}

const validPairingCode = "ABCDEF"

// register is a small helper: Register with a valid pairing code, failing
// the test on error.
func register(t *testing.T, r *Registry, hostname, publicIP, remoteIP string) *RegisterOutput {
	t.Helper()
	out, err := r.Register(context.Background(), RegisterInput{
		PairingCode: validPairingCode,
		Hostname:    hostname,
		PublicIP:    publicIP,
		RemoteIP:    remoteIP,
	})
	if err != nil {
		t.Fatalf("Register(%q, %q): %v", hostname, remoteIP, err)
	}
	return out
}

// approve registers and immediately approves under name, failing the test
// on error. It advances clk by rateLimitWindow first so a series of these
// never trip the per-IP 1/minute throttle against each other.
//
// nil paths approve with the full vocabulary, direct and hops — the
// default before decision #100, which most tests here were written
// against; a test of today's default (edges) passes it explicitly or calls
// Approve itself.
func approve(t *testing.T, r *Registry, clk *clock.Fake, name string, paths []string) *store.MonClient {
	t.Helper()
	if paths == nil {
		paths = []string{store.PathDirect, store.PathHops}
	}
	clk.Advance(rateLimitWindow)
	out := register(t, r, name, "", "198.51.100.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: name, Paths: paths})
	if err != nil {
		t.Fatalf("Approve(%q): %v", name, err)
	}
	return mc
}

// --- Register: rate limits (spec §6) ---

func TestRegister_RejectsBadPairingCode(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	cases := []string{"", "abcdef", "ABCDE", "ABCDEFG", "ABCD01"}
	for _, code := range cases {
		_, err := r.Register(context.Background(), RegisterInput{PairingCode: code, RemoteIP: "1.1.1.1"})
		if !errors.Is(err, ErrInvalidPairingCode) {
			t.Errorf("Register(code=%q) err = %v, want ErrInvalidPairingCode", code, err)
		}
	}
}

func TestRegister_PerIPRateLimit(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	register(t, r, "h1", "", "1.2.3.4")

	_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: "1.2.3.4"})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("second Register from same IP err = %v, want *RateLimitError", err)
	}
	if rl.RetryAfter != rateLimitWindow {
		t.Fatalf("RetryAfter = %v, want %v", rl.RetryAfter, rateLimitWindow)
	}

	clk.Advance(rateLimitWindow)
	if _, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: "1.2.3.4"}); err != nil {
		t.Fatalf("Register after Advance(%v): %v", rateLimitWindow, err)
	}
}

func TestRegister_MaxPendingPerIP(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	ip := "5.6.7.8"
	for i := 0; i < maxPendingPerIP; i++ {
		register(t, r, fmt.Sprintf("h%d", i), "", ip)
		clk.Advance(rateLimitWindow)
	}

	_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: ip})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("4th pending Register err = %v, want *RateLimitError", err)
	}
}

func TestRegister_MaxPendingGlobal(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	for i := 0; i < maxPendingGlobal; i++ {
		register(t, r, "h", "", fmt.Sprintf("10.0.0.%d", i))
	}

	_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: "10.0.1.1"})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("21st global pending Register err = %v, want *RateLimitError", err)
	}
}

func TestRegister_ExpiredPendingsDontCount(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	ip := "9.9.9.9"
	for i := 0; i < maxPendingPerIP; i++ {
		register(t, r, "h", "", ip)
		clk.Advance(rateLimitWindow)
	}

	// let the three pendings, and the 1/min throttle, both clear.
	clk.Advance(requestTTL)

	if _, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: ip}); err != nil {
		t.Fatalf("Register after pendings expired: %v", err)
	}
}

// TestRegister_RetryAfterRoundsUpPerIPWindow checks that the 1/minute-per-IP
// Retry-After is rounded up to a whole second, never truncated (59.2s of
// window remaining must be reported as 60, not 59).
func TestRegister_RetryAfterRoundsUpPerIPWindow(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	register(t, r, "h", "", "7.7.7.7")

	clk.Advance(800 * time.Millisecond) // 59.2s left in the 60s window
	_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: "7.7.7.7"})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	if rl.RetryAfter != 60*time.Second {
		t.Fatalf("RetryAfter = %v, want 60s (ceil of 59.2s)", rl.RetryAfter)
	}
}

// TestRegister_RetryAfterNeverZero checks the other rounding edge: a sliver
// of a second remaining (0.3s) is still at least a whole second, never 0.
func TestRegister_RetryAfterNeverZero(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	register(t, r, "h", "", "8.8.8.8")

	clk.Advance(rateLimitWindow - 300*time.Millisecond) // 0.3s left
	_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: "8.8.8.8"})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	if rl.RetryAfter != time.Second {
		t.Fatalf("RetryAfter = %v, want 1s (ceil of 0.3s, never 0)", rl.RetryAfter)
	}
}

// TestRegister_RetryAfterForPendingCapIsEarliestExpiry checks that hitting
// the per-IP pending cap reports the earliest blocking request's own expiry
// (spec §6), not the fixed fallback — the cap can only free up when one of
// those rows actually expires.
func TestRegister_RetryAfterForPendingCapIsEarliestExpiry(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	ip := "6.6.6.6"
	for i := 0; i < maxPendingPerIP; i++ {
		register(t, r, fmt.Sprintf("h%d", i), "", ip)
		clk.Advance(rateLimitWindow)
	}

	_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: ip})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	// The earliest of the three pending rows was created at t=0 and expires
	// at requestTTL; maxPendingPerIP*rateLimitWindow has elapsed since.
	want := requestTTL - time.Duration(maxPendingPerIP)*rateLimitWindow
	if rl.RetryAfter != want {
		t.Fatalf("RetryAfter = %v, want %v (earliest pending expiry - now)", rl.RetryAfter, want)
	}
}

// TestRegister_ConcurrentSameIPOnlyOneSucceeds checks item 1's atomicity fix:
// firing several Register calls from one IP at once must serialise the
// check-then-insert sequence (via DB.Transaction + SetMaxOpenConns(1)) so
// exactly one passes the 1/minute throttle and every other one is rate
// limited, never all of them racing past the same stale "last request" read.
func TestRegister_ConcurrentSameIPOnlyOneSucceeds(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	const n = 5
	results := make([]error, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: "42.42.42.42"})
			results[i] = err
		}(i)
	}
	wg.Wait()

	var ok, rateLimited int
	for _, err := range results {
		var rl *RateLimitError
		switch {
		case err == nil:
			ok++
		case errors.As(err, &rl):
			rateLimited++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("successful registrations = %d, want 1", ok)
	}
	if rateLimited != n-1 {
		t.Fatalf("rate-limited registrations = %d, want %d", rateLimited, n-1)
	}
}

// TestRegister_ConcurrentDistinctIPsRespectsGlobalCap checks item 1's
// atomicity fix from the other angle: firing more concurrent Register calls
// than maxPendingGlobal allows, each from its own IP (so the per-IP checks
// never trip), must still let through exactly maxPendingGlobal of them.
func TestRegister_ConcurrentDistinctIPsRespectsGlobalCap(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	const n = 25
	results := make([]error, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.10.%d.%d", i/256, i%256)
			_, err := r.Register(context.Background(), RegisterInput{PairingCode: validPairingCode, RemoteIP: ip})
			results[i] = err
		}(i)
	}
	wg.Wait()

	var ok int
	for _, err := range results {
		if err == nil {
			ok++
		}
	}
	if ok != maxPendingGlobal {
		t.Fatalf("successful registrations = %d, want %d", ok, maxPendingGlobal)
	}
}

// --- Poll: TTL and unknown ids ---

func TestPoll_UnknownRequestID(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	_, err := r.Poll(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("Poll err = %v, want ErrRequestNotFound", err)
	}
}

func TestPoll_ExpiredRequest(t *testing.T) {
	r, st, clk := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")

	clk.Advance(requestTTL + time.Second)
	_, err := r.Poll(context.Background(), out.RequestID)
	if !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("Poll err = %v, want ErrRequestExpired", err)
	}

	var req store.RegistrationRequest
	if err := st.DB.First(&req, "request_id = ?", out.RequestID).Error; err != nil {
		t.Fatalf("load request: %v", err)
	}
	if req.Status != store.RegistrationExpired {
		t.Fatalf("status column = %q, want %q", req.Status, store.RegistrationExpired)
	}
}

func TestPoll_PendingAndRejected(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")

	poll, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll (pending): %v", err)
	}
	if poll.Status != "pending" {
		t.Fatalf("status = %q, want pending", poll.Status)
	}

	if err := r.Reject(context.Background(), out.RequestID); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	poll, err = r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll (rejected): %v", err)
	}
	if poll.Status != "rejected" {
		t.Fatalf("status = %q, want rejected", poll.Status)
	}
}

// TestApprove_ExpiredUnsweptRequest checks item 2's mechanism-level fix: a
// pending request whose TTL has passed but nothing has ever swept (no
// Register/Poll/ExpireRequests call has touched it since) must still be
// ErrRequestExpired to Approve, not silently approvable.
func TestApprove_ExpiredUnsweptRequest(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	clk.Advance(requestTTL + time.Second)

	if _, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"}); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("Approve err = %v, want ErrRequestExpired", err)
	}
}

// TestReject_ExpiredUnsweptRequest is TestApprove_ExpiredUnsweptRequest's
// sibling for Reject (item 2: "Reject likewise").
func TestReject_ExpiredUnsweptRequest(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	clk.Advance(requestTTL + time.Second)

	if err := r.Reject(context.Background(), out.RequestID); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("Reject err = %v, want ErrRequestExpired", err)
	}
}

// TestPendingRequests_OmitsExpiredUnsweptRequest checks that
// PendingRequests's own expires_at > now filter keeps an expired-but-
// unswept row off the admin UI's list without needing ExpireRequests to
// have run first (item 2).
func TestPendingRequests_OmitsExpiredUnsweptRequest(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	clk.Advance(requestTTL + time.Second)

	pending, err := r.PendingRequests(context.Background())
	if err != nil {
		t.Fatalf("PendingRequests: %v", err)
	}
	for _, p := range pending {
		if p.RequestId == out.RequestID {
			t.Fatalf("PendingRequests = %+v, want the expired-but-unswept request omitted", pending)
		}
	}
}

// --- Approve: one-time token, defaults, validation ---

func TestPoll_TokenIssuedExactlyOnce(t *testing.T) {
	r, st, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	first, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if first.Status != "approved" || first.MonClientID != mc.Id || first.Token == "" {
		t.Fatalf("first Poll = %+v, want approved with a token and id %q", first, mc.Id)
	}

	second, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if second.Status != "approved" || second.Token != "" {
		t.Fatalf("second Poll = %+v, want approved with an empty token", second)
	}

	var req store.RegistrationRequest
	if err := st.DB.First(&req, "request_id = ?", out.RequestID).Error; err != nil {
		t.Fatalf("load request: %v", err)
	}
	if req.ApprovedToken != "" {
		t.Fatalf("approved_token column = %q, want empty after the first poll", req.ApprovedToken)
	}
}

// TestPoll_UncollectedApprovedTokenExpires checks item 5: an approved
// request whose token nobody collected within requestTTL of approval is
// itself treated as expired — flipped to "expired", its parked plaintext
// token cleared — instead of sitting there indefinitely.
func TestPoll_UncollectedApprovedTokenExpires(t *testing.T) {
	r, st, clk := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	if _, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	clk.Advance(requestTTL + time.Second)

	if _, err := r.Poll(context.Background(), out.RequestID); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("Poll err = %v, want ErrRequestExpired", err)
	}

	var req store.RegistrationRequest
	if err := st.DB.First(&req, "request_id = ?", out.RequestID).Error; err != nil {
		t.Fatalf("load request: %v", err)
	}
	if req.Status != store.RegistrationExpired {
		t.Fatalf("status = %q, want %q", req.Status, store.RegistrationExpired)
	}
	if req.ApprovedToken != "" {
		t.Fatalf("approved_token = %q, want empty", req.ApprovedToken)
	}
}

// TestPoll_ConcurrentHandOffExactlyOnce checks item 6: two concurrent polls
// of a freshly approved request must hand out the token exactly once — the
// single conditional UPDATE keyed on the token's own current value, not a
// bare read-then-clear.
func TestPoll_ConcurrentHandOffExactlyOnce(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	if _, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	const n = 2
	outs := make([]*PollOutput, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outs[i], errs[i] = r.Poll(context.Background(), out.RequestID)
		}(i)
	}
	wg.Wait()

	var withToken int
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Poll[%d]: %v", i, err)
		}
		if outs[i].Token != "" {
			withToken++
		}
	}
	if withToken != 1 {
		t.Fatalf("polls that got a token = %d, want exactly 1", withToken)
	}
}

func TestApprove_CreatesClientWithHashAndDefaults(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")

	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test Client", Region: "eu"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if mc.State != store.MonClientNever {
		t.Fatalf("State = %q, want %q", mc.State, store.MonClientNever)
	}
	if !mc.Enabled {
		t.Fatal("Enabled = false, want true")
	}
	if got := mc.PathsList(); !samePaths(got, []string{store.PathEdges}) {
		t.Fatalf("Paths = %v, want default [edges]", got)
	}

	poll, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	sum := sha256.Sum256([]byte(poll.Token))
	if want := hex.EncodeToString(sum[:]); mc.TokenHash != want {
		t.Fatalf("TokenHash = %q, want sha256(token) = %q", mc.TokenHash, want)
	}
}

// TestApprove_RejectsInvalidPath checks the paths vocabulary of spec §5.1:
// anything but direct, hops or a hop by name is refused — proxy included,
// which left the vocabulary for hops.
func TestApprove_RejectsInvalidPath(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	for i, bad := range [][]string{{"foo"}, {"proxy"}, {"direct", "edge:"}, {"edge:AMS"}, {"middle:x"}} {
		clk.Advance(rateLimitWindow)
		out := register(t, r, "h", "", fmt.Sprintf("1.1.1.%d", i+1))
		_, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test", Paths: bad})
		if !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("Approve(%v) err = %v, want ErrInvalidPath", bad, err)
		}
	}
}

// TestApprove_PathsVocabulary checks what the vocabulary accepts and how it
// is stored: direct, hops and hops by name, a repeat kept once.
func TestApprove_PathsVocabulary(t *testing.T) {
	r, _, clk := newTestRegistry(t)
	mc := approve(t, r, clk, "ams-1", []string{"edge:edge-a", store.PathDirect, "inner:core-1", "edge:edge-a"})
	if got := mc.PathsList(); strings.Join(got, ",") != "edge:edge-a,direct,inner:core-1" {
		t.Fatalf("Paths = %v, want edge:edge-a,direct,inner:core-1", got)
	}
}

func TestApprove_UnknownOrNonPendingRequest(t *testing.T) {
	r, _, _ := newTestRegistry(t)

	_, err := r.Approve(context.Background(), "no-such-id", ApproveInput{Name: "Test"})
	if !errors.Is(err, ErrRequestNotFound) {
		t.Fatalf("Approve(unknown) err = %v, want ErrRequestNotFound", err)
	}

	out := register(t, r, "h", "", "1.1.1.1")
	if _, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"}); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if _, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"}); !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("second Approve err = %v, want ErrRequestNotPending", err)
	}
}

// --- slug rule ---

func TestSlugify(t *testing.T) {
	cases := []struct{ name, want string }{
		{"Amsterdam #1", "amsterdam-1"},
		{"  Moscow  ", "moscow"},
		{"###", "mon-client"},
		{"already-a-slug_1-2", "already-a-slug_1-2"},
		{"msk.1", "msk-1"},
	}
	for _, c := range cases {
		if got := slugify(c.name); got != c.want {
			t.Errorf("slugify(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestApprove_SlugUniqueness(t *testing.T) {
	r, _, clk := newTestRegistry(t)

	mc1 := approve(t, r, clk, "Moscow", nil)
	mc2 := approve(t, r, clk, "Moscow", nil)
	if mc1.Id != "moscow" {
		t.Fatalf("first id = %q, want moscow", mc1.Id)
	}
	if mc2.Id != "moscow-2" {
		t.Fatalf("second id = %q, want moscow-2", mc2.Id)
	}

	long := strings.Repeat("a", 70)
	mc3 := approve(t, r, clk, long, nil)
	if len(mc3.Id) != slugMaxLen {
		t.Fatalf("capped id length = %d, want %d", len(mc3.Id), slugMaxLen)
	}
	mc4 := approve(t, r, clk, long, nil)
	if mc4.Id == mc3.Id {
		t.Fatal("second 70-char-name approval produced the same id as the first")
	}
	if len(mc4.Id) > slugMaxLen {
		t.Fatalf("second capped id length = %d, want <= %d", len(mc4.Id), slugMaxLen)
	}
}

// --- Approve as replacement ---

func TestApproveAsReplacement(t *testing.T) {
	r, _, clk := newTestRegistry(t)

	out1 := register(t, r, "h1", "", "1.1.1.1")
	existing, err := r.Approve(context.Background(), out1.RequestID, ApproveInput{Name: "Amsterdam", Region: "eu", Paths: []string{"hops"}})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll1, err := r.Poll(context.Background(), out1.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	oldToken := poll1.Token

	if _, err := r.Authenticate(context.Background(), oldToken); err != nil {
		t.Fatalf("Authenticate(oldToken) before replacement: %v", err)
	}

	clk.Advance(rateLimitWindow)
	out2 := register(t, r, "h1", "", "2.2.2.2")

	replaced, err := r.ApproveAsReplacement(context.Background(), out2.RequestID, existing.Id)
	if err != nil {
		t.Fatalf("ApproveAsReplacement: %v", err)
	}
	if replaced.Id != existing.Id {
		t.Fatalf("Id = %q, want %q (unchanged)", replaced.Id, existing.Id)
	}
	if replaced.Name != "Amsterdam" || replaced.Region != "eu" {
		t.Fatalf("name/region changed: %+v", replaced)
	}
	if !samePaths(replaced.PathsList(), []string{"hops"}) {
		t.Fatalf("Paths = %v, want [proxy] (unchanged)", replaced.PathsList())
	}
	if replaced.State != store.MonClientNever {
		t.Fatalf("State = %q, want %q", replaced.State, store.MonClientNever)
	}

	if _, err := r.Authenticate(context.Background(), oldToken); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Authenticate(oldToken) after replacement = %v, want ErrTokenRevoked", err)
	}

	poll2, err := r.Poll(context.Background(), out2.RequestID)
	if err != nil {
		t.Fatalf("Poll 2: %v", err)
	}
	if poll2.MonClientID != existing.Id || poll2.Token == "" {
		t.Fatalf("Poll 2 = %+v, want approved id %q with a token", poll2, existing.Id)
	}
	if _, err := r.Authenticate(context.Background(), poll2.Token); err != nil {
		t.Fatalf("Authenticate(newToken): %v", err)
	}
}

// TestApproveAsReplacement_RefreshesIdentityClearsHeartbeatFields checks
// item 4: remote_ip and version come from the *new* request, and every
// heartbeat-derived field the old box left behind (last_heartbeat,
// missed_heartbeats, xray_version, config_error, config_error_at,
// applied_revision) is cleared, so state=NEVER is coherent with "we know
// nothing about this box yet".
func TestApproveAsReplacement_RefreshesIdentityClearsHeartbeatFields(t *testing.T) {
	r, st, clk := newTestRegistry(t)

	out1 := register(t, r, "h1", "", "1.1.1.1")
	existing, err := r.Approve(context.Background(), out1.RequestID, ApproveInput{Name: "Amsterdam"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Simulate the old box having been alive for a while, so there is
	// heartbeat-derived state on the row for ApproveAsReplacement to clear.
	hb := clock.Ms(clk.Now())
	if err := st.DB.Model(&store.MonClient{}).Where("id = ?", existing.Id).Updates(map[string]any{
		"last_heartbeat":    hb,
		"missed_heartbeats": 3,
		"xray_version":      "1.8.0",
		"config_error":      "boom",
		"config_error_at":   hb,
		"applied_revision":  "rev-1",
	}).Error; err != nil {
		t.Fatalf("seed heartbeat fields: %v", err)
	}

	clk.Advance(rateLimitWindow)
	out2, err := r.Register(context.Background(), RegisterInput{
		PairingCode: validPairingCode, Hostname: "h1", Version: "0.2.0", RemoteIP: "2.2.2.2",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	replaced, err := r.ApproveAsReplacement(context.Background(), out2.RequestID, existing.Id)
	if err != nil {
		t.Fatalf("ApproveAsReplacement: %v", err)
	}

	if replaced.RemoteIp != "2.2.2.2" {
		t.Fatalf("RemoteIp = %q, want the new request's IP", replaced.RemoteIp)
	}
	if replaced.Version != "0.2.0" {
		t.Fatalf("Version = %q, want the new request's version", replaced.Version)
	}
	if replaced.LastHeartbeat != nil {
		t.Fatalf("LastHeartbeat = %v, want nil", replaced.LastHeartbeat)
	}
	if replaced.MissedHeartbeats != 0 {
		t.Fatalf("MissedHeartbeats = %d, want 0", replaced.MissedHeartbeats)
	}
	if replaced.XrayVersion != "" {
		t.Fatalf("XrayVersion = %q, want empty", replaced.XrayVersion)
	}
	if replaced.ConfigError != "" {
		t.Fatalf("ConfigError = %q, want empty", replaced.ConfigError)
	}
	if replaced.ConfigErrorAt != nil {
		t.Fatalf("ConfigErrorAt = %v, want nil", replaced.ConfigErrorAt)
	}
	if replaced.AppliedRevision != "" {
		t.Fatalf("AppliedRevision = %q, want empty", replaced.AppliedRevision)
	}
	if replaced.State != store.MonClientNever {
		t.Fatalf("State = %q, want %q", replaced.State, store.MonClientNever)
	}
}

func TestApproveAsReplacement_UnknownExisting(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	_, err := r.ApproveAsReplacement(context.Background(), out.RequestID, "no-such-client")
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("ApproveAsReplacement err = %v, want ErrClientNotFound", err)
	}
}

// --- registry management ---

func TestRevoke(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if err := r.Revoke(context.Background(), mc.Id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := r.Authenticate(context.Background(), poll.Token); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Authenticate after Revoke = %v, want ErrTokenRevoked", err)
	}

	got, err := r.Get(context.Background(), mc.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != store.MonClientOffline {
		t.Fatalf("State = %q, want %q", got.State, store.MonClientOffline)
	}
}

// TestRevoke_ClearsParkedApprovedToken checks item 5's other half: revoking
// a mon-client whose registration request was approved but never polled
// (the plaintext token is still parked in approved_token) must clear that
// column too — Revoke means the token stops working right now, and a
// parked plaintext copy waiting for a future Poll would defeat that.
func TestRevoke_ClearsParkedApprovedToken(t *testing.T) {
	r, st, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// Deliberately not polled: the token stays parked in approved_token.

	if err := r.Revoke(context.Background(), mc.Id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	var req store.RegistrationRequest
	if err := st.DB.First(&req, "request_id = ?", out.RequestID).Error; err != nil {
		t.Fatalf("load request: %v", err)
	}
	if req.ApprovedToken != "" {
		t.Fatalf("approved_token = %q, want empty after Revoke", req.ApprovedToken)
	}
}

func TestSetEnabled_DisableRevokesAccessAndCallsHook(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	var disabledID string
	r.SetHooks(Hooks{Disabled: func(_ context.Context, id string) error {
		disabledID = id
		return nil
	}})

	if err := r.SetEnabled(context.Background(), mc.Id, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if disabledID != mc.Id {
		t.Fatalf("Disabled hook called with %q, want %q", disabledID, mc.Id)
	}

	if _, err := r.Authenticate(context.Background(), poll.Token); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Authenticate after disable = %v, want ErrDisabled", err)
	}
}

func TestSetEnabled_UnknownClient(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	if err := r.SetEnabled(context.Background(), "no-such-client", false); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("SetEnabled err = %v, want ErrClientNotFound", err)
	}
}

func TestSnapshot_IncludesDisabledAndRevokedClients(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if err := r.SetEnabled(context.Background(), mc.Id, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err := r.Revoke(context.Background(), mc.Id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	snap, err := r.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, c := range snap {
		if c.Id == mc.Id {
			return
		}
	}
	t.Fatalf("Snapshot %+v does not include the disabled+revoked client %q", snap, mc.Id)
}

func TestDelete_RemovesClientAndTargets(t *testing.T) {
	r, st, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	targets := []store.Target{
		{MonClientId: mc.Id, InboundKind: store.InboundKindXray, InboundId: 1, Path: store.PathProxy},
		{MonClientId: mc.Id, InboundKind: store.InboundKindXray, InboundId: 1, Path: store.PathDirect},
	}
	for i := range targets {
		if err := st.DB.Create(&targets[i]).Error; err != nil {
			t.Fatalf("seed target: %v", err)
		}
	}

	if err := r.Delete(context.Background(), mc.Id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := r.Get(context.Background(), mc.Id); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrClientNotFound", err)
	}
	var count int64
	if err := st.DB.Model(&store.Target{}).Where("mon_client_id = ?", mc.Id).Count(&count).Error; err != nil {
		t.Fatalf("count targets: %v", err)
	}
	if count != 0 {
		t.Fatalf("targets remaining after Delete = %d, want 0", count)
	}
}

func TestDelete_UnknownClient(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	if err := r.Delete(context.Background(), "no-such-client"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Delete err = %v, want ErrClientNotFound", err)
	}
}

func TestUpdate_PathsChangedHookOnlyFiresOnRealChange(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test", Paths: []string{"hops", "direct"}})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	var calls int
	r.SetHooks(Hooks{PathsChanged: func(_ context.Context, _ string) error {
		calls++
		return nil
	}})

	// Same set, different order: must not count as a change.
	if err := r.Update(context.Background(), mc.Id, "Test", "", []string{"direct", "hops"}); err != nil {
		t.Fatalf("Update (reordered, unchanged): %v", err)
	}
	if calls != 0 {
		t.Fatalf("PathsChanged calls = %d, want 0 for a reordered-but-unchanged set", calls)
	}

	if err := r.Update(context.Background(), mc.Id, "Test", "", []string{"hops"}); err != nil {
		t.Fatalf("Update (changed): %v", err)
	}
	if calls != 1 {
		t.Fatalf("PathsChanged calls = %d, want 1", calls)
	}

	got, err := r.Get(context.Background(), mc.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !samePaths(got.PathsList(), []string{"hops"}) {
		t.Fatalf("Paths after Update = %v, want [hops]", got.PathsList())
	}
}

func TestUpdate_UnknownClient(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	if err := r.Update(context.Background(), "no-such-client", "Name", "", nil); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Update err = %v, want ErrClientNotFound", err)
	}
}

// --- SuggestReplacement ---

func TestSuggestReplacement(t *testing.T) {
	r, st, clk := newTestRegistry(t)

	out1 := register(t, r, "vps-ams-1", "203.0.113.5", "203.0.113.5")
	existing, err := r.Approve(context.Background(), out1.RequestID, ApproveInput{Name: "Amsterdam"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	loadReq := func(id string) *store.RegistrationRequest {
		t.Helper()
		var req store.RegistrationRequest
		if err := st.DB.First(&req, "request_id = ?", id).Error; err != nil {
			t.Fatalf("load request %s: %v", id, err)
		}
		return &req
	}

	clk.Advance(rateLimitWindow)
	byIP := register(t, r, "other-host", "203.0.113.5", "10.0.0.1")
	if mc, ok := r.SuggestReplacement(context.Background(), loadReq(byIP.RequestID)); !ok || mc.Id != existing.Id {
		t.Fatalf("public_ip match = (%v, %v), want (%q, true)", mc, ok, existing.Id)
	}

	clk.Advance(rateLimitWindow)
	byHostname := register(t, r, "vps-ams-1", "198.51.100.9", "10.0.0.2")
	if mc, ok := r.SuggestReplacement(context.Background(), loadReq(byHostname.RequestID)); !ok || mc.Id != existing.Id {
		t.Fatalf("hostname match = (%v, %v), want (%q, true)", mc, ok, existing.Id)
	}

	clk.Advance(rateLimitWindow)
	noMatch := register(t, r, "totally-new-host", "192.0.2.1", "10.0.0.3")
	if mc, ok := r.SuggestReplacement(context.Background(), loadReq(noMatch.RequestID)); ok {
		t.Fatalf("expected no match, got (%v, true)", mc)
	}
}

// --- Authenticate ---

func TestAuthenticate_UnknownAndDisabledTokens(t *testing.T) {
	r, _, _ := newTestRegistry(t)

	if _, err := r.Authenticate(context.Background(), "not-a-real-token"); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Authenticate(garbage) = %v, want ErrTokenRevoked", err)
	}

	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	got, err := r.Authenticate(context.Background(), poll.Token)
	if err != nil {
		t.Fatalf("Authenticate(valid): %v", err)
	}
	if got.Id != mc.Id {
		t.Fatalf("Authenticate returned client %q, want %q", got.Id, mc.Id)
	}

	if err := r.SetEnabled(context.Background(), mc.Id, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, err := r.Authenticate(context.Background(), poll.Token); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Authenticate(disabled) = %v, want ErrDisabled", err)
	}
}

// TestApproveAsReplacement_ResetsLastAckSeqAfterRevoke is decision #51 §1:
// seq belongs to one token generation. The replaced box starts counting at
// seq 1, so a last_ack_seq carried over from the old box would make
// mon-server silently discard every cycle up to it (~1440 a day).
func TestApproveAsReplacement_ResetsLastAckSeqAfterRevoke(t *testing.T) {
	r, st, clk := newTestRegistry(t)

	out1 := register(t, r, "h1", "", "1.1.1.1")
	existing, err := r.Approve(context.Background(), out1.RequestID, ApproveInput{Name: "Amsterdam"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if existing.LastAckSeq != 0 {
		t.Fatalf("new mon-client LastAckSeq = %d, want 0", existing.LastAckSeq)
	}
	if err := st.DB.Model(&store.MonClient{}).Where("id = ?", existing.Id).
		Update("last_ack_seq", 1440).Error; err != nil {
		t.Fatalf("seed last_ack_seq: %v", err)
	}
	if err := r.Revoke(context.Background(), existing.Id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	clk.Advance(rateLimitWindow)
	out2 := register(t, r, "h1", "", "2.2.2.2")
	replaced, err := r.ApproveAsReplacement(context.Background(), out2.RequestID, existing.Id)
	if err != nil {
		t.Fatalf("ApproveAsReplacement: %v", err)
	}
	if replaced.LastAckSeq != 0 {
		t.Fatalf("LastAckSeq = %d after replacement, want 0 (a new token starts a new seq generation)", replaced.LastAckSeq)
	}
}

// TestRevoke_RevokedHookRunsInTheTransaction pins decision #51 §2's seam:
// the hook (the state engine) sees the mon-client as it was before the
// revoke — it needs the from-state for the event — and its writes share
// the revoke's transaction, so a failing hook leaves the token working.
// The follow-up it returns runs only after the commit.
func TestRevoke_RevokedHookRunsInTheTransaction(t *testing.T) {
	r, st, _ := newTestRegistry(t)
	out := register(t, r, "h", "", "1.1.1.1")
	mc, err := r.Approve(context.Background(), out.RequestID, ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	poll, err := r.Poll(context.Background(), out.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if err := st.DB.Model(&store.MonClient{}).Where("id = ?", mc.Id).
		Update("state", store.MonClientOnline).Error; err != nil {
		t.Fatalf("seed state: %v", err)
	}

	hookErr := errors.New("engine refused")
	r.SetHooks(Hooks{Revoked: func(_ context.Context, _ *gorm.DB, _ store.MonClient) (func(context.Context), error) {
		return nil, hookErr
	}})
	if err := r.Revoke(context.Background(), mc.Id); !errors.Is(err, hookErr) {
		t.Fatalf("Revoke err = %v, want the hook's error", err)
	}
	if _, err := r.Authenticate(context.Background(), poll.Token); err != nil {
		t.Fatalf("Authenticate after a rolled-back Revoke = %v, want the token still valid", err)
	}

	var seen store.MonClient
	var committedWhenAfterRan string
	r.SetHooks(Hooks{Revoked: func(_ context.Context, tx *gorm.DB, row store.MonClient) (func(context.Context), error) {
		seen = row
		return func(context.Context) {
			var now store.MonClient
			if err := st.DB.First(&now, "id = ?", row.Id).Error; err == nil {
				committedWhenAfterRan = now.State
			}
		}, nil
	}})
	if err := r.Revoke(context.Background(), mc.Id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if seen.Id != mc.Id || seen.State != store.MonClientOnline {
		t.Fatalf("hook saw %+v, want %s as it was before the revoke (ONLINE)", seen, mc.Id)
	}
	if committedWhenAfterRan != store.MonClientOffline {
		t.Fatalf("follow-up saw state %q, want it to run after the commit (OFFLINE)", committedWhenAfterRan)
	}
	if _, err := r.Authenticate(context.Background(), poll.Token); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("Authenticate after Revoke = %v, want ErrTokenRevoked", err)
	}
}
