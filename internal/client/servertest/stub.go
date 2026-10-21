// Package servertest is an httptest implementation of mon-server's side of
// mon-protocol.md, for every mon-client package's own tests. It exists for
// exactly the reason internal/panel/paneltest exists on the mon-server
// side: every mon-client package that talks to mon-server — registration
// (step 2), config (step 3, 8), the probe cycle (step 5, 6) and the
// heartbeat loop (step 7) — needs to be testable without a real
// mon-server, and a hand-rolled fake per package would drift from the
// protocol one package at a time.
//
// It runs over TLS (httptest.NewTLSServer) because mon-protocol.md §1
// requires HTTPS on every route and a mon-client that only ever spoke to a
// plaintext stub could not exercise the certificate-trust seam
// (Stub.HTTPClient() hands back a client that trusts exactly this server's
// certificate, standing in for a mon-client's own "trust the system CAs"
// in production, spec §2).
package servertest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// RecordedRequest is one request the stub received, kept regardless of how
// it was answered — a test asserting "mon-client sent exactly this pairing
// code" needs to see the request even if the stub was told to fail it.
type RecordedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// registration is one pending/approved/rejected/expired registration
// request (protocol §2.1, §2.2).
type registration struct {
	status      string // "pending" | "approved" | "rejected" | "expired"
	monClientID string
	token       string
	tokenIssued bool // protocol §2.2: the token is handed out exactly once
}

// Stub is a programmable mon-server. Every knob is mutex-protected because
// the component under test usually drives it from its own goroutine (the
// probe cycle, the heartbeat loop) while the test body reprograms it.
type Stub struct {
	srv *httptest.Server
	mu  sync.Mutex

	requests []RecordedRequest

	// registration (protocol §2)
	registerStatus     int // 0 = normal 202; else a forced status (e.g. 429)
	registerRetryAfter time.Duration
	failRegisterN      int // >0: this many POST /v1/register answer failRegisterStatus
	failRegisterStatus int
	failPollN          int // >0: this many polls answer failPollStatus
	failPollStatus     int
	registrations      map[string]*registration
	validTokens        map[string]string // token -> monClientId, for authenticate

	// auth override (protocol §3): forces every authenticated route
	tokenStatus int // 0 = check validTokens normally; else 401 or 403 always

	// config (protocol §4.2)
	configDoc    *proto.ConfigDoc
	configStatus int // 0 = serve configDoc normally; else a forced status

	// heartbeat (protocol §5.3)
	heartbeats          []proto.HeartbeatRequest
	revision            string
	failHeartbeatN      int
	failHeartbeatStatus int
	dropHeartbeatN      int
	// lastAck is mon-server's last_ack_seq per monClientId: ackSeq never
	// goes below it, and cycles at or below it are the duplicates
	// mon-server drops (spec §7.1 step 3).
	lastAck map[string]int64
	// sweep is the diagnostic sweep job the next heartbeat answer carries.
	sweep *proto.SweepJob

	// tunnel probe (protocol §5.2)
	probeNonceOverride *string
	hangProbeN         int
}

// NewStub starts a mon-server stub on a loopback TLS port and registers
// its shutdown with t.
func NewStub(t testing.TB) *Stub {
	t.Helper()
	s := &Stub{
		registrations: map[string]*registration{},
		validTokens:   map[string]string{},
		lastAck:       map[string]int64{},
	}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the stub's base URL, the form api.New's baseURL expects (spec §2:
// "https://<ip>:443").
func (s *Stub) URL() string { return s.srv.URL }

// HTTPClient returns an *http.Client that trusts the stub's own
// certificate — standing in for a mon-client's "trust the system CAs" in
// production (spec §2), since httptest's self-signed certificate is not in
// any real trust store.
func (s *Stub) HTTPClient() *http.Client {
	return s.srv.Client()
}

// Requests returns every request the stub saw, in arrival order.
func (s *Stub) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RecordedRequest(nil), s.requests...)
}

// RegisterStatus forces every POST /v1/register to answer with this status
// instead of the normal 202 (e.g. 429 for the rate-limit path, protocol
// §2.1). retryAfter is only sent as the Retry-After header when status is
// 429; pass 0 to stop forcing a status.
func (s *Stub) RegisterStatus(status int, retryAfter time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registerStatus = status
	s.registerRetryAfter = retryAfter
}

// FailNextRegisters makes the next n POST /v1/register answer status and
// the ones after that behave normally — the counted twin of
// RegisterStatus. Counted rather than sticky because spec §3.2's backoff
// ladder is about a *streak* of failures ending: a test that has to flip a
// sticky knob back mid-flight races the loop it is driving, while "the
// next two fail" is decided before the loop starts and cannot race.
func (s *Stub) FailNextRegisters(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRegisterN, s.failRegisterStatus = n, status
}

// FailNextPolls is FailNextRegisters for GET /v1/register/<requestId>: the
// next n polls answer status (a 5xx from a mon-server that is up but
// unhappy), whatever the request's real state is. A 410 is better spelled
// Expire, which is what mon-server would really do.
func (s *Stub) FailNextPolls(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPollN, s.failPollStatus = n, status
}

// Approve marks requestID approved, to be handed out with monClientID and
// token on the next poll (protocol §2.2). It also registers token as valid
// for every authenticated route, standing in for mon-server actually
// issuing the client token at approval time. Like mon-server, it resets
// the mon-client's last_ack_seq: seq belongs to one token generation
// (decision #51 §1).
func (s *Stub) Approve(requestID, monClientID, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrations[requestID] = &registration{status: "approved", monClientID: monClientID, token: token}
	s.validTokens[token] = monClientID
	delete(s.lastAck, monClientID)
}

// Reject marks requestID rejected (protocol §2.2: mon-client waits an hour
// and files a new request with a new pairing code).
func (s *Stub) Reject(requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.registrations[requestID]; ok {
		r.status = "rejected"
	}
}

// Expire marks requestID expired: every subsequent poll answers 410
// (protocol §2.1's 5-minute TTL, forced here instead of waited out).
func (s *Stub) Expire(requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.registrations[requestID]; ok {
		r.status = "expired"
	}
}

// SetTokenStatus forces every authenticated route (/v1/config,
// /v1/heartbeat, /v1/probe) to answer 401 or 403 regardless of the bearer
// token presented — protocol §2.3's revoke and §3's disable, without a
// test needing to know which token was actually issued. 0 restores the
// normal validTokens check.
func (s *Stub) SetTokenStatus(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenStatus = status
}

// SetConfig programs GET /v1/config's document (protocol §4.2). Passing
// nil goes back to "no config built yet", which the stub answers as 503
// config_not_ready — mirroring mon-server's own registry.ErrNoConfig
// before its first successful panel poll.
func (s *Stub) SetConfig(doc *proto.ConfigDoc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configDoc = doc
}

// SetConfigStatus forces GET /v1/config to answer with this status instead
// of serving the programmed document (0 restores normal serving).
func (s *Stub) SetConfigStatus(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configStatus = status
}

// Heartbeats returns every heartbeat body the stub accepted, in arrival
// order — including ones later told to fail is not the case: only
// successfully-answered heartbeats are recorded here, since RecordedRequest
// already carries every raw body regardless of outcome.
func (s *Stub) Heartbeats() []proto.HeartbeatRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]proto.HeartbeatRequest(nil), s.heartbeats...)
}

// SetRevision sets the configRevision every heartbeat response carries
// (protocol §5.3) — a test drives a revision change by calling this
// between two heartbeats.
func (s *Stub) SetRevision(rev string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revision = rev
}

// FailNextHeartbeats makes the next n POST /v1/heartbeat requests answer
// with status instead of 200 — protocol §5.3/§6's "heartbeat not
// acknowledged" path (5xx), exercised without a network failure.
func (s *Stub) FailNextHeartbeats(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failHeartbeatN = n
	s.failHeartbeatStatus = status
}

// DropNextHeartbeats hijacks and closes the connection for the next n
// heartbeats, producing a transport error rather than an HTTP status — the
// other half of protocol §5.3's "not acknowledged" (network failure this
// time, not a 5xx).
func (s *Stub) DropNextHeartbeats(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropHeartbeatN = n
}

// SetProbeNonce makes GET /v1/probe always echo wrong instead of the nonce
// it was actually sent, forcing the probe's http_error path (protocol
// §5.2, spec §5: "не 200 или чужой nonce") without needing a mismatched
// client. Passing "" restores echoing the real nonce.
func (s *Stub) SetProbeNonce(wrong string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if wrong == "" {
		s.probeNonceOverride = nil
		return
	}
	s.probeNonceOverride = &wrong
}

// HangNextProbes makes the next n GET /v1/probe requests never answer —
// they block until the request's own context is cancelled — forcing the
// caller's probe_timeout/tcp_timeout path (spec §5) without a real slow
// network.
func (s *Stub) HangNextProbes(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hangProbeN = n
}

// serve is the whole stub: record, then route. Requests are recorded
// before authentication or any injected failure, exactly like paneltest,
// so a test can see what was attempted even when the stub was told to
// refuse it.
func (s *Stub) serve(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)

	s.mu.Lock()
	s.requests = append(s.requests, RecordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Header: r.Header.Clone(),
		Body:   body,
	})
	s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/register":
		s.handleRegister(w, body)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/register/"):
		s.handlePoll(w, strings.TrimPrefix(r.URL.Path, "/v1/register/"))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/config":
		s.handleConfig(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/heartbeat":
		s.handleHeartbeat(w, r, body)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/probe":
		s.handleProbe(w, r)
	default:
		writeErr(w, http.StatusNotFound, "not_found", "unknown route "+r.Method+" "+r.URL.Path)
	}
}

// handleRegister implements POST /v1/register (protocol §2.1).
func (s *Stub) handleRegister(w http.ResponseWriter, body []byte) {
	s.mu.Lock()
	if s.failRegisterN > 0 {
		s.failRegisterN--
		status := s.failRegisterStatus
		s.mu.Unlock()
		writeErr(w, status, injectedCode(status), "injected failure")
		return
	}
	if s.registerStatus != 0 {
		status, retry := s.registerStatus, s.registerRetryAfter
		s.mu.Unlock()
		if status == http.StatusTooManyRequests && retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
		}
		writeErr(w, status, injectedCode(status), "injected failure")
		return
	}
	s.mu.Unlock()

	var in proto.RegisterRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	id := newRequestID()
	s.mu.Lock()
	s.registrations[id] = &registration{status: "pending"}
	s.mu.Unlock()

	writeJSON(w, http.StatusAccepted, proto.RegisterResponse{
		RequestID:   id,
		PollAfterMs: 10000,
		ExpiresAt:   time.Now().Add(5 * time.Minute).UnixMilli(),
	})
}

// handlePoll implements GET /v1/register/<requestId> (protocol §2.2). An
// approved request hands out its token exactly once, mirroring
// mon-server's own one-time hand-off (internal/registry.Poll).
func (s *Stub) handlePoll(w http.ResponseWriter, requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failPollN > 0 {
		s.failPollN--
		writeErr(w, s.failPollStatus, injectedCode(s.failPollStatus), "injected failure")
		return
	}

	reg, ok := s.registrations[requestID]
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}

	switch reg.status {
	case "pending":
		writeJSON(w, http.StatusOK, proto.PollResponse{Status: "pending"})
	case "rejected":
		writeJSON(w, http.StatusOK, proto.PollResponse{Status: "rejected"})
	case "expired":
		writeErr(w, http.StatusGone, "request_expired", "registration request expired")
	case "approved":
		out := proto.PollResponse{Status: "approved", MonClientID: reg.monClientID}
		if !reg.tokenIssued {
			out.Token = reg.token
			reg.tokenIssued = true
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// authenticate implements protocol §3 for every route but /v1/register*:
// SetTokenStatus, when set, overrides the outcome unconditionally (a test
// simulating revoke/disable should not also need a valid-looking token);
// otherwise the bearer token must be one Approve handed out.
func (s *Stub) authenticate(r *http.Request) (monClientID string, failStatus int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tokenStatus != 0 {
		return "", s.tokenStatus
	}

	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return "", http.StatusUnauthorized
	}
	id, ok := s.validTokens[token]
	if !ok {
		return "", http.StatusUnauthorized
	}
	return id, 0
}

// handleConfig implements GET /v1/config (protocol §4.2).
func (s *Stub) handleConfig(w http.ResponseWriter, r *http.Request) {
	if _, failStatus := s.authenticate(r); failStatus != 0 {
		writeErr(w, failStatus, authCode(failStatus), "injected auth failure")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.configStatus != 0 {
		writeErr(w, s.configStatus, injectedCode(s.configStatus), "injected failure")
		return
	}
	if s.configDoc == nil {
		writeErr(w, http.StatusServiceUnavailable, "config_not_ready", "no config has been built yet")
		return
	}
	writeJSON(w, http.StatusOK, s.configDoc)
}

// SetLastAckSeq programs mon-server's remembered last_ack_seq for one
// mon-client — a box that lost its cycles.json and state.json behind a
// mon-server that still remembers the seqs it acknowledged.
// SetSweep makes the next heartbeat answer ask for a diagnostic sweep run
// (decision #100); only that one answer carries it.
func (s *Stub) SetSweep(job *proto.SweepJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep = job
}

func (s *Stub) SetLastAckSeq(monClientID string, seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAck[monClientID] = seq
}

// handleHeartbeat implements POST /v1/heartbeat (protocol §5.3): ackSeq is
// the highest seq among the cycles in this request or mon-server's own
// last_ack_seq, whichever is higher, mirroring mon-server taking
// responsibility for everything it was just sent (spec §7.1 step 4).
func (s *Stub) handleHeartbeat(w http.ResponseWriter, r *http.Request, body []byte) {
	monClientID, failStatus := s.authenticate(r)
	if failStatus != 0 {
		writeErr(w, failStatus, authCode(failStatus), "injected auth failure")
		return
	}

	s.mu.Lock()
	if s.dropHeartbeatN > 0 {
		s.dropHeartbeatN--
		s.mu.Unlock()
		hijackClose(w)
		return
	}
	if s.failHeartbeatN > 0 {
		s.failHeartbeatN--
		status := s.failHeartbeatStatus
		s.mu.Unlock()
		writeErr(w, status, injectedCode(status), "injected failure")
		return
	}
	s.mu.Unlock()

	var hb proto.HeartbeatRequest
	if err := json.Unmarshal(body, &hb); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	s.mu.Lock()
	ackSeq := s.lastAck[monClientID]
	for _, c := range hb.Cycles {
		if c.Seq > ackSeq {
			ackSeq = c.Seq
		}
	}
	s.lastAck[monClientID] = ackSeq
	s.heartbeats = append(s.heartbeats, hb)
	rev := s.revision
	sweep := s.sweep
	s.sweep = nil
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, proto.HeartbeatResponse{
		ConfigRevision: rev,
		ServerTs:       time.Now().UnixMilli(),
		AckSeq:         ackSeq,
		Sweep:          sweep,
	})
}

// handleProbe implements GET /v1/probe (protocol §5.2).
func (s *Stub) handleProbe(w http.ResponseWriter, r *http.Request) {
	if _, failStatus := s.authenticate(r); failStatus != 0 {
		writeErr(w, failStatus, authCode(failStatus), "injected auth failure")
		return
	}

	s.mu.Lock()
	hang := false
	if s.hangProbeN > 0 {
		s.hangProbeN--
		hang = true
	}
	nonceOverride := s.probeNonceOverride
	s.mu.Unlock()

	if hang {
		<-r.Context().Done()
		return
	}

	nonce := r.URL.Query().Get("n")
	if nonceOverride != nil {
		nonce = *nonceOverride
	}

	writeJSON(w, http.StatusOK, proto.ProbeEcho{
		Nonce:    nonce,
		EgressIp: hostOf(r.RemoteAddr),
		ServerTs: time.Now().UnixMilli(),
	})
}

// newRequestID mints a registration request id (protocol §2.1: "128 бит,
// base64url").
func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is a broken host, not a condition any caller
		// can meaningfully recover from — every other stub in this repo
		// (paneltest) treats an unrecoverable internal error the same way.
		panic("servertest: crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// hostOf strips the port off a RemoteAddr (host:port), for the probe
// echo's egressIp field.
func hostOf(remoteAddr string) string {
	if i := strings.LastIndex(remoteAddr, ":"); i != -1 {
		return remoteAddr[:i]
	}
	return remoteAddr
}

// authCode names the auth failure with the code the real handler uses
// (internal/api/auth.go): 401 is always token_revoked, 403 always
// disabled.
func authCode(status int) string {
	if status == http.StatusForbidden {
		return "disabled"
	}
	return "token_revoked"
}

// injectedCode names an injected failure with a representative snake_case
// code, so a test asserting on the decoded error body sees something
// plausible rather than an empty string.
func injectedCode(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "too_many_requests"
	case http.StatusServiceUnavailable:
		return "config_not_ready"
	case http.StatusBadRequest:
		return "bad_request"
	default:
		return "internal"
	}
}

func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	defer func() { _ = r.Body.Close() }()
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// hijackClose takes the connection away from net/http and closes it
// without writing a response — the closest a stub can get to a mon-server
// that dropped the connection mid-request (protocol §5.3's "сеть" failure
// mode).
func hijackClose(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}
