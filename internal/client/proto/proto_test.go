package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// int64Ptr and strPtr are the tests' shorthand for the pointer fields
// Result and ClientInfo use to distinguish "not measured" from a measured
// zero.
func int64Ptr(v int64) *int64 { return &v }
func strPtr(v string) *string { return &v }

// TestTargetKey_StringAndParseRoundTrip checks the ?target= form the
// tunnel probe uses (protocol §5.2) round-trips through String/ParseTargetKey.
func TestTargetKey_StringAndParseRoundTrip(t *testing.T) {
	k := TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"}
	if got, want := k.String(), "xray:12:proxy"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	got, err := ParseTargetKey("xray:12:proxy")
	if err != nil {
		t.Fatalf("ParseTargetKey: %v", err)
	}
	if got != k {
		t.Fatalf("ParseTargetKey round-trip = %+v, want %+v", got, k)
	}
}

// TestParseTargetKey_Malformed checks the shapes ParseTargetKey must reject:
// too few parts, a non-numeric or negative inboundId, and a path outside
// the grammar (protocol §4.2) — which is also what a fourth part is.
func TestParseTargetKey_Malformed(t *testing.T) {
	for _, s := range []string{"", "xray:12", "xray:12:proxy:extra", "xray:notanumber:proxy", "xray:-1:proxy",
		"xray:12:hops", "xray:12:edge:", "xray:12:middle:x", "xray:12:edge:AMS", "xray:12:edge:a:b"} {
		if _, err := ParseTargetKey(s); err == nil {
			t.Errorf("ParseTargetKey(%q) = nil error, want error", s)
		}
	}
}

// TestHeartbeatRequest_MarshalsToProtocolShape marshals a HeartbeatRequest
// built to mirror mon-protocol.md §5.3's own example byte-for-byte (modulo
// key order, which encoding/json does not guarantee, so this test decodes
// both sides into map[string]any instead of comparing strings) — the seam
// mon-server's internal/state.HeartbeatRequest independently decodes.
func TestHeartbeatRequest_MarshalsToProtocolShape(t *testing.T) {
	hb := HeartbeatRequest{
		MonClientID:    "ams-1",
		ConfigRevision: "3a91c0de77b1f2e4",
		Client: ClientInfo{
			Version:     "0.1.0",
			XrayVersion: "26.3.27",
			UptimeMs:    86400000,
			ConfigError: nil,
		},
		Cycles: []Cycle{
			{
				Seq: 1441, Ts: 1757721600000, Unverified: false,
				Results: []Result{
					{
						TargetKey:   TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"},
						Ok:          true,
						ConnectMs:   int64Ptr(3),
						TlsMs:       int64Ptr(47),
						TtfbMs:      int64Ptr(39),
						HandshakeMs: nil,
						EgressIp:    strPtr("203.0.113.10"),
						Reason:      nil,
						Detail:      nil,
					},
					{
						TargetKey:   TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"},
						Ok:          false,
						ConnectMs:   nil,
						TlsMs:       nil,
						TtfbMs:      nil,
						HandshakeMs: nil,
						EgressIp:    nil,
						Reason:      strPtr("awg_no_handshake"),
						Detail:      strPtr("last_handshake_time=0 after 30000ms, 6 handshake attempts"),
					},
				},
			},
		},
	}

	raw, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const protocolExample = `{
  "monClientId": "ams-1", "configRevision": "3a91c0de77b1f2e4",
  "client": {"version": "0.1.0", "xrayVersion": "26.3.27", "uptimeMs": 86400000, "configError": null},
  "cycles": [
    {"seq": 1441, "ts": 1757721600000, "unverified": false, "results": [
      {"inboundKind": "xray", "inboundId": 12, "path": "proxy", "ok": true,
       "connectMs": 3, "tlsMs": 47, "ttfbMs": 39, "handshakeMs": null, "egressIp": "203.0.113.10", "reason": null, "detail": null},
      {"inboundKind": "awg", "inboundId": 0, "path": "proxy", "ok": false,
       "connectMs": null, "tlsMs": null, "ttfbMs": null, "handshakeMs": null, "egressIp": null,
       "reason": "awg_no_handshake", "detail": "last_handshake_time=0 after 30000ms, 6 handshake attempts"}
    ]}
  ]
}`

	var got, want any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal produced JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(protocolExample), &want); err != nil {
		t.Fatalf("unmarshal protocol example: %v", err)
	}

	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("marshalled HeartbeatRequest does not match protocol §5.3 shape:\n got:  %s\n want: %s", gotJSON, wantJSON)
	}
}

// TestConfigDoc_DecodesProtocolExample checks ConfigDoc against
// mon-protocol.md §4.2's own example document verbatim.
func TestConfigDoc_DecodesProtocolExample(t *testing.T) {
	const protocolExample = `{
  "configRevision": "3a91c0de77b1f2e4",
  "monClientId": "ams-1",
  "probeUrl": "https://203.0.113.10:443/v1/probe",
  "probe": {"intervalMs": 60000, "budgetMs": 20000, "connectMs": 5000, "tlsMs": 10000, "headersMs": 10000, "startJitterMs": 5000, "heartbeatTimeoutMs": 10000},
  "targets": [
    {"inboundKind": "xray", "inboundId": 12, "path": "proxy",  "protocol": "vless", "link": "vless://x@front.example.net:443?security=reality#probe-12"},
    {"inboundKind": "xray", "inboundId": 12, "path": "direct", "protocol": "vless", "link": "vless://x@203.0.113.10:443?security=none#probe-12"},
    {"inboundKind": "awg",  "inboundId": 0,  "path": "proxy",  "protocol": "awg",   "conf": "[Interface]\n...\n[Peer]\nEndpoint = front.example.net:51820\n..."}
  ]
}`

	var doc ConfigDoc
	if err := json.Unmarshal([]byte(protocolExample), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if doc.ConfigRevision != "3a91c0de77b1f2e4" {
		t.Errorf("ConfigRevision = %q", doc.ConfigRevision)
	}
	if doc.MonClientID != "ams-1" {
		t.Errorf("MonClientID = %q", doc.MonClientID)
	}
	if doc.ProbeURL != "https://203.0.113.10:443/v1/probe" {
		t.Errorf("ProbeURL = %q", doc.ProbeURL)
	}
	wantProbe := ProbeParams{IntervalMs: 60000, BudgetMs: 20000, ConnectMs: 5000, TlsMs: 10000, HeadersMs: 10000, StartJitterMs: 5000, HeartbeatTimeoutMs: 10000}
	if doc.Probe != wantProbe {
		t.Errorf("Probe = %+v, want %+v", doc.Probe, wantProbe)
	}
	if len(doc.Targets) != 3 {
		t.Fatalf("len(Targets) = %d, want 3", len(doc.Targets))
	}
	xrayProxy := doc.Targets[0]
	wantKey := TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"}
	if xrayProxy.TargetKey != wantKey {
		t.Errorf("Targets[0].TargetKey = %+v, want %+v", xrayProxy.TargetKey, wantKey)
	}
	if xrayProxy.Protocol != "vless" || xrayProxy.Link == "" || xrayProxy.Conf != "" {
		t.Errorf("Targets[0] = %+v, want vless link, no conf", xrayProxy)
	}
	awg := doc.Targets[2]
	if awg.TargetKey != (TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}) {
		t.Errorf("Targets[2].TargetKey = %+v", awg.TargetKey)
	}
	if awg.Conf == "" || awg.Link != "" {
		t.Errorf("Targets[2] = %+v, want conf, no link", awg)
	}
}

// TestClientInfo_RejectedTargetsShape pins protocol §5.3's
// client.rejectedTargets (decision #53 п. 3): a list of {target, error}
// with the target in its `<kind>:<inboundId>:<path>` form, and absent
// altogether when every target was applied — an empty list and no list
// mean the same thing, and a box with nothing rejected sends neither.
func TestClientInfo_RejectedTargetsShape(t *testing.T) {
	info := ClientInfo{
		Version: "0.1.0",
		RejectedTargets: []RejectedTarget{{
			Target: TargetKey{InboundKind: "awg", InboundID: 3, Path: "direct"}.String(),
			Error:  `[Interface] has an unknown key "Foo"`,
		}},
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"rejectedTargets":[{"target":"awg:3:direct","error":"[Interface] has an unknown key \"Foo\""}]`; !strings.Contains(string(raw), want) {
		t.Errorf("client block = %s, want it to carry %s", raw, want)
	}

	raw, err = json.Marshal(ClientInfo{Version: "0.1.0"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), "rejectedTargets") {
		t.Errorf("client block = %s, want no rejectedTargets when nothing was rejected", raw)
	}
}

// TestParseTargetKey_HopPaths checks protocol §5.2's split into at most
// three parts: a hop path keeps its own ':' and round-trips through String.
func TestParseTargetKey_HopPaths(t *testing.T) {
	for _, path := range []string{"direct", "proxy", "edge:ams-1", "inner:core-1"} {
		k := TargetKey{InboundKind: "awg", InboundID: 0, Path: path}
		got, err := ParseTargetKey(k.String())
		if err != nil {
			t.Fatalf("ParseTargetKey(%q): %v", k.String(), err)
		}
		if got != k {
			t.Fatalf("ParseTargetKey(%q) = %+v, want %+v", k.String(), got, k)
		}
	}
}
