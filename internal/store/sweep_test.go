package store

import (
	"encoding/json"
	"testing"
)

// TestSweepEvent_Wire is the kind "sweep" event of decision #100 as POST
// /events sends it: phase and report, no inbound id or path, a host check
// without a report spelled {"from", "to", "at": null} plus lastAt when
// known — never a measured-looking 0% — and one with a report in full.
func TestSweepEvent_Wire(t *testing.T) {
	at, last, rtt := int64(1757721540000), int64(1757721180000), int64(2)
	ev := EventPayload{
		ID: "019254a0-cd55-7274-8a61-6e7f8091a2b3", Ts: at, Kind: "sweep",
		MonClientID: "ams-1", InboundKind: InboundKindAwg, Phase: SweepPhaseStart,
		Report: &SweepReport{
			Paths: []SweepPath{{Path: "edge:proxy", Reason: "awg_no_handshake"}, {Path: "direct", Ok: true}},
			Hosts: []SweepHostCheck{
				{From: SweepFromMonClient, To: "proxy", At: &at, Sent: 10, RttAvgMs: &rtt},
				{From: "proxy", To: "bridge", LastAt: &last},
				{From: "bridge", To: ""},
			},
		},
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"id":"019254a0-cd55-7274-8a61-6e7f8091a2b3","ts":1757721540000,"kind":"sweep","monClientId":"ams-1","inboundKind":"awg",` +
		`"from":"","to":"","reason":"","notified":false,"phase":"start","report":{"paths":[{"path":"edge:proxy","ok":false,"reason":"awg_no_handshake"},{"path":"direct","ok":true}],` +
		`"hosts":[{"from":"mon-client","to":"proxy","at":1757721540000,"sent":10,"lossPct":0,"rttAvgMs":2},` +
		`{"from":"proxy","to":"bridge","at":null,"lastAt":1757721180000},{"from":"bridge","to":"","at":null}]}}`
	if string(raw) != want {
		t.Fatalf("wire =\n%s\nwant\n%s", raw, want)
	}

	var back EventPayload
	if err := json.Unmarshal(raw, &back); err != nil || back.Report == nil || back.Report.Hosts[1].LastAt == nil || back.Report.Hosts[2].At != nil {
		t.Fatalf("round trip = %+v (%v), want the report back", back, err)
	}
}
