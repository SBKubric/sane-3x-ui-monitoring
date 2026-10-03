package store

import (
	"encoding/json"
)

// Diagnostic sweep phases (decision #100, contract §4.6): the sweep of one
// mon-client × inbound kind started, its picture changed, or it ended.
const (
	SweepPhaseStart  = "start"
	SweepPhaseChange = "change"
	SweepPhaseEnd    = "end"
)

// SweepFromMonClient is the From of a host reachability check the
// mon-client made itself; any other From is a hop name.
const SweepFromMonClient = "mon-client"

// SweepReport is what one diagnostic sweep found for one mon-client and
// inbound kind (CONTEXT.md: Diagnostic sweep), in the wire form of a
// kind "sweep" event's report (decision #100, contract §4.6): the tunnel
// probe of each path, and the host reachability checks from the mon-client
// to every hop it holds and the real server, and from every hop to its
// next hop.
type SweepReport struct {
	Paths []SweepPath      `json:"paths"`
	Hosts []SweepHostCheck `json:"hosts"`
}

// SweepPath is one path's tunnel probe in a sweep report. Reason is the
// failure's diagnosis and is absent while Ok.
type SweepPath struct {
	Path   string `json:"path"`
	Ok     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// SweepHostCheck is one host reachability check in a sweep report: a
// series of ICMP echoes From (SweepFromMonClient or a hop name) To (a hop
// name, or "" for the real server). At is when it was measured; nil means
// there is no report, and then LastAt may carry the time of the hop's last
// one. RttAvgMs is nil when every echo was lost.
type SweepHostCheck struct {
	From     string `json:"from"`
	To       string `json:"to"`
	At       *int64 `json:"at"`
	LastAt   *int64 `json:"lastAt,omitempty"`
	Sent     int    `json:"sent"`
	LossPct  int    `json:"lossPct"`
	RttAvgMs *int64 `json:"rttAvgMs"`
}

// MarshalJSON writes a check without a report as decision #100 spells it —
// {"from", "to", "at": null} and lastAt when known — rather than with a
// sent and lossPct of 0, which would read as a measured 0% loss.
func (h SweepHostCheck) MarshalJSON() ([]byte, error) {
	if h.At == nil {
		return json.Marshal(struct {
			From   string `json:"from"`
			To     string `json:"to"`
			At     *int64 `json:"at"`
			LastAt *int64 `json:"lastAt,omitempty"`
		}{h.From, h.To, nil, h.LastAt})
	}
	type plain SweepHostCheck
	return json.Marshal(plain(h))
}

// Sweep is the diagnostic sweep in progress for one mon-client and inbound
// kind (decision #100): when it started, whether its start has been
// announced (the first run's report is what the start event carries), its
// place in the schedule, when the next run is due and when the last run
// was handed to the mon-client, and the last report. A row exists exactly
// while the sweep does; it is kept in the database so a restart neither
// loses an ongoing sweep nor announces it a second time.
type Sweep struct {
	Id          int    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	MonClientId string `json:"monClientId" gorm:"column:mon_client_id;not null;size:64;uniqueIndex:idx_ms_sweeps_key,priority:1"`
	InboundKind string `json:"inboundKind" gorm:"column:inbound_kind;not null;size:16;uniqueIndex:idx_ms_sweeps_key,priority:2"`

	StartedAt int64 `json:"startedAt" gorm:"column:started_at;not null"`
	// Announced is whether the start event went out — after the first run
	// reported, since it carries that run's report.
	Announced bool `json:"announced" gorm:"column:announced;not null;default:false"`
	// Step is the index into the run schedule (1, 2, 5, 10, 15 min).
	Step int `json:"step" gorm:"column:step;not null;default:0"`
	// NextAt is when the next run is due.
	NextAt int64 `json:"nextAt" gorm:"column:next_at;not null"`
	// RequestedAt is when the pending run was handed to the mon-client in a
	// heartbeat answer; nil while no run is pending.
	RequestedAt *int64 `json:"requestedAt" gorm:"column:requested_at"`
	// Report is the last run's SweepReport as JSON, "" before the first.
	Report string `json:"report" gorm:"column:report;not null;default:''"`
}

func (Sweep) TableName() string { return "sweeps" }

// ReportValue decodes Report, the zero report for none or a corrupt one.
func (s *Sweep) ReportValue() SweepReport {
	var r SweepReport
	if s.Report != "" {
		_ = json.Unmarshal([]byte(s.Report), &r)
	}
	return r
}

// SetReport encodes r into Report.
func (s *Sweep) SetReport(r SweepReport) {
	b, err := json.Marshal(r)
	if err != nil {
		// A report of strings, bools and ints cannot fail to marshal.
		panic("store: marshal sweep report: " + err.Error())
	}
	s.Report = string(b)
}
