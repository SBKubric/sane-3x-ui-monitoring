package tg

import (
	"fmt"
	"strings"
	"time"
)

// configErrorMaxRunes bounds MsgConfigError's first-line excerpt (spec §8:
// "configError mon-client (mon-client <name>: config error <первая
// строка>)") — a mon-client's reported configError can be an arbitrarily
// long stack trace or JSON blob; only the first line, and only up to this
// many runes of it, ever goes to Telegram.
const configErrorMaxRunes = 256

// viaMonServerMark is the label spec §4.1/§8 requires on every transition
// mon-server sends on the panel's behalf while PANEL_DOWN, so an operator
// reading the chat can tell those messages apart from the panel's own.
const viaMonServerMark = "[via mon-server]"

// MsgConfigError formats the "configError appeared" message (spec §8): it
// is sent whenever a mon-client's heartbeat reports a non-empty configError,
// regardless of PANEL_DOWN — unlike the two transition formatters below,
// this one never carries the "via mon-server" mark. raw is the mon-client's
// full reported configError text; only its first line, trimmed to
// configErrorMaxRunes runes, is used, since Telegram messages are meant to
// be skimmed, not to hold a whole error dump.
func MsgConfigError(monClientName, raw string) string {
	return fmt.Sprintf("mon-client %s: config error %s", monClientName, firstLineTrimmed(raw))
}

// firstLineTrimmed returns s's first line (split on "\n", trailing "\r"
// stripped) truncated to configErrorMaxRunes runes.
func firstLineTrimmed(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimRight(s, "\r")

	r := []rune(s)
	if len(r) > configErrorMaxRunes {
		r = r[:configErrorMaxRunes]
	}
	return string(r)
}

// MsgTargetTransition formats a target state transition sent by mon-server
// itself while PANEL_DOWN (spec §4.1: "переходы targets ... mon-server сам
// шлёт в Telegram с пометкой «via mon-server»"), e.g.:
//
//	[via mon-server] target ams-1 (NL) xray:12/proxy UP → DOWN (tls_timeout)
func MsgTargetTransition(monClientName, region, inboundKind string, inboundID int, path, from, to, reason string) string {
	return fmt.Sprintf("%s target %s (%s) %s:%d/%s %s → %s (%s)",
		viaMonServerMark, monClientName, region, inboundKind, inboundID, path, from, to, reason)
}

// MsgTargetRecovered formats the one transition spec §7.2 wants worded
// differently: the "UP" row says the message carries the length of the
// outage, and only when the target is coming back from DOWN («UP» с
// длительностью простоя (только из DOWN)). An operator reading the chat
// wants "was it five seconds or five hours" without going to the panel,
// e.g.:
//
//	[via mon-server] target ams-1 (NL) xray:12/proxy DOWN → UP after 12m30s
//
// downtime is rounded to whole seconds — the probe interval is measured in
// tens of seconds, so sub-second precision here would be noise — and a
// negative value (a row whose `since` somehow sits in the future) is shown
// as 0s rather than as a negative duration.
func MsgTargetRecovered(monClientName, region, inboundKind string, inboundID int, path string, downtime time.Duration) string {
	if downtime < 0 {
		downtime = 0
	}
	return fmt.Sprintf("%s target %s (%s) %s:%d/%s DOWN → UP after %s",
		viaMonServerMark, monClientName, region, inboundKind, inboundID, path, downtime.Round(time.Second))
}

// MsgMonClientTransition formats a mon-client state transition sent by
// mon-server itself while PANEL_DOWN (spec §4.1), e.g.:
//
//	[via mon-server] mon-client ams-1 (NL) ONLINE → OFFLINE
func MsgMonClientTransition(monClientName, region, from, to string) string {
	return fmt.Sprintf("%s mon-client %s (%s) %s → %s", viaMonServerMark, monClientName, region, from, to)
}

// MsgSweep formats a diagnostic sweep's summary sent by mon-server itself
// while PANEL_DOWN (spec §4.1, decision #100) — normally the panel sends
// its own: a head line with the phase, then the report one line each, e.g.:
//
//	[via mon-server] sweep start: awg unreachable through every edge · ams-1 (NL)
//	tunnel edge:proxy ❌ awg_no_handshake
//	ICMP mon-client → proxy ✅ 0% · 2 ms
func MsgSweep(monClientName, region, inboundKind, phase string, lines []string) string {
	head := "unreachable through every edge"
	switch phase {
	case "change":
		head = "unreachable through every edge, the picture changed"
	case "end":
		head = "reachable through an edge again"
	}
	text := fmt.Sprintf("%s sweep %s: %s %s · %s (%s)", viaMonServerMark, phase, inboundKind, head, monClientName, region)
	if len(lines) > 0 {
		text += "\n" + strings.Join(lines, "\n")
	}
	return text
}
