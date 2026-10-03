package store

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// PathHops is the paths-vocabulary word for "every probed hop of the chain,
// including hops that join later" (spec §5.1) — on a panel without a chain
// it stands for proxy. It lives in MonClient.Paths and in the ensure
// snapshot, never on a target: a target's path is always one hop.
const PathHops = "hops"

// PathEdges is the paths-vocabulary word for "every edge front of the
// chain, active and standby, including edges that join later" (spec §5.1,
// decision #100) — on a panel without a chain it stands for proxy, like
// hops. It is the default: a mon-client on edges probes only its edge
// paths every cycle, and the rest of the chain is kept for the diagnostic
// sweep (CONTEXT.md: Derived state, Diagnostic sweep). Like hops it lives
// in MonClient.Paths only, never on a target.
const PathEdges = "edges"

// Hop roles (CONTEXT.md: edge front, inner front), the prefix of a hop's
// path.
const (
	HopRoleEdge  = "edge"
	HopRoleInner = "inner"
)

// hopNameRe is a hop name in the chain registry (proxy-chain §6.1,
// spec §5.1: [a-z0-9-]{1,32}).
var hopNameRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// HopPath is a chain hop's path, "<role>:<name>" (spec §5.1).
func HopPath(role, name string) string { return role + ":" + name }

// ValidHopName reports whether name is a hop name by grammar.
func ValidHopName(name string) bool { return hopNameRe.MatchString(name) }

// IsHopPath reports whether p is edge:<name> or inner:<name> by grammar. A
// hop path is only split on its first ':' — the name itself has none.
func IsHopPath(p string) bool {
	role, name, ok := strings.Cut(p, ":")
	if !ok {
		return false
	}
	return (role == HopRoleEdge || role == HopRoleInner) && ValidHopName(name)
}

// IsEdgePath reports whether p is an edge-path: edge:<name>, or proxy —
// the one path to the proxy front on a panel without a chain. These are the
// paths a mon-client on edges probes every cycle (decision #100).
func IsEdgePath(p string) bool {
	return p == PathProxy || (IsHopPath(p) && strings.HasPrefix(p, HopRoleEdge+":"))
}

// IsInnerPath reports whether p is inner:<name>.
func IsInnerPath(p string) bool {
	return IsHopPath(p) && strings.HasPrefix(p, HopRoleInner+":")
}

// ValidPath is the path grammar of spec §5.1 (protocol §4.2, contract §3):
// direct | proxy | edge:<name> | inner:<name>. It checks the spelling only;
// whether the hop is in the chain is the material's question.
func ValidPath(p string) bool {
	return p == PathDirect || p == PathProxy || IsHopPath(p)
}

// migrateProxyPaths is the paths vocabulary migration of decision #61 п. 3
// (spec §3): "proxy" left the vocabulary, and a stored one becomes "hops",
// which on a panel without a chain expands back into proxy — a box keeps
// probing exactly what it probed before, and on a chained panel follows
// every probed hop. A list that already had "hops" ends up with one. Rows
// are rewritten one by one, in no transaction: each rewrite is complete on
// its own, and a crash halfway leaves the rest for the next start.
func (s *Store) migrateProxyPaths() error {
	var rows []MonClient
	if err := s.DB.Where("paths LIKE ?", `%"`+PathProxy+`"%`).Find(&rows).Error; err != nil {
		return fmt.Errorf("store: read mon-client paths to migrate: %w", err)
	}
	for i := range rows {
		old := rows[i].PathsList()
		if !slices.Contains(old, PathProxy) {
			continue
		}
		out := make([]string, 0, len(old))
		for _, p := range old {
			if p == PathProxy {
				p = PathHops
			}
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		rows[i].SetPaths(out)
		if err := s.DB.Model(&MonClient{}).Where("id = ?", rows[i].Id).
			Update("paths", rows[i].Paths).Error; err != nil {
			return fmt.Errorf("store: migrate paths of %s: %w", rows[i].Id, err)
		}
	}
	return nil
}
