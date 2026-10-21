package awg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// Bounds of TestProbeMemoryPerProbeIsBounded. A probe on the batch-1 bind
// allocates a little over a megabyte (a gVisor netstack, a TLS handshake,
// one 64 KiB message buffer per device routine); on the default bind it was
// ~25 MB (#85). The bounds sit far from both, so neither -race nor a busy
// CI box can tip them.
const (
	// maxAllocPerProbe caps what one probe may allocate, garbage included:
	// garbage is exactly what made mon-client's heap target, and with it
	// its RSS, balloon into swap (#85).
	maxAllocPerProbe = 4 << 20
	// maxHeapGrowth caps how much HeapInuse may grow over all probes once
	// the garbage is collected: a leak guard, not a tight fit.
	maxHeapGrowth = 8 << 20
)

// memoryProbes is how many probes of each kind the test runs after the
// warm-up. Enough that one-off costs (package-level tables, the first TLS
// handshake) disappear in the average; few enough that the no-handshake
// probes, which each wait out their whole (short) budget, stay a couple of
// seconds.
const memoryProbes = 8

// TestProbeMemoryPerProbeIsBounded is #90 (cause found in #85): every
// probe device ran on conn.NewDefaultBind(), whose linux BatchSize of 128
// makes amneziawg-go take 128 × 64 KiB message buffers for each receive
// routine and for the TUN reader — ~25 MB per probe, parked in the
// device's sync.Pool after Close. That was no leak, but at a probe per AWG
// target a minute it kept mon-client's heap target, and its RSS, several
// times its live heap, and a 380 MB stand box swapped and stalled for
// seconds at a time.
//
// It runs what a stand cycle runs, a successful probe and a no-handshake
// one, and measures allocation per probe and the heap left once the
// garbage (sync.Pool's victim cache included, hence two GCs) is gone. Not
// parallel: both numbers are process-wide.
func TestProbeMemoryPerProbeIsBounded(t *testing.T) {
	far := startFarEnd(t, http.HandlerFunc(probeEcho))
	okCfg := far.clientConf(t, fmt.Sprintf("127.0.0.1:%d", far.port))
	deadCfg := confFor(t, "203.0.113.7:51820", "")
	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: far.pool}}
	deadBudgets := probe.Budgets{Budget: 300 * time.Millisecond, Connect: 200 * time.Millisecond, TLS: time.Second, Headers: time.Second}

	cycle := func() {
		t.Helper()
		ok := p.Probe(context.Background(), far.probeURL(), "tok", proto.TargetKey{InboundKind: "awg", Path: "direct"}, okCfg, tunnelBudgets())
		if !ok.Ok {
			t.Fatalf("probe through the tunnel failed: reason=%q detail=%q", deref(ok.Reason), deref(ok.Detail))
		}
		dead := p.Probe(context.Background(), "https://203.0.113.7:8443/v1/probe", "tok", proto.TargetKey{InboundKind: "awg", Path: "proxy"}, deadCfg, deadBudgets)
		if got := deref(dead.Reason); got != proto.ReasonAWGNoHandshake {
			t.Fatalf("probe to a black hole: reason = %q, want %q", got, proto.ReasonAWGNoHandshake)
		}
	}

	// Warm-up: the first probes pay for lazily built package state that
	// no later probe pays for again.
	cycle()
	cycle()
	before := settledMemStats()

	for range memoryProbes {
		cycle()
	}
	after := settledMemStats()

	probes := uint64(2 * memoryProbes)
	perProbe := (after.TotalAlloc - before.TotalAlloc) / probes
	t.Logf("allocated per probe: %d KiB; HeapInuse %d KiB → %d KiB",
		perProbe>>10, before.HeapInuse>>10, after.HeapInuse>>10)
	if perProbe > maxAllocPerProbe {
		t.Errorf("a probe allocates %d KiB, want at most %d KiB", perProbe>>10, maxAllocPerProbe>>10)
	}
	if after.HeapInuse > before.HeapInuse && after.HeapInuse-before.HeapInuse > maxHeapGrowth {
		t.Errorf("HeapInuse grew by %d KiB over %d probes, want at most %d KiB",
			(after.HeapInuse-before.HeapInuse)>>10, probes, maxHeapGrowth>>10)
	}
}

// settledMemStats reads the memory statistics once the garbage is gone:
// two GCs, because a sync.Pool's contents survive the first one in its
// victim cache, and a short pause between them for goroutines of just
// closed devices to finish unwinding.
func settledMemStats() runtime.MemStats {
	for range 2 {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}
