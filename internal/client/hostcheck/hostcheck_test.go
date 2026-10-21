package hostcheck

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// fakeConn is an ICMP datagram socket whose far end answers every echo
// whose sequence number drop does not name, the way the kernel hands a
// udp4 ICMP socket its replies: the bare ICMP message, no IP header.
type fakeConn struct {
	drop func(seq int) bool

	mu       sync.Mutex
	replies  chan []byte
	deadline time.Time
	closed   bool
	sentTo   []net.Addr
}

func newFakeConn(drop func(seq int) bool) *fakeConn {
	return &fakeConn{drop: drop, replies: make(chan []byte, 64)}
}

func (c *fakeConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	c.mu.Lock()
	c.sentTo = append(c.sentTo, dst)
	c.mu.Unlock()
	msg, err := xicmp.ParseMessage(1, b)
	if err != nil {
		return 0, err
	}
	echo := msg.Body.(*xicmp.Echo)
	if c.drop != nil && c.drop(echo.Seq) {
		return len(b), nil
	}
	reply := xicmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: echo}
	rb, err := reply.Marshal(nil)
	if err != nil {
		return 0, err
	}
	// A stray reply of someone else's series comes first: it must be
	// ignored.
	stray := xicmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &xicmp.Echo{Seq: echo.Seq, Data: []byte("other")}}
	sb, _ := stray.Marshal(nil)
	c.replies <- sb
	c.replies <- rb
	return len(b), nil
}

func (c *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		closed, deadline := c.closed, c.deadline
		c.mu.Unlock()
		if closed || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		select {
		case r := <-c.replies:
			return copy(b, r), &net.UDPAddr{}, nil
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func fastChecker(conn Conn, listenErr error) *Checker {
	return &Checker{
		Interval: time.Millisecond,
		Timeout:  200 * time.Millisecond,
		Listen: func() (Conn, error) {
			if listenErr != nil {
				return nil, listenErr
			}
			return conn, nil
		},
		Resolve: func(_ context.Context, host string) (net.IP, error) {
			if host == "nowhere.example.net" {
				return nil, errors.New("no such host")
			}
			return net.IPv4(192, 0, 2, 7), nil
		},
	}
}

// TestCheck_AllAnswered: ten echoes, ten replies — 0% loss and an average
// round trip, sent to the host's address.
func TestCheck_AllAnswered(t *testing.T) {
	conn := newFakeConn(nil)
	got := fastChecker(conn, nil).One(context.Background(), proto.SweepJobHost{Name: "edge-a", Host: "198.51.100.20"})
	if got.Name != "edge-a" || got.Sent != 10 || got.LossPct != 0 || got.RttAvgMs == nil || got.Reason != nil {
		t.Fatalf("check = %+v, want 10 sent, 0%% loss, an rtt", got)
	}
	if dst := conn.sentTo[0].(*net.UDPAddr); !dst.IP.Equal(net.IPv4(198, 51, 100, 20)) {
		t.Fatalf("echo sent to %v, want the host's address", dst)
	}
}

// TestCheck_SomeLost: three of ten unanswered is 30%.
func TestCheck_SomeLost(t *testing.T) {
	conn := newFakeConn(func(seq int) bool { return seq%3 == 0 && seq > 0 })
	got := fastChecker(conn, nil).One(context.Background(), proto.SweepJobHost{Name: "", Host: "real.example.net"})
	if got.Sent != 10 || got.LossPct != 30 || got.RttAvgMs == nil {
		t.Fatalf("check = %+v, want 30%% loss", got)
	}
}

// TestCheck_AllLost: nothing answered is 100% and no round trip.
func TestCheck_AllLost(t *testing.T) {
	conn := newFakeConn(func(int) bool { return true })
	got := fastChecker(conn, nil).One(context.Background(), proto.SweepJobHost{Name: "edge-b", Host: "198.51.100.21"})
	if got.Sent != 10 || got.LossPct != 100 || got.RttAvgMs != nil || got.Reason != nil {
		t.Fatalf("check = %+v, want 100%% loss with no rtt", got)
	}
}

// TestCheck_Unavailable: a box that cannot open the ICMP socket says so —
// icmp_unavailable, nothing sent — rather than reporting 100% loss; a host
// that does not resolve is resolve_failed.
func TestCheck_Unavailable(t *testing.T) {
	got := fastChecker(nil, errors.New("socket: permission denied")).One(context.Background(), proto.SweepJobHost{Name: "edge-a", Host: "198.51.100.20"})
	if got.Reason == nil || *got.Reason != proto.ReasonICMPUnavailable || got.Sent != 0 || got.LossPct != 0 {
		t.Fatalf("check = %+v, want icmp_unavailable and nothing measured", got)
	}
	got = fastChecker(newFakeConn(nil), nil).One(context.Background(), proto.SweepJobHost{Name: "core-1", Host: "nowhere.example.net"})
	if got.Reason == nil || *got.Reason != proto.ReasonResolveFailed {
		t.Fatalf("check = %+v, want resolve_failed", got)
	}
}

// TestCheck_ManyHostsInOrder: one series per host, reported in the job's
// order.
func TestCheck_ManyHostsInOrder(t *testing.T) {
	c := fastChecker(nil, nil)
	c.Listen = func() (Conn, error) { return newFakeConn(nil), nil }
	got := c.Check(context.Background(), []proto.SweepJobHost{{Name: "a", Host: "192.0.2.1"}, {Name: "b", Host: "192.0.2.2"}, {Name: "", Host: "192.0.2.3"}})
	if len(got) != 3 || got[0].Name != "a" || got[1].Name != "b" || got[2].Name != "" {
		t.Fatalf("checks = %+v, want three in order", got)
	}
}
