// Package hostcheck is mon-client's host reachability check (CONTEXT.md:
// Host reachability check, decision #100): a series of ICMP echoes to a
// hop or the real server during a diagnostic sweep, reported as the share
// lost and the average round trip. It says only whether the address
// answers, not whether an inbound behind it works — that is the tunnel
// probe's job.
//
// It uses an unprivileged ICMP datagram socket (SOCK_DGRAM/IPPROTO_ICMP,
// "udp4" in golang.org/x/net/icmp): mon-client runs without capabilities,
// and the kernel allows such a socket to the groups in
// net.ipv4.ping_group_range. A box that does not allow it gets
// icmp_unavailable — an explicit "not measured", never a 100% loss.
package hostcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// The series decision #100 fixes: about ten echoes, ~200 ms apart, and a
// last wait for late replies.
const (
	DefaultCount    = 10
	DefaultInterval = 200 * time.Millisecond
	DefaultTimeout  = time.Second
)

// Conn is the part of an ICMP socket a check uses — *icmp.PacketConn's
// methods — so a test can stand in a fake socket.
type Conn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// Checker runs host reachability checks. The zero value is ready to use
// with the defaults above, the real socket and the system resolver.
type Checker struct {
	Count    int
	Interval time.Duration
	Timeout  time.Duration
	// Listen opens the socket one series runs on. Nil means an
	// unprivileged ICMP datagram socket.
	Listen func() (Conn, error)
	// Resolve turns a host into its IPv4 address. Nil means the system
	// resolver; an IPv4 literal is never resolved.
	Resolve func(ctx context.Context, host string) (net.IP, error)
}

// Check runs one series per host, all at once, and reports them in the
// hosts' order.
func (c *Checker) Check(ctx context.Context, hosts []proto.SweepJobHost) []proto.HostCheck {
	out := make([]proto.HostCheck, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = c.One(ctx, h)
		}()
	}
	wg.Wait()
	return out
}

// One runs one series against one host.
func (c *Checker) One(ctx context.Context, h proto.SweepJobHost) proto.HostCheck {
	res := proto.HostCheck{Name: h.Name}
	ip, err := c.resolve(ctx, h.Host)
	if err != nil {
		reason := proto.ReasonResolveFailed
		res.Reason = &reason
		return res
	}
	conn, err := c.listen()
	if err != nil {
		reason := proto.ReasonICMPUnavailable
		res.Reason = &reason
		return res
	}
	sent, rtts := c.series(ctx, conn, ip)
	res.Sent = sent
	if sent == 0 {
		return res
	}
	res.LossPct = (sent - len(rtts)) * 100 / sent
	if len(rtts) > 0 {
		var sum time.Duration
		for _, d := range rtts {
			sum += d
		}
		avg := (sum / time.Duration(len(rtts))).Round(time.Millisecond).Milliseconds()
		res.RttAvgMs = &avg
	}
	return res
}

// series sends the echoes and collects the replies: how many were sent and
// the round trip of each one answered. The socket is closed on return.
func (c *Checker) series(ctx context.Context, conn Conn, ip net.IP) (int, []time.Duration) {
	count, interval, timeout := c.count(), c.interval(), c.timeout()
	token := make([]byte, 8)
	_, _ = rand.Read(token)

	var (
		mu       sync.Mutex
		sentAt   = make(map[int]time.Time, count)
		answered = make(map[int]time.Duration, count)
		done     = make(chan struct{})
		all      = make(chan struct{})
	)
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			seq, ok := echoReply(buf[:n], token)
			if !ok {
				continue
			}
			mu.Lock()
			if at, sent := sentAt[seq]; sent {
				if _, dup := answered[seq]; !dup {
					answered[seq] = time.Since(at)
					if len(answered) == count {
						close(all)
					}
				}
			}
			mu.Unlock()
		}
	}()

	sent := 0
	dst := &net.UDPAddr{IP: ip}
	for seq := 0; seq < count; seq++ {
		if seq > 0 && !sleep(ctx, interval) {
			break
		}
		msg := xicmp.Message{Type: ipv4.ICMPTypeEcho, Body: &xicmp.Echo{ID: 0, Seq: seq, Data: token}}
		b, err := msg.Marshal(nil)
		if err != nil {
			break
		}
		mu.Lock()
		sentAt[seq] = time.Now()
		mu.Unlock()
		sent++
		// A send that fails (no route, a refusing firewall) is an echo
		// that got no answer: it counts as sent and lost.
		_, _ = conn.WriteTo(b, dst)
	}

	wait := time.NewTimer(timeout)
	select {
	case <-all:
	case <-wait.C:
	case <-ctx.Done():
	}
	wait.Stop()
	_ = conn.SetReadDeadline(time.Now())
	_ = conn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	rtts := make([]time.Duration, 0, len(answered))
	for seq, d := range answered {
		if seq < sent {
			rtts = append(rtts, d)
		}
	}
	return sent, rtts
}

// echoReply parses one received ICMP message and reports the sequence
// number of an echo reply to this series (its data is the series' token).
func echoReply(b, token []byte) (int, bool) {
	msg, err := xicmp.ParseMessage(1, b) // 1: ICMP for IPv4
	if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
		return 0, false
	}
	echo, ok := msg.Body.(*xicmp.Echo)
	if !ok || !bytes.Equal(echo.Data, token) {
		return 0, false
	}
	return echo.Seq, true
}

func (c *Checker) resolve(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, errors.New("hostcheck: not an IPv4 address")
	}
	if c.Resolve != nil {
		return c.Resolve(ctx, host)
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("hostcheck: no IPv4 address")
	}
	return ips[0], nil
}

func (c *Checker) listen() (Conn, error) {
	if c.Listen != nil {
		return c.Listen()
	}
	return xicmp.ListenPacket("udp4", "0.0.0.0")
}

func (c *Checker) count() int {
	if c.Count > 0 {
		return c.Count
	}
	return DefaultCount
}

func (c *Checker) interval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return DefaultInterval
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// sleep waits d unless ctx ends first, reporting whether it waited.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
