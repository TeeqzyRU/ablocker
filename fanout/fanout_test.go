package fanout

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest(threshold int, window time.Duration) (*Detector, *clock) {
	c := &clock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	d := New(threshold, window, nil)
	d.now = c.now
	return d, c
}

// peer returns a distinct public IPv4 for index i.
func peer(i int) string { return fmt.Sprintf("91.%d.%d.%d", (i/65536)%200+1, (i/256)%256, i%256+1) }

func TestTorrentBurstFiresOnce(t *testing.T) {
	d, c := newTest(150, 10*time.Minute)
	fires := 0
	for i := 0; i < 230; i++ { // shape of a real swarm: ~230 peers in one window
		if f, _ := d.Observe("100003", "203.0.113.50", peer(i), 20000+i); f {
			fires++
		}
		c.advance(500 * time.Millisecond)
	}
	if fires != 1 {
		t.Fatalf("want exactly one alert for one burst from one IP, got %d", fires)
	}
}

func TestNormalUserNeverFires(t *testing.T) {
	d, c := newTest(150, 10*time.Minute)
	// Heaviest legitimate users in the real logs: ~46 distinct raw-IP
	// destinations on non-service ports per 10 minutes. Simulate an hour.
	for minute := 0; minute < 60; minute++ {
		for i := 0; i < 5; i++ {
			if f, _ := d.Observe("normal", "1.2.3.4", peer(minute*5+i), 27015); f {
				t.Fatalf("normal user must not fire (minute %d)", minute)
			}
		}
		c.advance(time.Minute)
	}
}

func TestSlowAccumulationOutsideWindowDoesNotFire(t *testing.T) {
	d, c := newTest(150, 10*time.Minute)
	for i := 0; i < 100; i++ {
		d.Observe("u", "1.1.1.2", peer(i), 40000)
	}
	c.advance(11 * time.Minute) // first batch is now outside the window
	for i := 100; i < 200; i++ {
		if f, _ := d.Observe("u", "1.1.1.2", peer(i), 40000); f {
			t.Fatal("200 peers spread over 11 minutes is 100 per window — must not fire")
		}
	}
}

func TestRepeatedDestinationCountsOnce(t *testing.T) {
	d, _ := newTest(150, 10*time.Minute)
	for i := 0; i < 1000; i++ {
		if f, n := d.Observe("caller", "5.5.5.5", "192.0.2.213", 33333); f || n != 1 {
			t.Fatalf("same peer must count once, got fired=%v n=%d", f, n)
		}
	}
}

func TestIgnoredTrafficNotCounted(t *testing.T) {
	d, _ := newTest(3, 10*time.Minute)
	cases := []struct {
		host string
		port int
	}{
		{"142.250.1.1", 443},       // web
		{"74.125.250.129", 19302},  // Google STUN
		{"162.159.207.0", 3478},    // Cloudflare STUN (Discord)
		{"17.57.146.29", 5223},     // Apple push
		{"www.gstatic.com", 40000}, // domain, not a peer
		{"192.168.1.201", 7680},    // LAN
		{"192.168.1.5", 6881},      // LAN even on a torrent port
		{"255.255.255.255", 34569}, // broadcast
		{"10.0.0.7", 6881},         // private
		{"100.64.3.3", 6881},       // CGNAT
		{"127.0.0.1", 6881},        // loopback
	}
	for _, tc := range cases {
		if d.Relevant(tc.host, tc.port) {
			t.Errorf("%s:%d must be ignored", tc.host, tc.port)
		}
	}
	if !d.Relevant("91.200.13.44", 51413) {
		t.Error("public IP on a random high port must count")
	}
	if !d.Relevant("2a02:6b8::1", 6881) {
		t.Error("public IPv6 peer must count")
	}
}

func TestNewSourceIPFiresAgain(t *testing.T) {
	d, c := newTest(10, 10*time.Minute)
	for i := 0; i < 10; i++ {
		d.Observe("u", "1.1.1.1", peer(i), 40000+i)
	}
	// keep torrenting from the same IP: no repeat alert inside the window
	for i := 10; i < 40; i++ {
		if f, _ := d.Observe("u", "1.1.1.1", peer(i), 40000+i); f {
			t.Fatal("must not re-alert for the same IP within the window")
		}
		c.advance(time.Second)
	}
	// user hops to a new mobile IP and continues: alert immediately
	if f, _ := d.Observe("u", "2.2.2.2", peer(99), 41000); !f {
		t.Fatal("must alert again when the same user continues from a new IP")
	}
}

func TestUsersAreIndependent(t *testing.T) {
	d, _ := newTest(150, 10*time.Minute)
	for i := 0; i < 100; i++ {
		if f, _ := d.Observe("a", "1.1.1.1", peer(i), 40000); f {
			t.Fatal("user a fired at 100")
		}
		if f, _ := d.Observe("b", "2.2.2.2", peer(i), 40000); f {
			t.Fatal("user b fired at 100")
		}
	}
}

func TestSweepForgetsIdleUsers(t *testing.T) {
	d, c := newTest(150, 10*time.Minute)
	d.Observe("idle", "1.1.1.1", peer(1), 40000)
	d.Observe("busy", "2.2.2.2", peer(2), 40000)
	c.advance(11 * time.Minute)
	d.Observe("busy", "2.2.2.2", peer(3), 40000)
	d.Sweep()
	if d.Users() != 1 {
		t.Fatalf("want 1 tracked user after sweep, got %d", d.Users())
	}
}

func TestMemoryBoundedUnderLongTorrenting(t *testing.T) {
	d, c := newTest(150, 10*time.Minute)
	for i := 0; i < 50000; i++ { // hours of torrenting
		d.Observe("u", "1.1.1.1", peer(i), 40000)
		c.advance(200 * time.Millisecond)
	}
	d.mu.Lock()
	n := len(d.users["u"].dsts)
	d.mu.Unlock()
	if n > 4*150 {
		t.Fatalf("per-user set must stay bounded by the hard cap, got %d", n)
	}
}

func TestPortScannerStaysCheapAndBounded(t *testing.T) {
	d, c := newTest(150, 10*time.Minute)
	start := time.Now()
	fires := 0
	for i := 0; i < 200000; i++ { // scanner: 2000 new hosts per second
		if f, _ := d.Observe("scanner", "9.9.9.9", peer(i), 22); f {
			fires++
		}
		if i%2000 == 0 {
			c.advance(time.Second)
		}
	}
	if fires != 1 {
		t.Fatalf("scanner from one IP must raise exactly one alert per window, got %d", fires)
	}
	d.mu.Lock()
	n := len(d.users["scanner"].dsts)
	d.mu.Unlock()
	if n > 4*150 {
		t.Fatalf("scanner set must be trimmed to the hard cap, got %d", n)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("200k observations took %v — not amortised O(1)", el)
	}
}
