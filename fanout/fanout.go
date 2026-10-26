// Package fanout detects BitTorrent (and port scanning) by connection
// behaviour rather than by payload.
//
// Protocol sniffing and signature matching only see unencrypted BitTorrent;
// modern clients use MSE/PE encryption and uTP, so the payload is opaque. What
// encryption cannot hide is the connection graph: a torrent client reaches out
// to hundreds of different peers on random high ports within minutes, while a
// normal device touches a few dozen remote addresses at most, almost all of
// them on 443/80 or a handful of well-known service ports.
//
// The detector keeps, per user, the set of distinct raw-IP destinations on
// non-service ports seen within a sliding window, and fires when that set
// crosses a threshold.
package fanout

import (
	"net"
	"sync"
	"time"
)

// DefaultIgnorePorts are destination ports never counted: web, DNS, mail,
// push notifications, Cloudflare alternate ports, STUN/TURN used by voice and
// video calls, Windows Delivery Optimization, and common blockchain P2P ports
// (fan-out there is legitimate and not a copyright problem).
var DefaultIgnorePorts = []int{
	80, 443, 8080, 8443, 8880, // web
	2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, // Cloudflare alternate HTTP(S)
	53, 853, 123, // DNS, DoT, NTP
	25, 110, 143, 465, 587, 993, 995, // mail
	5222, 5223, 5228, 5229, 5230, // XMPP, Apple push, Google FCM
	1080, 1443, // proxies
	3478, 3479, 3480, 3481, // STUN/TURN
	19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309, // Google STUN
	7680,                            // Windows Delivery Optimization
	8333, 18333, 30303, 9735, 18080, // Bitcoin, Ethereum, Lightning, Monero
}

// Detector is safe for concurrent use.
type Detector struct {
	mu         sync.Mutex
	window     time.Duration
	threshold  int
	hardCap    int           // per-user set size that forces a trim once alerted
	pruneEvery time.Duration // how often a user's set is aged out while alerted
	ignore     map[int]struct{}
	users      map[string]*userState
	now        func() time.Time
}

type userState struct {
	dsts     map[string]time.Time // destination IP -> last seen
	lastSeen time.Time
	prunedAt time.Time
	firedIP  string // source IP the last alert was raised for
	firedAt  time.Time
}

// New builds a detector. threshold is the number of distinct destinations in
// window that marks a user as a torrent client; extraIgnore adds ports to
// DefaultIgnorePorts.
func New(threshold int, window time.Duration, extraIgnore []int) *Detector {
	ig := make(map[int]struct{}, len(DefaultIgnorePorts)+len(extraIgnore))
	for _, p := range DefaultIgnorePorts {
		ig[p] = struct{}{}
	}
	for _, p := range extraIgnore {
		ig[p] = struct{}{}
	}
	hardCap := 4 * threshold
	if hardCap < 64 {
		hardCap = 64
	}
	pruneEvery := window / 10
	if pruneEvery < time.Second {
		pruneEvery = time.Second
	}
	return &Detector{
		window:     window,
		threshold:  threshold,
		hardCap:    hardCap,
		pruneEvery: pruneEvery,
		ignore:     ig,
		users:      make(map[string]*userState),
		now:        time.Now,
	}
}

// Relevant reports whether a destination can count towards fan-out at all:
// a public IP literal (domains are browsing, peers are raw IPs) on a port that
// is not a known service port. Callers use it as a cheap pre-filter before
// parsing the rest of the log line.
func (d *Detector) Relevant(dstHost string, dstPort int) bool {
	if dstPort <= 0 {
		return false
	}
	if _, skip := d.ignore[dstPort]; skip {
		return false
	}
	ip := net.ParseIP(dstHost)
	if ip == nil {
		return false
	}
	return isPublic(ip)
}

// Observe records one outbound connection. It returns fired=true (with the
// current distinct-destination count) when the user crosses the threshold;
// it fires at most once per window for the same source IP, but immediately
// again if the user shows up from a different source IP.
func (d *Detector) Observe(user, srcIP, dstHost string, dstPort int) (fired bool, count int) {
	if !d.Relevant(dstHost, dstPort) {
		return false, 0
	}
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()

	st := d.users[user]
	if st == nil {
		st = &userState{dsts: make(map[string]time.Time)}
		d.users[user] = st
	}
	st.dsts[dstHost] = now
	st.lastSeen = now

	n := len(st.dsts)
	if n < d.threshold {
		return false, n
	}

	// Already alerted for this source IP within the window: no new alert, but
	// keep memory flat cheaply (a port scanner can add thousands of
	// destinations per second, so never age the whole set on every insert).
	if srcIP == st.firedIP && now.Sub(st.firedAt) < d.window {
		if n > d.hardCap {
			d.prune(st, now)
			if len(st.dsts) > d.hardCap {
				// Still huge: the alert is already raised, the exact set no
				// longer matters — trim to the threshold.
				for k := range st.dsts {
					delete(st.dsts, k)
					if len(st.dsts) <= d.threshold {
						break
					}
				}
			}
		} else if now.Sub(st.prunedAt) >= d.pruneEvery {
			d.prune(st, now)
		}
		return false, len(st.dsts)
	}

	// Candidate for a new alert: decide on an exact, aged-out count. Outside
	// the cooldown the set is never far above the threshold, so this is cheap.
	d.prune(st, now)
	count = len(st.dsts)
	if count < d.threshold {
		return false, count
	}
	st.firedIP = srcIP
	st.firedAt = now
	return true, count
}

// prune drops destinations last seen before the window.
func (d *Detector) prune(st *userState, now time.Time) {
	cutoff := now.Add(-d.window)
	for k, t := range st.dsts {
		if t.Before(cutoff) {
			delete(st.dsts, k)
		}
	}
	st.prunedAt = now
}

// Sweep forgets users idle for longer than the window. Call it periodically.
func (d *Detector) Sweep() {
	cutoff := d.now().Add(-d.window)
	d.mu.Lock()
	defer d.mu.Unlock()
	for u, st := range d.users {
		if st.lastSeen.Before(cutoff) {
			delete(d.users, u)
		}
	}
}

// Users returns how many users are currently tracked (for diagnostics/tests).
func (d *Detector) Users() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.users)
}

func isPublic(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 255 || v4[0] == 0 { // broadcast, "this network"
			return false
		}
		if v4[0] == 100 && v4[1]&0xC0 == 64 { // 100.64.0.0/10 CGNAT
			return false
		}
	}
	return true
}
