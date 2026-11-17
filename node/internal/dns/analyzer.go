// Package dns implements DNS Water Torture (NXDOMAIN / random-subdomain)
// detection and unsolicited-response analysis for the xSight Node.
//
// It parses DNS QNAME labels in Go userspace (avoiding deep variable-length
// loops in eBPF), scores leftmost subdomain labels using Shannon entropy and
// label length/depth, and tracks per-parent-zone NXDOMAIN ratios to flag
// active Water Torture attacks. Zone hashes can be pushed back to the XDP
// data plane for per-zone rate limiting.
package dns

import (
	"hash/fnv"
	"math"
	"net"
	"sync"
	"time"
)

// DNSQuery is a parsed DNS query observed by the node.
type DNSQuery struct {
	QName      string    // e.g. "x7y9z2.example.com" (trailing dot removed)
	QType      uint16    // host byte order
	QClass     uint16    // host byte order
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16    // host byte order
	DstPort    uint16    // host byte order
	Timestamp  time.Time
}

// DNSResponse is a parsed DNS response observed by the node.
type DNSResponse struct {
	QName      string
	RCode      uint16 // 0=NOERROR, 3=NXDOMAIN, etc.
	SrcIP      net.IP // responder (server)
	DstIP      net.IP // client
	Timestamp  time.Time
}

// Detection thresholds.
const (
	// EntropyThreshold above which a leftmost label is considered random.
	EntropyThreshold = 3.5
	// MinLabelLen minimum label length to be considered for entropy scoring.
	MinLabelLen = 4
	// NXDOMAINRatioThreshold above which a zone is flagged for Water Torture.
	NXDOMAINRatioThreshold = 0.40
	// MinQueriesForEvaluation minimum queries per window before ratio eval.
	MinQueriesForEvaluation = 10
	// ZoneWindow zone tracking window.
	ZoneWindow = 10 * time.Second
)

// Analyzer tracks DNS queries and responses per parent zone, scoring
// Water Torture characteristics.
type Analyzer struct {
	mu    sync.Mutex
	zones map[string]*zoneTracker
}

type zoneTracker struct {
	mu               sync.Mutex
	queries          uint64
	nxdomain         uint64
	highEntropyLabel uint64
	lastReset        time.Time
}

// NewAnalyzer creates a DNS analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{zones: make(map[string]*zoneTracker)}
}

// parentZone extracts the parent zone (registrable domain) from a QName.
// Best-effort: takes the last two labels.
func parentZone(qName string) string {
	labels := splitLabels(stripTrailingDot(qName))
	if len(labels) <= 2 {
		return stripTrailingDot(qName)
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// splitLabels splits a QName into its labels (without trailing dot).
func splitLabels(qName string) []string {
	if qName == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i < len(qName); i++ {
		if qName[i] == '.' {
			if i > start {
				labels = append(labels, qName[start:i])
			}
			start = i + 1
		}
	}
	if start < len(qName) {
		labels = append(labels, qName[start:])
	}
	return labels
}

func stripTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// leftmostLabel returns the leftmost (first) label of a QName.
func leftmostLabel(qName string) string {
	labels := splitLabels(stripTrailingDot(qName))
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

// shannonEntropy computes the Shannon entropy (in bits) of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var ent float64
	invLen := 1.0 / float64(len(s))
	for _, n := range freq {
		if n == 0 {
			continue
		}
		p := float64(n) * invLen
		ent -= p * math.Log2(p)
	}
	return ent
}

// IsRandomLabel reports whether a label looks randomly generated based on
// entropy and length.
func IsRandomLabel(label string) bool {
	if len(label) < MinLabelLen {
		return false
	}
	return shannonEntropy(label) >= EntropyThreshold
}

// ObserveQuery records a DNS query and updates zone statistics.
func (a *Analyzer) ObserveQuery(q *DNSQuery) {
	if q == nil || q.QName == "" {
		return
	}
	zone := parentZone(q.QName)
	a.mu.Lock()
	zt := a.zones[zone]
	if zt == nil {
		zt = &zoneTracker{lastReset: time.Now()}
		a.zones[zone] = zt
	}
	a.mu.Unlock()

	zt.mu.Lock()
	zt.queries++
	if IsRandomLabel(leftmostLabel(q.QName)) {
		zt.highEntropyLabel++
	}
	zt.mu.Unlock()
}

// ObserveResponse records a DNS response and updates NXDOMAIN counts.
func (a *Analyzer) ObserveResponse(r *DNSResponse) {
	if r == nil || r.QName == "" {
		return
	}
	zone := parentZone(r.QName)
	a.mu.Lock()
	zt := a.zones[zone]
	if zt == nil {
		zt = &zoneTracker{lastReset: time.Now()}
		a.zones[zone] = zt
	}
	a.mu.Unlock()

	zt.mu.Lock()
	if r.RCode == 3 { // NXDOMAIN
		zt.nxdomain++
	}
	zt.mu.Unlock()
}

// ZoneReport is a snapshot of one zone's Water Torture metrics.
type ZoneReport struct {
	Zone             string
	Queries          uint64
	NXDOMAIN         uint64
	NXDOMAINRatio    float64
	HighEntropyLabel uint64
	HighEntropyRatio float64
	IsWaterTorture   bool
}

// ZoneReports returns a snapshot of all tracked zones.
func (a *Analyzer) ZoneReports() []ZoneReport {
	a.mu.Lock()
	zones := make([]string, 0, len(a.zones))
	for z := range a.zones {
		zones = append(zones, z)
	}
	a.mu.Unlock()

	var out []ZoneReport
	now := time.Now()
	for _, z := range zones {
		zt := a.zones[z]
		zt.mu.Lock()
		q := zt.queries
		nx := zt.nxdomain
		he := zt.highEntropyLabel
		stale := now.Sub(zt.lastReset) > 5*ZoneWindow
		zt.mu.Unlock()
		if stale {
			a.mu.Lock()
			delete(a.zones, z)
			a.mu.Unlock()
			continue
		}
		if q < MinQueriesForEvaluation {
			continue
		}
		nxRatio := float64(nx) / float64(q)
		heRatio := float64(he) / float64(q)
		isWT := nxRatio >= NXDOMAINRatioThreshold && heRatio >= 0.5
		out = append(out, ZoneReport{
			Zone:             z,
			Queries:          q,
			NXDOMAIN:         nx,
			NXDOMAINRatio:    nxRatio,
			HighEntropyLabel: he,
			HighEntropyRatio: heRatio,
			IsWaterTorture:   isWT,
		})
	}
	return out
}

// ZoneHash computes an FNV-1a hash of a domain name for pushing to the XDP
// data plane as a per-zone rate-limit key. (The BPF side can re-key on the
// same hash value.)
func ZoneHash(domain string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(stripTrailingDot(domain)))
	return h.Sum64()
}
