// Package sigs extracts dynamic UDP payload byte-offset signatures from
// ringbuf samples during a UDP surge with no dominant source port.
//
// The extractor aligns sampled UDP payloads at L4 payload offset 0..63,
// computes per-offset byte frequency across attack and baseline samples, and
// extracts a contiguous 4-to-8 byte pattern + bitmask where modal bytes
// appear in >= 85% of attack packets and < 1% of baseline traffic.
//
// The resulting bpf.UDPPayloadSigValue can be installed into the kernel's
// udp_payload_sigs map via bpf.Manager.SetUDPPayloadSig.
package sigs

import (
	"sync"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

// Sample is one captured UDP payload slice with its destination.
type Sample struct {
	DstIP   []byte // 4-byte IPv4 destination
	Payload []byte // first 64 bytes of UDP payload (may be shorter)
}

// AttackThreshold is the minimum modal-byte frequency among attack samples.
const AttackThreshold = 0.85

// BaselineThreshold is the maximum modal-byte frequency among baseline samples.
const BaselineThreshold = 0.01

// MinPatternLen / MaxPatternLen bound the extracted signature length.
const (
	MinPatternLen = 4
	MaxPatternLen = 8
)

// Extractor accumulates attack and baseline UDP payload samples and extracts
// a byte-offset signature. Zero value is ready to use.
type Extractor struct {
	mu        sync.Mutex
	attack    []Sample
	baseline  []Sample
}

// AddAttack records one attack-side UDP payload sample.
func (e *Extractor) AddAttack(s Sample) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attack = append(e.attack, s)
}

// AddBaseline records one baseline-side UDP payload sample.
func (e *Extractor) AddBaseline(s Sample) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.baseline = append(e.baseline, s)
}

// Len returns the number of attack and baseline samples collected.
func (e *Extractor) Len() (attack, baseline int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.attack), len(e.baseline)
}

// Reset clears all collected samples.
func (e *Extractor) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attack = e.attack[:0]
	e.baseline = e.baseline[:0]
}

// byteFreq returns a [256]int histogram of byte values at the given offset
// across the provided samples. Samples shorter than offset+1 are skipped.
func byteFreq(samples []Sample, offset int) [256]int {
	var freq [256]int
	for _, s := range samples {
		if offset < len(s.Payload) {
			freq[s.Payload[offset]]++
		}
	}
	return freq
}

// modalByte returns the most frequent byte value and its count from a
// frequency histogram.
func modalByte(freq [256]int) (byte, int) {
	var m byte
	var c int
	for v, n := range freq {
		if n > c {
			c = n
			m = byte(v)
		}
	}
	return m, c
}

// significant reports whether the byte at offset within samples meets the
// attack/baseline thresholds, and if so returns the modal byte.
func significant(attack, baseline []Sample, offset int) (byte, bool) {
	totalAttack := len(attack)
	if totalAttack == 0 {
		return 0, false
	}
	afreq := byteFreq(attack, offset)
	ab, ac := modalByte(afreq)
	if float64(ac)/float64(totalAttack) < AttackThreshold {
		return 0, false
	}
	if len(baseline) > 0 {
		bfreq := byteFreq(baseline, offset)
		// Reject if the attack modal byte appears in >= 1% of baseline samples.
		if float64(bfreq[ab])/float64(len(baseline)) >= BaselineThreshold {
			return 0, false
		}
	}
	return ab, true
}

// Extract computes the best UDP payload signature from collected samples.
// Returns nil, false when no signature meets the thresholds.
func (e *Extractor) Extract() *bpf.UDPPayloadSigValue {
	e.mu.Lock()
	attack := append([]Sample(nil), e.attack...)
	baseline := append([]Sample(nil), e.baseline...)
	e.mu.Unlock()

	totalAttack := len(attack)
	if totalAttack < 256 {
		return nil // need a statistically meaningful sample
	}

	bestLen := 0
	bestConf := 0.0
	bestOffset := 0
	bestPattern := uint64(0)
	bestMask := uint64(0)

	// Scan every payload offset 0..56 (leaving room for an 8-byte load).
	for offset := 0; offset <= 56; offset++ {
		// Determine which positions within this 8-byte window are significant.
		var sig [8]struct {
			b   byte
			ok  bool
			conf float64
		}
		sigCount := 0
		for i := 0; i < 8; i++ {
			pos := offset + i
			if pos >= 64 {
				break
			}
			mb, ok := significant(attack, baseline, pos)
			if !ok {
				continue
			}
			// Compute confidence for this position.
			afreq := byteFreq(attack, pos)
			_, ac := modalByte(afreq)
			conf := float64(ac) / float64(totalAttack)
			sig[i] = struct {
				b    byte
				ok   bool
				conf float64
			}{mb, true, conf}
			sigCount++
		}

		// Find the longest contiguous run of significant positions with
		// length between MinPatternLen and MaxPatternLen.
		runStart := -1
		for i := 0; i <= 8; i++ {
			if i < 8 && sig[i].ok {
				if runStart < 0 {
					runStart = i
				}
				continue
			}
			if runStart >= 0 {
				runLen := i - runStart
				if runLen >= MinPatternLen && runLen <= MaxPatternLen {
					// Score: longer runs with higher confidence win.
					avgConf := 0.0
					for j := runStart; j < i; j++ {
						avgConf += sig[j].conf
					}
					avgConf /= float64(runLen)
					score := float64(runLen) * avgConf
					if score > bestConf || (score == bestConf && runLen > bestLen) {
						bestConf = score
						bestLen = runLen
						bestOffset = offset + runStart
						bestPattern = 0
						bestMask = 0
						for j := runStart; j < i; j++ {
							shift := uint((j - runStart) * 8)
							bestPattern |= uint64(sig[j].b) << shift
							bestMask |= uint64(0xFF) << shift
						}
					}
				}
				runStart = -1
			}
		}
	}

	if bestLen == 0 {
		return nil
	}

	return &bpf.UDPPayloadSigValue{
		Offset:  uint8(bestOffset),
		Len:     uint8(bestLen),
		Action:  bpf.FilterActionDrop,
		Pattern: bestPattern,
		Mask:    bestMask,
	}
}
