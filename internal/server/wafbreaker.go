// Package server — WAF circuit breaker + account quarantine (PRD 4.4).
//
// Mencegah blind failover loop: saat upstream WAF (403) mem-blokir, jangan
// langsung lempar request yang sama ke akun berikutnya dalam milidetik —
// WAF mem-blokir berdasarkan IP/fingerprint, bukan akun, jadi failover
// cepat cuma membakar seluruh pool tanpa hasil.
package server

import (
	"math/rand"
	"sync"
	"time"
)

const (
	// PRD 4.4: akun yang kena WAF 403 di-quarantine minimum 15 menit.
	quarantineDuration = 15 * time.Minute
	// Sliding window untuk menghitung laju blokir beruntun.
	wafBlockWindow = 5 * time.Minute
	// Batas blokir dalam window sebelum circuit trip.
	maxBlocksPerWindow = 3
	// Cap tunggu maksimal circuit trip (jangan sampai berjam-jam).
	maxCircuitWait = 60 * time.Second
)

// wafBreaker melacak akun yang kena WAF block dan menahan request saat
// blokir terjadi beruntun (circuit trip). In-memory, reset saat restart —
// quarantine persisten di level DB tidak diperlukan karena blokir WAF
// berbasis IP/fingerprint yang biasanya lebar dalam hitungan menit.
type wafBreaker struct {
	mu           sync.Mutex
	quarantined  map[int64]time.Time // account ID → quarantine until
	blocks       []time.Time         // timestamp blokir (sliding window)
	trippedUntil time.Time
}

var breaker = &wafBreaker{quarantined: make(map[int64]time.Time)}

// quarantine menandai akun kena WAF block selama quarantineDuration.
func (b *wafBreaker) quarantine(accountID int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.quarantined[accountID] = time.Now().Add(quarantineDuration)
}

// isQuarantined mengembalikan true jika akun masih dalam masa quarantine.
// Entry expired dihapus otomatis (lazily).
func (b *wafBreaker) isQuarantined(accountID int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.quarantined[accountID]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(b.quarantined, accountID)
		return false
	}
	return true
}

// record memcatat blokir WAF baru. Return: (tripped, waitDuration).
// Jika jumlah blokir dalam sliding window ≥ maxBlocksPerWindow, circuit
// trip: caller menunggu waitDuration (exponential backoff + jitter, PRD
// 4.4) sebelum mencoba akun berikutnya — memberi WAF waktu untuk
// "melupakan" fingerprint kita.
func (b *wafBreaker) record() (tripped bool, wait time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()

	// Buang blokir di luar sliding window.
	keep := b.blocks[:0]
	for _, t := range b.blocks {
		if now.Sub(t) < wafBlockWindow {
			keep = append(keep, t)
		}
	}
	b.blocks = append(keep, now)

	if len(b.blocks) < maxBlocksPerWindow {
		return false, 0
	}

	// Exponential backoff with jitter (PRD 4.4): 2s → 4s → 8s → 16s → 32s
	// (+ jitter acak 0–1s), cap di maxCircuitWait.
	if now.Before(b.trippedUntil) {
		return true, time.Until(b.trippedUntil)
	}
	attempt := len(b.blocks) - maxBlocksPerWindow + 1
	if attempt > 5 {
		attempt = 5
	}
	wait = time.Duration(1<<uint(attempt)) * time.Second
	wait += time.Duration(rand.Int63n(int64(time.Second)))
	if wait > maxCircuitWait {
		wait = maxCircuitWait
	}
	b.trippedUntil = now.Add(wait)
	b.blocks = nil // reset window setelah trip — mulai hitung ulang
	return true, wait
}
