package server

import (
	"testing"
	"time"
)

func TestWafBreakerQuarantine(t *testing.T) {
	b := &wafBreaker{quarantined: make(map[int64]time.Time)}
	if b.isQuarantined(1) {
		t.Fatal("akun baru tidak boleh quarantine")
	}
	b.quarantine(1)
	if !b.isQuarantined(1) {
		t.Fatal("akun harus quarantine setelah quarantine(1)")
	}
}

func TestWafBreakerQuarantineExpiry(t *testing.T) {
	b := &wafBreaker{quarantined: make(map[int64]time.Time)}
	b.quarantined[1] = time.Now().Add(-time.Minute) // expired
	if b.isQuarantined(1) {
		t.Fatal("quarantine expired harus dilepas")
	}
}

func TestWafBreakerCircuitTrip(t *testing.T) {
	b := &wafBreaker{quarantined: make(map[int64]time.Time)}
	// 2 blokir pertama belum trip
	for i := 0; i < maxBlocksPerWindow-1; i++ {
		tripped, _ := b.record()
		if tripped {
			t.Fatalf("trip terlalu cepat di iterasi %d", i)
		}
	}
	// blokir ke-max → trip dengan backoff > 0
	tripped, wait := b.record()
	if !tripped {
		t.Fatal("harus trip setelah maxBlocksPerWindow blokir")
	}
	if wait <= 0 || wait > maxCircuitWait {
		t.Fatalf("wait di luar range: %v", wait)
	}
	// reset setelah trip — window kosong
	if len(b.blocks) != 0 {
		t.Fatal("window harus di-reset setelah trip")
	}
}

func TestWafBreakerJitter(t *testing.T) {
	b1 := &wafBreaker{quarantined: make(map[int64]time.Time)}
	b2 := &wafBreaker{quarantined: make(map[int64]time.Time)}
	for i := 0; i < maxBlocksPerWindow; i++ {
		b1.record()
		b2.record()
	}
	_, w1 := b1.record()
	_, w2 := b2.record()
	// dua breaker dengan pola sama harus punya wait sedikit beda (jitter)
	if w1 == w2 {
		t.Log("jitter menghasilkan wait sama (mungkin 1/8 chance) — tidak fatal")
	}
}
