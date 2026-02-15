package security

import (
	"sync"
	"time"
)

// ReplayGuard is an in-memory replay detector keyed by message id.
type ReplayGuard struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string]time.Time
	ops  uint64
}

const (
	// replayMaxEntries caps the in-memory replay table size to avoid unbounded growth
	// in long-running agent processes (e.g. stream/autojoin).
	replayMaxEntries = 50_000
	// replayPruneEvery amortizes prune cost; prune is O(n).
	replayPruneEvery = 1_000
)

func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{
		now:  time.Now,
		seen: make(map[string]time.Time),
	}
}

func (r *ReplayGuard) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

func (r *ReplayGuard) Seen(id string, ttl time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.now()
	r.ops++
	if r.ops%replayPruneEvery == 0 || len(r.seen) > replayMaxEntries {
		for k, exp := range r.seen {
			if !current.Before(exp) {
				delete(r.seen, k)
			}
		}
		// Hard cap: if still too large (e.g. sustained high volume), evict an
		// arbitrary subset. This trades strict replay coverage for bounded memory.
		if over := len(r.seen) - replayMaxEntries; over > 0 {
			for k := range r.seen {
				delete(r.seen, k)
				over--
				if over <= 0 {
					break
				}
			}
		}
	}
	if exp, ok := r.seen[id]; ok && current.Before(exp) {
		return true
	}
	r.seen[id] = current.Add(ttl)
	return false
}

func (r *ReplayGuard) Prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.now()
	for id, exp := range r.seen {
		if !current.Before(exp) {
			delete(r.seen, id)
		}
	}
}
