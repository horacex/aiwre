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
}

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
