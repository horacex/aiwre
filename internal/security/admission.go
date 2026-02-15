package security

import (
	"fmt"
	"time"

	"github.com/horacex/aiwre/internal/protocol"
)

// AdmissionPolicy validates cryptographic correctness plus freshness and replay checks.
type AdmissionPolicy struct {
	Now           func() time.Time
	AllowedSkew   time.Duration
	DefaultMaxAge time.Duration
	Replay        *ReplayGuard
}

func NewAdmissionPolicy() *AdmissionPolicy {
	return &AdmissionPolicy{
		Now:           time.Now,
		AllowedSkew:   protocol.MaxClockSkew,
		DefaultMaxAge: time.Duration(protocol.MaxTTL) * time.Second,
		Replay:        NewReplayGuard(),
	}
}

func (p *AdmissionPolicy) Verify(msg *protocol.Message) error {
	if err := protocol.VerifyMessage(msg); err != nil {
		return err
	}
	now := p.Now()
	ts, err := time.Parse(time.RFC3339, msg.Timestamp)
	if err != nil {
		return err
	}
	if ts.After(now.Add(p.AllowedSkew)) {
		return fmt.Errorf("timestamp is too far in future")
	}
	age := now.Sub(ts)
	maxAge := time.Duration(msg.TTL) * time.Second
	if maxAge <= 0 || maxAge > p.DefaultMaxAge {
		maxAge = p.DefaultMaxAge
	}
	if age > maxAge {
		return fmt.Errorf("message expired")
	}
	if p.Replay != nil && p.Replay.Seen(msg.ID, maxAge) {
		return fmt.Errorf("replay detected")
	}
	return nil
}
