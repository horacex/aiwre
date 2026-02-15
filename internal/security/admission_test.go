package security

import (
	"testing"
	"time"

	"github.com/horacex/aiwre/internal/protocol"
)

func signedMessage(t *testing.T, timestamp string, ttl int) *protocol.Message {
	t.Helper()
	_, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := &protocol.Message{
		Timestamp: timestamp,
		Topic:     "ops.heartbeat",
		Type:      protocol.TypeHeartbeat,
		TTL:       ttl,
		Nonce:     "deadbeefdeadbeefdeadbeefdeadbeef",
		Body:      "alive",
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestAdmissionReplay(t *testing.T) {
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	msg := signedMessage(t, now.Format(time.RFC3339), 120)
	policy := NewAdmissionPolicy()
	policy.Now = func() time.Time { return now }
	policy.Replay.SetClock(func() time.Time { return now })

	if err := policy.Verify(msg); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if err := policy.Verify(msg); err == nil {
		t.Fatal("expected replay failure")
	}
}

func TestAdmissionExpiry(t *testing.T) {
	ts := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	msg := signedMessage(t, ts.Format(time.RFC3339), 30)
	policy := NewAdmissionPolicy()
	future := ts.Add(31 * time.Second)
	policy.Now = func() time.Time { return future }
	policy.Replay.SetClock(func() time.Time { return future })
	if err := policy.Verify(msg); err == nil {
		t.Fatal("expected expiry failure")
	}
}
