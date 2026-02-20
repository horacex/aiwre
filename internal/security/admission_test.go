package security

import (
	"strings"
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
	} else {
		got := err.Error()
		if !strings.Contains(got, "message expired") || !strings.Contains(got, "max_age=") {
			t.Fatalf("expected detailed expiry error, got: %q", got)
		}
	}
}

func TestAdmissionFutureSkewDetail(t *testing.T) {
	now := time.Date(2026, 2, 14, 12, 0, 0, 0, time.UTC)
	msgTs := now.Add(3 * time.Minute)
	msg := signedMessage(t, msgTs.Format(time.RFC3339), 300)
	policy := NewAdmissionPolicy()
	policy.Now = func() time.Time { return now }
	policy.AllowedSkew = 2 * time.Minute
	policy.Replay.SetClock(func() time.Time { return now })
	err := policy.Verify(msg)
	if err == nil {
		t.Fatal("expected future skew failure")
	}
	got := err.Error()
	if !strings.Contains(got, "timestamp is too far in future") || !strings.Contains(got, "allowed_skew=") {
		t.Fatalf("expected detailed future-skew error, got: %q", got)
	}
}
