package protocol

import (
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := &Message{
		Topic: "ops.alerts",
		Type:  TypeBroadcast,
		Nonce: "00112233445566778899aabbccddeeff",
		Metadata: map[string]any{
			"priority": "high",
			"tags":     []any{"security", "net"},
		},
		Body: "# Subject\n\nAIWRE online.\n",
	}
	if err := SignMessage(msg, priv); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessage(msg); err != nil {
		t.Fatal(err)
	}
	raw, err := RenderSignalMD(msg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignalMD(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessage(parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.ID != msg.ID {
		t.Fatalf("id mismatch: got=%s want=%s", parsed.ID, msg.ID)
	}
}

func TestTamperFailsVerification(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := &Message{
		Topic: "mesh.sync",
		Type:  TypeResponse,
		Nonce: "abcabcabcabcabcabcabcabcabcabcab",
		Body:  "original payload",
	}
	if err := SignMessage(msg, priv); err != nil {
		t.Fatal(err)
	}
	msg.Body = "tampered payload"
	if err := VerifyMessage(msg); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestMetadataDepthLimit(t *testing.T) {
	msg := &Message{
		AiwreV:    Version,
		Timestamp: "2026-01-01T00:00:00Z",
		Topic:     "mesh.depth",
		Type:      TypeBroadcast,
		TTL:       10,
		Nonce:     "abc",
		Metadata: map[string]any{
			"a": map[string]any{
				"b": map[string]any{
					"c": map[string]any{
						"d": true,
					},
				},
			},
		},
	}
	if err := msg.ValidateUnsigned(); err == nil {
		t.Fatal("expected metadata depth validation failure")
	}
}

func TestCodecRejectsUnknownHeader(t *testing.T) {
	raw := strings.Join([]string{
		"---",
		"aiwre_v: 1.0",
		"timestamp: 2026-01-01T00:00:00Z",
		"topic: mesh.test",
		"type: broadcast",
		"ttl: 10",
		"nonce: 123",
		"metadata: {}",
		"foo: bar",
		"---",
		"body",
	}, "\n")
	if _, err := ParseSignalMD(raw); err == nil {
		t.Fatal("expected parse failure for unknown header")
	}
}

func TestNumericMetadataRoundTrip(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := &Message{
		Topic: "mesh.metrics",
		Type:  TypeBroadcast,
		Nonce: "11223344556677889900aabbccddeeff",
		Metadata: map[string]any{
			"seq":    42,
			"worker": 7,
		},
		Body: "metrics payload\n",
	}
	if err := SignMessage(msg, priv); err != nil {
		t.Fatal(err)
	}
	raw, err := RenderSignalMD(msg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignalMD(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessage(parsed); err != nil {
		t.Fatalf("verify parsed failed: %v", err)
	}
}
