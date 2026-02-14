package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	Version          = "1.0"
	DefaultTTL       = 300
	MaxTTL           = 86400
	MaxClockSkew     = 2 * time.Minute
	MaxMetadataDepth = 3
)

type MessageType string

const (
	TypeBroadcast MessageType = "broadcast"
	TypeQuery     MessageType = "query"
	TypeResponse  MessageType = "response"
	TypeHeartbeat MessageType = "heartbeat"
)

var allowedTypes = map[MessageType]struct{}{
	TypeBroadcast: {},
	TypeQuery:     {},
	TypeResponse:  {},
	TypeHeartbeat: {},
}

var topicPattern = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_-]+)+$`)

// Message is the v0.1 canonical in-memory representation of Signal-MD.
type Message struct {
	AiwreV    string         `json:"aiwre_v"`
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp"`
	Sender    string         `json:"sender"`
	PubKey    string         `json:"pubkey"`
	Topic     string         `json:"topic"`
	Type      MessageType    `json:"type"`
	TTL       int            `json:"ttl"`
	Nonce     string         `json:"nonce"`
	Metadata  map[string]any `json:"metadata"`
	Body      string         `json:"body"`
	Signature string         `json:"sig"`
}

func (m *Message) Normalize() {
	if m.AiwreV == "" {
		m.AiwreV = Version
	}
	if m.Timestamp == "" {
		m.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if m.TTL == 0 {
		m.TTL = DefaultTTL
	}
	if m.Metadata == nil {
		m.Metadata = map[string]any{}
	}
}

func (m *Message) ValidateUnsigned() error {
	if m.AiwreV != Version {
		return fmt.Errorf("unsupported aiwre_v %q", m.AiwreV)
	}
	if _, err := time.Parse(time.RFC3339, m.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if m.Topic == "" || !topicPattern.MatchString(m.Topic) {
		return errors.New("topic must match namespace.topic")
	}
	if _, ok := allowedTypes[m.Type]; !ok {
		return fmt.Errorf("invalid type %q", m.Type)
	}
	if m.TTL < 1 || m.TTL > MaxTTL {
		return fmt.Errorf("ttl out of range: %d", m.TTL)
	}
	if m.Nonce == "" {
		return errors.New("nonce is required")
	}
	if err := validateMetadataDepth(m.Metadata, 1); err != nil {
		return err
	}
	return nil
}

func (m *Message) ValidateSigned() error {
	if err := m.ValidateUnsigned(); err != nil {
		return err
	}
	if m.ID == "" {
		return errors.New("id is required")
	}
	if m.Sender == "" {
		return errors.New("sender is required")
	}
	if m.PubKey == "" {
		return errors.New("pubkey is required")
	}
	if m.Signature == "" {
		return errors.New("sig is required")
	}
	return nil
}

func validateMetadataDepth(v any, depth int) error {
	if depth > MaxMetadataDepth {
		return fmt.Errorf("metadata nesting exceeds max depth %d", MaxMetadataDepth)
	}
	switch t := v.(type) {
	case nil, string, bool, int, int64, int32, uint, uint64, uint32, json.Number:
		return nil
	case map[string]any:
		for _, vv := range t {
			if err := validateMetadataDepth(vv, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, vv := range t {
			if err := validateMetadataDepth(vv, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported metadata type %T", v)
	}
}

func Fingerprint(pub []byte) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])
}
