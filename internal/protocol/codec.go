package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func ParseSignalMD(raw string) (*Message, error) {
	const delim = "---\n"
	if !strings.HasPrefix(raw, delim) {
		return nil, errors.New("signal must start with frontmatter delimiter")
	}
	rest := strings.TrimPrefix(raw, delim)
	idx := strings.Index(rest, "\n---\n")
	if idx == -1 {
		return nil, errors.New("missing closing frontmatter delimiter")
	}
	headerBlock := rest[:idx]
	body := rest[idx+5:]

	msg := &Message{Metadata: map[string]any{}, Body: body}
	lines := strings.Split(headerBlock, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header line %q", line)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.TrimSpace(val)
		switch key {
		case "aiwre_v":
			msg.AiwreV = val
		case "id":
			msg.ID = val
		case "timestamp":
			msg.Timestamp = val
		case "sender":
			msg.Sender = val
		case "pubkey":
			msg.PubKey = val
		case "topic":
			msg.Topic = val
		case "type":
			msg.Type = MessageType(val)
		case "ttl":
			ttl, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("invalid ttl: %w", err)
			}
			msg.TTL = ttl
		case "nonce":
			msg.Nonce = val
		case "metadata":
			dec := json.NewDecoder(strings.NewReader(val))
			dec.UseNumber()
			if err := dec.Decode(&msg.Metadata); err != nil {
				return nil, fmt.Errorf("invalid metadata json: %w", err)
			}
		case "sig":
			msg.Signature = val
		default:
			return nil, fmt.Errorf("unknown header key %q", key)
		}
	}
	if msg.Metadata == nil {
		msg.Metadata = map[string]any{}
	}
	return msg, nil
}

func RenderSignalMD(m *Message) (string, error) {
	metadata, err := marshalCanonical(m.Metadata)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	buf.WriteString("---\n")
	buf.WriteString("aiwre_v: " + m.AiwreV + "\n")
	buf.WriteString("id: " + m.ID + "\n")
	buf.WriteString("timestamp: " + m.Timestamp + "\n")
	buf.WriteString("sender: " + m.Sender + "\n")
	buf.WriteString("pubkey: " + m.PubKey + "\n")
	buf.WriteString("topic: " + m.Topic + "\n")
	buf.WriteString("type: " + string(m.Type) + "\n")
	buf.WriteString("ttl: " + strconv.Itoa(m.TTL) + "\n")
	buf.WriteString("nonce: " + m.Nonce + "\n")
	buf.WriteString("metadata: " + string(metadata) + "\n")
	buf.WriteString("sig: " + m.Signature + "\n")
	buf.WriteString("---\n")
	buf.WriteString(m.Body)
	return buf.String(), nil
}
