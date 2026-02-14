package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

type canonicalIDPayload struct {
	AiwreV    string         `json:"aiwre_v"`
	Timestamp string         `json:"timestamp"`
	Sender    string         `json:"sender"`
	PubKey    string         `json:"pubkey"`
	Topic     string         `json:"topic"`
	Type      MessageType    `json:"type"`
	TTL       int            `json:"ttl"`
	Nonce     string         `json:"nonce"`
	Metadata  map[string]any `json:"metadata"`
	Body      string         `json:"body"`
}

type canonicalSignPayload struct {
	ID        string         `json:"id"`
	AiwreV    string         `json:"aiwre_v"`
	Timestamp string         `json:"timestamp"`
	Sender    string         `json:"sender"`
	PubKey    string         `json:"pubkey"`
	Topic     string         `json:"topic"`
	Type      MessageType    `json:"type"`
	TTL       int            `json:"ttl"`
	Nonce     string         `json:"nonce"`
	Metadata  map[string]any `json:"metadata"`
	Body      string         `json:"body"`
}

func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		raw, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(raw)
	case int:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(t), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(t), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(t, 10))
	case float64:
		return fmt.Errorf("float64 not allowed in canonical payload")
	case json.Number:
		buf.WriteString(t.String())
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kk, _ := json.Marshal(k)
			buf.Write(kk)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, vv := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, vv); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		// Normalize structs and typed collections through JSON first, then
		// canonicalize the decoded generic representation.
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("unsupported canonical type %T", v)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var normalized any
		if err := dec.Decode(&normalized); err != nil {
			return err
		}
		return writeCanonical(buf, normalized)
	}
	return nil
}
