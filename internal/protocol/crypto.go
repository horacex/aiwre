package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func NewNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func ComputeID(m *Message) (string, error) {
	payload := canonicalIDPayload{
		AiwreV:    m.AiwreV,
		Timestamp: m.Timestamp,
		Sender:    m.Sender,
		PubKey:    m.PubKey,
		Topic:     m.Topic,
		Type:      m.Type,
		TTL:       m.TTL,
		Nonce:     m.Nonce,
		Metadata:  m.Metadata,
		Body:      m.Body,
	}
	raw, err := marshalCanonical(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func signingBytes(m *Message) ([]byte, error) {
	payload := canonicalSignPayload{
		ID:        m.ID,
		AiwreV:    m.AiwreV,
		Timestamp: m.Timestamp,
		Sender:    m.Sender,
		PubKey:    m.PubKey,
		Topic:     m.Topic,
		Type:      m.Type,
		TTL:       m.TTL,
		Nonce:     m.Nonce,
		Metadata:  m.Metadata,
		Body:      m.Body,
	}
	return marshalCanonical(payload)
}

func SignMessage(m *Message, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("invalid private key size")
	}
	m.Normalize()
	if m.Nonce == "" {
		n, err := NewNonce()
		if err != nil {
			return err
		}
		m.Nonce = n
	}
	pub := priv.Public().(ed25519.PublicKey)
	m.PubKey = base64.RawStdEncoding.EncodeToString(pub)
	m.Sender = Fingerprint(pub)

	if err := m.ValidateUnsigned(); err != nil {
		return err
	}
	id, err := ComputeID(m)
	if err != nil {
		return err
	}
	m.ID = id
	raw, err := signingBytes(m)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, raw)
	m.Signature = base64.RawStdEncoding.EncodeToString(sig)
	return nil
}

func VerifyMessage(m *Message) error {
	if err := m.ValidateSigned(); err != nil {
		return err
	}
	pub, err := base64.RawStdEncoding.DecodeString(m.PubKey)
	if err != nil {
		return fmt.Errorf("invalid pubkey encoding: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}
	if Fingerprint(pub) != m.Sender {
		return errors.New("sender fingerprint mismatch")
	}
	expectedID, err := ComputeID(m)
	if err != nil {
		return err
	}
	if expectedID != m.ID {
		return errors.New("id mismatch")
	}
	raw, err := signingBytes(m)
	if err != nil {
		return err
	}
	sig, err := base64.RawStdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("invalid sig encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
