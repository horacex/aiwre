package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDMTopicDeterministic(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	gotAB := dmTopic(a, b)
	gotBA := dmTopic(b, a)
	want := "dm." + a + "." + b
	if gotAB != want {
		t.Fatalf("dmTopic(a,b)=%q want %q", gotAB, want)
	}
	if gotBA != want {
		t.Fatalf("dmTopic(b,a)=%q want %q", gotBA, want)
	}
}

func TestNormalizeTopicSegment(t *testing.T) {
	ok, err := normalizeTopicSegment(" Ops_Room-1 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok != "ops_room-1" {
		t.Fatalf("normalized=%q want %q", ok, "ops_room-1")
	}

	if _, err := normalizeTopicSegment("bad.room"); err == nil {
		t.Fatalf("expected invalid character error")
	}
}

func TestChatEncryptDecryptRoundTrip(t *testing.T) {
	secret := "shared-secret"
	topic := "room.ops"
	plain := "hello world"
	cipherB64, nonceB64, err := encryptChatBody(secret, topic, plain)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	got, err := decryptChatBody(secret, topic, cipherB64, nonceB64)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if got != plain {
		t.Fatalf("plain=%q want %q", got, plain)
	}

	if _, err := decryptChatBody("wrong-secret", topic, cipherB64, nonceB64); err == nil {
		t.Fatalf("expected decrypt failure with wrong secret")
	}
}

func TestDecryptInvalidNonceSize(t *testing.T) {
	_, err := decryptChatBody("x", "room.ops", "AQID", "AQID")
	if err == nil {
		t.Fatalf("expected nonce size error")
	}
}

func TestCursorStateMonotonicSet(t *testing.T) {
	st := &cursorState{}
	st.set("global.announce", 0, 10)
	st.set("global.announce", 0, 8)
	st.set("global.announce", 0, 25)

	got, ok := st.get("global.announce", 0)
	if !ok {
		t.Fatalf("missing cursor")
	}
	if got != 25 {
		t.Fatalf("cursor=%d want=25", got)
	}
}

func TestCursorStateSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cursor.json")

	st := &cursorState{
		Version: 1,
		Cursors: map[string]int64{
			cursorKey("room.ops", 3): 99,
		},
	}
	if err := saveCursorState(path, st); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got := loadCursorState(path)
	v, ok := got.get("room.ops", 3)
	if !ok {
		t.Fatalf("missing saved cursor")
	}
	if v != 99 {
		t.Fatalf("loaded cursor=%d want=99", v)
	}
}
