package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/horacex/aiwre/internal/protocol"
	"github.com/horacex/aiwre/internal/transport"
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

func TestNormalizeAgentIDURI(t *testing.T) {
	got, err := normalizeAgentIDURI("aiwre:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "aiwre:" + strings.Repeat("a", 64)
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}

	if _, err := normalizeAgentIDURI("bad:" + strings.Repeat("a", 64)); err == nil {
		t.Fatalf("expected prefix validation error")
	}
}

func TestParseAgentIDQuery(t *testing.T) {
	sender := strings.Repeat("b", 64)
	gotSender, gotAlias, err := parseAgentIDQuery("aiwre:" + sender)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotSender != sender || gotAlias != "" {
		t.Fatalf("sender parse mismatch: sender=%q alias=%q", gotSender, gotAlias)
	}

	gotSender, gotAlias, err = parseAgentIDQuery("agent-node@relay.aiwre.io")
	if err != nil {
		t.Fatalf("unexpected alias error: %v", err)
	}
	if gotSender != "" || gotAlias != "agent-node@relay.aiwre.io" {
		t.Fatalf("alias parse mismatch: sender=%q alias=%q", gotSender, gotAlias)
	}
}

func TestNormalizeAgentAliasWithRelay(t *testing.T) {
	got, err := normalizeAgentAlias("Node_One", "https://relay.aiwre.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "node_one@relay.aiwre.io" {
		t.Fatalf("got=%q want=%q", got, "node_one@relay.aiwre.io")
	}

	got, err = normalizeAgentAlias("ops-bot@mesh.aiwre.net", "https://relay.aiwre.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ops-bot@mesh.aiwre.net" {
		t.Fatalf("got=%q", got)
	}
}

func TestParseCSV(t *testing.T) {
	got := parseCSV("stream, dm ,STREAM,room,,dm")
	want := []string{"stream", "dm", "room"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}

func TestInteractionSelectedForReplyDeterministic(t *testing.T) {
	self := strings.Repeat("a", 64)
	msgID := strings.Repeat("b", 64)
	mod := 32

	got1 := interactionSelectedForReply(self, msgID, mod)
	got2 := interactionSelectedForReply(self, msgID, mod)
	if got1 != got2 {
		t.Fatalf("selection must be deterministic")
	}

	// mod<=1 should always select.
	if !interactionSelectedForReply(self, msgID, 1) {
		t.Fatalf("mod=1 should always select")
	}
}

func TestInteractionStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "interaction.json")
	st := &interactionState{
		Version:      1,
		Day:          "2026-02-16",
		RepliesToday: 3,
		LastReplyAt:  time.Now().UTC().Format(time.RFC3339),
		Replied: map[string]string{
			strings.Repeat("a", 64): time.Now().UTC().Format(time.RFC3339),
		},
	}
	if err := saveInteractionState(path, st); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file missing: %v", err)
	}
	got := loadInteractionState(path)
	if got.Day != st.Day || got.RepliesToday != st.RepliesToday {
		t.Fatalf("roundtrip mismatch: got=%+v want=%+v", got, st)
	}
	if len(got.Replied) != 1 {
		t.Fatalf("unexpected replied size: %d", len(got.Replied))
	}
}

func TestParseSemver(t *testing.T) {
	v, ok := parseSemver("v1.2.3")
	if !ok {
		t.Fatalf("expected valid semver")
	}
	if v.Major != 1 || v.Minor != 2 || v.Patch != 3 {
		t.Fatalf("unexpected semver parse: %+v", v)
	}
	if _, ok := parseSemver("dev"); ok {
		t.Fatalf("dev should not parse as semver")
	}
}

func TestCompareSemver(t *testing.T) {
	a, _ := parseSemver("1.4.0")
	b, _ := parseSemver("1.3.9")
	if compareSemver(a, b) <= 0 {
		t.Fatalf("expected 1.4.0 > 1.3.9")
	}
	if compareSemver(b, a) >= 0 {
		t.Fatalf("expected 1.3.9 < 1.4.0")
	}
	if compareSemver(a, a) != 0 {
		t.Fatalf("same version should compare equal")
	}
}

func TestParseChecksums(t *testing.T) {
	raw := "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd  aiwre_1.2.3_linux_amd64.tar.gz\n" +
		"1234123412341234123412341234123412341234123412341234123412341234 *aiwre_1.2.3_darwin_arm64.tar.gz\n"
	got := parseChecksums(raw)
	if got["aiwre_1.2.3_linux_amd64.tar.gz"] == "" {
		t.Fatalf("missing linux checksum")
	}
	if got["aiwre_1.2.3_darwin_arm64.tar.gz"] == "" {
		t.Fatalf("missing darwin checksum")
	}
}

func TestWithinRolloutDeterministic(t *testing.T) {
	id := strings.Repeat("a", 64)
	a := withinRollout(id, 25)
	b := withinRollout(id, 25)
	if a != b {
		t.Fatalf("rollout selection must be deterministic")
	}
	if !withinRollout(id, 100) {
		t.Fatalf("100%% rollout should include all")
	}
	if withinRollout(id, 0) {
		t.Fatalf("0%% rollout should include none")
	}
}

func TestBoundedJitter(t *testing.T) {
	max := 150 * time.Millisecond
	for i := 0; i < 20; i++ {
		d := boundedJitter(max)
		if d < 0 || d > max {
			t.Fatalf("jitter out of bounds: %s", d)
		}
	}
	if boundedJitter(0) != 0 {
		t.Fatalf("zero bound should return zero")
	}
}

func TestResolveChatConfigPathDefault(t *testing.T) {
	dir := t.TempDir()
	path, ok, err := resolveChatConfigPath(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected no config when file missing, got %s", path)
	}

	cfgPath := filepath.Join(dir, defaultChatConfigName)
	if err := os.WriteFile(cfgPath, []byte(`{"dm":[],"rooms":[]}`), 0644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}
	path, ok, err = resolveChatConfigPath(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || path != cfgPath {
		t.Fatalf("expected default config path, got ok=%v path=%s", ok, path)
	}
}

func TestNewChatRuntimeLoadsTopics(t *testing.T) {
	dir := t.TempDir()
	cfg := chatConfigFile{
		DM: []chatDMConfig{
			{Peer: strings.Repeat("b", 64), Secret: "dm-secret"},
		},
		Rooms: []chatRoomConfig{
			{Room: "ops", Secret: "room-secret"},
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	cfgPath := filepath.Join(dir, defaultChatConfigName)
	if err := os.WriteFile(cfgPath, raw, 0644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}
	self := strings.Repeat("a", 64)
	rt, err := newChatRuntime(
		"https://relay.aiwre.io",
		dir,
		self,
		make(ed25519.PrivateKey, ed25519.PrivateKeySize),
		"",
		true,
		90*time.Second,
		8,
	)
	if err != nil {
		t.Fatalf("newChatRuntime error: %v", err)
	}
	if rt == nil {
		t.Fatalf("expected runtime")
	}
	got := rt.watchTopics()
	wantDM := dmTopic(self, strings.Repeat("b", 64))
	want := []string{wantDM, "room.ops"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topics mismatch: got=%v want=%v", got, want)
	}
}

func TestNormalizeChatReplyMode(t *testing.T) {
	if got := normalizeChatReplyMode("unknown", "query"); got != "query" {
		t.Fatalf("fallback mismatch: %s", got)
	}
	if got := normalizeChatReplyMode("mention", "query"); got != "mention" {
		t.Fatalf("mode mismatch: %s", got)
	}
}

func TestParseAllowedMessageTypes(t *testing.T) {
	types, err := parseAllowedMessageTypes("broadcast,query,response,heartbeat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(types) != 4 {
		t.Fatalf("unexpected type count: %d", len(types))
	}
	if _, err := parseAllowedMessageTypes("broadcast,unknown_type"); err == nil {
		t.Fatalf("expected invalid type error")
	}
}

func TestContentPolicyCheck(t *testing.T) {
	p, err := newContentPolicy(10, 64, 3, "broadcast", "global.")
	if err != nil {
		t.Fatalf("policy create failed: %v", err)
	}
	okMsg := &protocol.Message{
		Topic: "global.announce",
		Type:  protocol.TypeBroadcast,
		Body:  "hello",
	}
	if err := p.check(okMsg, okMsg.Topic); err != nil {
		t.Fatalf("unexpected policy reject: %v", err)
	}

	tooLarge := &protocol.Message{
		Topic: "global.announce",
		Type:  protocol.TypeBroadcast,
		Body:  "hello world over ten bytes",
	}
	if err := p.check(tooLarge, tooLarge.Topic); err == nil {
		t.Fatalf("expected body size rejection")
	}

	wrongType := &protocol.Message{
		Topic: "global.announce",
		Type:  protocol.TypeQuery,
		Body:  "hi",
	}
	if err := p.check(wrongType, wrongType.Topic); err == nil {
		t.Fatalf("expected type rejection")
	}

	wrongTopic := &protocol.Message{
		Topic: "room.ops",
		Type:  protocol.TypeBroadcast,
		Body:  "hi",
	}
	if err := p.check(wrongTopic, wrongTopic.Topic); err == nil {
		t.Fatalf("expected topic rejection")
	}

	metaTooDeep := &protocol.Message{
		Topic: "global.announce",
		Type:  protocol.TypeBroadcast,
		Body:  "hi",
		Metadata: map[string]any{
			"a": map[string]any{
				"b": map[string]any{
					"c": map[string]any{"d": "too-deep"},
				},
			},
		},
	}
	if err := p.check(metaTooDeep, metaTooDeep.Topic); err == nil {
		t.Fatalf("expected metadata depth rejection")
	}

	metaTooLarge := &protocol.Message{
		Topic: "global.announce",
		Type:  protocol.TypeBroadcast,
		Body:  "hi",
		Metadata: map[string]any{
			"payload": strings.Repeat("x", 128),
		},
	}
	if err := p.check(metaTooLarge, metaTooLarge.Topic); err == nil {
		t.Fatalf("expected metadata size rejection")
	}
}

func TestParseRelayCandidatesAndMerge(t *testing.T) {
	in := " https://relay.aiwre.io/,https://relay-backup.aiwre.io ,https://relay.aiwre.io "
	got := parseRelayCandidates(in)
	want := []string{"https://relay.aiwre.io", "https://relay-backup.aiwre.io"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseRelayCandidates mismatch: got=%v want=%v", got, want)
	}

	profile := &transport.BootstrapProfile{
		Relay:  "https://relay-alt.aiwre.io/",
		Relays: []string{"https://relay-third.aiwre.io", "https://relay.aiwre.io"},
	}
	merged := relayCandidatesFromBootstrap(in, "https://relay-primary.aiwre.io", profile)
	wantMerged := []string{
		"https://relay-primary.aiwre.io",
		"https://relay.aiwre.io",
		"https://relay-backup.aiwre.io",
		"https://relay-alt.aiwre.io",
		"https://relay-third.aiwre.io",
	}
	if !reflect.DeepEqual(merged, wantMerged) {
		t.Fatalf("relayCandidatesFromBootstrap mismatch: got=%v want=%v", merged, wantMerged)
	}
}

func TestIsRateLimitedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "429", err: errors.New("feed cursor failed: status=429 body={\"error\":\"rate limited\"}"), want: true},
		{name: "budget", err: errors.New("status=429 body={\"error\":\"budget limit reached\"}"), want: true},
		{name: "other", err: errors.New("status=500 body={\"error\":\"oops\"}"), want: false},
	}
	for _, tc := range cases {
		got := isRateLimitedError(tc.err)
		if got != tc.want {
			t.Fatalf("%s: got=%v want=%v", tc.name, got, tc.want)
		}
	}
}

func TestRunKeygenCreatesOutputDir(t *testing.T) {
	base := t.TempDir()
	out := filepath.Join(base, "nested", "keys")
	if err := runKeygen([]string{"--out-dir", out}); err != nil {
		t.Fatalf("runKeygen failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "ed25519_private.key")); err != nil {
		t.Fatalf("private key not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "ed25519_public.key")); err != nil {
		t.Fatalf("public key not created: %v", err)
	}
}

func TestPullAndDecryptChatWithFailoverEmptyRelays(t *testing.T) {
	_, _, err := pullAndDecryptChatWithFailover(nil, "room.ops", "secret", 10, t.TempDir(), true, "room")
	if err == nil {
		t.Fatalf("expected error for empty relay candidates")
	}
}
