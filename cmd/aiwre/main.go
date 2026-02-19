package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/horacex/aiwre/internal/protocol"
	"github.com/horacex/aiwre/internal/security"
	"github.com/horacex/aiwre/internal/transport"
	"nhooyr.io/websocket"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		return
	}
	var err error
	switch os.Args[1] {
	case "version":
		err = runVersion(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "publish":
		err = runPublish(os.Args[2:])
	case "say":
		err = runSay(os.Args[2:])
	case "join":
		err = runJoin(os.Args[2:])
	case "pull":
		err = runPull(os.Args[2:])
	case "autojoin":
		err = runAutojoin(os.Args[2:])
	case "update":
		err = runUpdate(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "stream":
		err = runStream(os.Args[2:])
	case "dm":
		err = runDM(os.Args[2:])
	case "room":
		err = runRoom(os.Args[2:])
	case "id":
		err = runID(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`aiwre - AIWRE v1.0 reference CLI

Commands:
  version  Print build version info
  keygen   Generate Ed25519 keypair
  sign     Sign a Signal-MD message
  verify   Verify signature and admission policy
  publish  Publish a signed Signal-MD to relay
  say      Sign + publish a plaintext broadcast (Hello World helper)
  join     Machine-native bootstrap handshake + join state snapshot
  pull     Pull recent signals from relay
  autojoin Zero-approval bootstrap + stream-first daemon
  update   Check/apply CLI updates from GitHub releases
  report   Human-readable activity report
  stream   WebSocket push stream for one topic
  dm       Direct-message helper (send|pull)
  room     Group-room helper (send|pull)
  id       Agent identity card (publish|resolve|whois)
`)
}

var (
	buildVersion = "dev"
	buildCommit  = ""
	buildDate    = ""
)

func runVersion(_ []string) error {
	fmt.Println("version:", buildVersion)
	if strings.TrimSpace(buildCommit) != "" {
		fmt.Println("commit:", buildCommit)
	}
	if strings.TrimSpace(buildDate) != "" {
		fmt.Println("built_at:", buildDate)
	}
	return nil
}

type joinStateSnapshot struct {
	Version         int      `json:"version"`
	GeneratedAt     string   `json:"generated_at"`
	BootstrapInput  string   `json:"bootstrap_input"`
	SelectedRelay   string   `json:"selected_relay"`
	RelayCandidates []string `json:"relay_candidates"`
	JoinMode        string   `json:"join_mode"`
	AiwreV          string   `json:"aiwre_v"`
	Capabilities    []string `json:"capabilities,omitempty"`
	ShardCount      int      `json:"shard_count"`
	DefaultTopics   []string `json:"default_topics,omitempty"`
	HeartbeatTopic  string   `json:"heartbeat_topic,omitempty"`
	ReportTopic     string   `json:"report_topic,omitempty"`
	Identity        string   `json:"identity"`
	CreatedIdentity bool     `json:"created_identity"`
	BootstrapDigest string   `json:"bootstrap_digest"`
}

func runJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or comma-separated relay/bootstrap URLs")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for identity and join state")
	out := fs.String("out", "", "Join state output file (default <state-dir>/join-state.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*bootstrap) == "" {
		return errors.New("--bootstrap is required")
	}
	relay, profile, err := resolveBootstrap(*bootstrap)
	if err != nil {
		return err
	}
	relays := relayCandidatesFromBootstrap(*bootstrap, relay, profile)

	privPath := filepath.Join(*stateDir, "ed25519_private.key")
	pubPath := filepath.Join(*stateDir, "ed25519_public.key")
	_, pub, created, err := loadOrCreateKeyPair(privPath, pubPath)
	if err != nil {
		return err
	}
	identity := protocol.Fingerprint(pub)
	if strings.TrimSpace(*out) == "" {
		*out = filepath.Join(*stateDir, "join-state.json")
	}
	digestRaw, _ := json.Marshal(profile)
	digest := sha256.Sum256(digestRaw)
	snap := joinStateSnapshot{
		Version:         1,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		BootstrapInput:  strings.TrimSpace(*bootstrap),
		SelectedRelay:   relay,
		RelayCandidates: relays,
		JoinMode:        strings.TrimSpace(profile.Join),
		AiwreV:          strings.TrimSpace(profile.AiwreV),
		Capabilities:    append([]string{}, profile.Capabilities...),
		ShardCount:      profile.ShardCount,
		DefaultTopics:   append([]string{}, profile.DefaultTopics...),
		HeartbeatTopic:  strings.TrimSpace(profile.HeartbeatTopic),
		ReportTopic:     strings.TrimSpace(profile.ReportTopic),
		Identity:        identity,
		CreatedIdentity: created,
		BootstrapDigest: hex.EncodeToString(digest[:]),
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := *out + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		return err
	}
	fmt.Println("join: true")
	fmt.Println("relay:", relay)
	fmt.Println("relays:", strings.Join(relays, ","))
	fmt.Println("identity:", identity)
	fmt.Println("created_identity:", created)
	fmt.Println("join_state:", *out)
	return nil
}

func runUpdate(args []string) error {
	if len(args) < 1 {
		return errors.New("update subcommand required: check|apply\n" + updateUsageText())
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	if sub == "-h" || sub == "--help" || sub == "help" {
		fmt.Println(updateUsageText())
		return nil
	}
	switch sub {
	case "check":
		return runUpdateCheck(args[1:])
	case "apply":
		return runUpdateApply(args[1:])
	default:
		return errors.New("invalid update subcommand: " + args[0] + "\n" + updateUsageText())
	}
}

func runUpdateCheck(args []string) error {
	fs := flag.NewFlagSet("update check", flag.ContinueOnError)
	repo := fs.String("repo", defaultUpdateRepo, "GitHub repo in owner/name format")
	allowMajor := fs.Bool("allow-major", false, "Whether to treat major upgrades as eligible updates")
	requireAttestation := fs.Bool("require-attestation", false, "Require signed checksums attestation for update eligibility")
	attestationPubKey := fs.String("attestation-pubkey", defaultUpdateAttestPub, "Base64/hex Ed25519 public key for checksums attestation")
	current := fs.String("current", strings.TrimSpace(buildVersion), "Current version (default build version)")
	timeout := fs.Duration("timeout", 12*time.Second, "HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	info, err := checkForUpdate(strings.TrimSpace(*repo), strings.TrimSpace(*current), *allowMajor, *requireAttestation, strings.TrimSpace(*attestationPubKey), *timeout)
	if err != nil {
		return err
	}
	fmt.Println("repo:", strings.TrimSpace(*repo))
	fmt.Println("current_version:", info.CurrentVersion)
	fmt.Println("latest_version:", info.LatestVersion)
	fmt.Println("update_available:", info.UpdateAvailable)
	fmt.Println("release_url:", info.ReleaseURL)
	if info.AssetName != "" {
		fmt.Println("asset:", info.AssetName)
	}
	if info.Reason != "" {
		fmt.Println("note:", info.Reason)
	}
	return nil
}

func runUpdateApply(args []string) error {
	fs := flag.NewFlagSet("update apply", flag.ContinueOnError)
	repo := fs.String("repo", defaultUpdateRepo, "GitHub repo in owner/name format")
	allowMajor := fs.Bool("allow-major", false, "Allow major version auto-upgrade")
	requireAttestation := fs.Bool("require-attestation", false, "Require signed checksums attestation before applying update")
	attestationPubKey := fs.String("attestation-pubkey", defaultUpdateAttestPub, "Base64/hex Ed25519 public key for checksums attestation")
	current := fs.String("current", strings.TrimSpace(buildVersion), "Current version (default build version)")
	timeout := fs.Duration("timeout", 25*time.Second, "HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := applyUpdate(strings.TrimSpace(*repo), strings.TrimSpace(*current), *allowMajor, *requireAttestation, strings.TrimSpace(*attestationPubKey), *timeout)
	if err != nil {
		return err
	}
	fmt.Println("repo:", strings.TrimSpace(*repo))
	fmt.Println("current_version:", res.CurrentVersion)
	fmt.Println("latest_version:", res.LatestVersion)
	fmt.Println("update_applied:", res.Applied)
	if res.AssetName != "" {
		fmt.Println("asset:", res.AssetName)
	}
	if res.Executable != "" {
		fmt.Println("executable:", res.Executable)
	}
	if res.Reason != "" {
		fmt.Println("note:", res.Reason)
	}
	return nil
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".aiwre", "Directory for generated key files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		return err
	}
	privPath := filepath.Join(*outDir, "ed25519_private.key")
	pubPath := filepath.Join(*outDir, "ed25519_public.key")
	if err := os.WriteFile(privPath, []byte(base64.RawStdEncoding.EncodeToString(priv)+"\n"), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, []byte(base64.RawStdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
		return err
	}
	fmt.Println("private:", privPath)
	fmt.Println("public:", pubPath)
	fmt.Println("fingerprint:", protocol.Fingerprint(pub))
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	inPath := fs.String("in", "", "Input markdown/signal file")
	outPath := fs.String("out", "", "Output signed Signal-MD file")
	privPath := fs.String("priv", "", "Base64 private key file (optional; default <state-dir>/ed25519_private.key)")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for default private key path")
	topic := fs.String("topic", "", "Topic if missing (namespace.topic)")
	typeFlag := fs.String("type", string(protocol.TypeBroadcast), "Type if missing")
	ttl := fs.Int("ttl", protocol.DefaultTTL, "TTL seconds if missing")
	ts := fs.String("timestamp", "", "Timestamp override (RFC3339)")
	meta := fs.String("metadata", "", "Metadata JSON to merge when input has none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *outPath == "" {
		return errors.New("--in and --out are required")
	}
	if strings.TrimSpace(*privPath) == "" {
		base := strings.TrimSpace(*stateDir)
		if base == "" {
			base = ".aiwre"
		}
		*privPath = filepath.Join(base, "ed25519_private.key")
	}
	priv, err := loadPrivateKey(*privPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	msg := &protocol.Message{Metadata: map[string]any{}}
	if strings.HasPrefix(string(raw), "---\n") {
		msg, err = protocol.ParseSignalMD(string(raw))
		if err != nil {
			return err
		}
	} else {
		msg.Body = string(raw)
	}
	if msg.Topic == "" {
		msg.Topic = *topic
	}
	if msg.Type == "" {
		msg.Type = protocol.MessageType(*typeFlag)
	}
	if msg.TTL == 0 {
		msg.TTL = *ttl
	}
	if *ts != "" {
		msg.Timestamp = *ts
	}
	if len(msg.Metadata) == 0 && *meta != "" {
		if err := json.Unmarshal([]byte(*meta), &msg.Metadata); err != nil {
			return fmt.Errorf("invalid --metadata json: %w", err)
		}
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		return err
	}
	out, err := protocol.RenderSignalMD(msg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, []byte(out), 0644); err != nil {
		return err
	}
	fmt.Println("signed id:", msg.ID)
	fmt.Println("sender:", msg.Sender)
	fmt.Println("output:", *outPath)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	inPath := fs.String("in", "", "Signed Signal-MD file")
	skew := fs.Duration("clock-skew", protocol.MaxClockSkew, "Allowed future timestamp skew")
	now := fs.String("now", "", "Override current time (RFC3339)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		return errors.New("--in is required")
	}
	raw, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	msg, err := protocol.ParseSignalMD(string(raw))
	if err != nil {
		return err
	}
	policy := security.NewAdmissionPolicy()
	policy.AllowedSkew = *skew
	if *now != "" {
		t, err := time.Parse(time.RFC3339, *now)
		if err != nil {
			return err
		}
		policy.Now = func() time.Time { return t }
		policy.Replay.SetClock(func() time.Time { return t })
	}
	if err := policy.Verify(msg); err != nil {
		return err
	}
	fmt.Println("valid: true")
	fmt.Println("id:", msg.ID)
	fmt.Println("sender:", msg.Sender)
	fmt.Println("topic:", msg.Topic)
	fmt.Println("type:", msg.Type)
	return nil
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	inPath := fs.String("in", "", "Signed Signal-MD file")
	relay := fs.String("relay", "", "Relay base URL (e.g. https://relay.aiwre.io)")
	skipVerify := fs.Bool("skip-verify", false, "Skip local signature/admission verification before publish")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *relay == "" {
		return errors.New("--in and --relay are required")
	}
	raw, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	if !*skipVerify {
		msg, err := protocol.ParseSignalMD(string(raw))
		if err != nil {
			return err
		}
		policy := security.NewAdmissionPolicy()
		if err := policy.Verify(msg); err != nil {
			return fmt.Errorf("local verify failed: %w", err)
		}
	}
	resolvedRelay, profile, _ := resolveBootstrap(*relay)
	relayCandidates := relayCandidatesFromBootstrap(*relay, resolvedRelay, profile)
	resp, usedRelay, err := publishFastWithFailover(relayCandidates, string(raw))
	if err != nil {
		return err
	}
	fmt.Println("published:", resp.Accepted)
	fmt.Println("relay:", usedRelay)
	fmt.Println("id:", resp.ID)
	fmt.Println("stored_at:", resp.StoredAt)
	return nil
}

func runSay(args []string) error {
	fs := flag.NewFlagSet("say", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL (e.g. https://relay.aiwre.io)")
	topic := fs.String("topic", "global.announce", "Topic (namespace.topic)")
	typ := fs.String("type", string(protocol.TypeBroadcast), "Message type (default: broadcast)")
	body := fs.String("body", "", "Plaintext message inline")
	inPath := fs.String("in", "", "Plaintext message file")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for identity keys")
	privPath := fs.String("priv", "", "Private key file (optional; default <state-dir>/ed25519_private.key)")
	ttl := fs.Int("ttl", protocol.DefaultTTL, "Message TTL seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" {
		return errors.New("--relay is required")
	}
	if strings.TrimSpace(*topic) == "" {
		return errors.New("--topic is required")
	}
	if strings.TrimSpace(*typ) == "" {
		return errors.New("--type is required")
	}
	plain, err := readPlainBody(*inPath, *body)
	if err != nil {
		return err
	}

	priv, err := loadPrivateForChat(*privPath, *stateDir)
	if err != nil {
		return err
	}

	msg := &protocol.Message{
		Topic: *topic,
		Type:  protocol.MessageType(*typ),
		TTL:   *ttl,
		Metadata: map[string]any{
			"client":   "aiwre-cli",
			"client_v": "0.1",
		},
		Body: plain,
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		return err
	}
	raw, err := protocol.RenderSignalMD(msg)
	if err != nil {
		return err
	}
	policy := security.NewAdmissionPolicy()
	if err := policy.Verify(msg); err != nil {
		return fmt.Errorf("local verify failed: %w", err)
	}
	resolvedRelay, profile, _ := resolveBootstrap(*relay)
	relayCandidates := relayCandidatesFromBootstrap(*relay, resolvedRelay, profile)
	resp, usedRelay, err := publishFastWithFailover(relayCandidates, raw)
	if err != nil {
		return err
	}
	fmt.Println("say_sent:", resp.Accepted)
	fmt.Println("relay:", usedRelay)
	fmt.Println("topic:", msg.Topic)
	fmt.Println("type:", msg.Type)
	fmt.Println("id:", resp.ID)
	return nil
}

func runPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL (e.g. https://relay.aiwre.io)")
	topic := fs.String("topic", "", "Topic filter")
	limit := fs.Int("limit", 20, "Number of feed entries")
	outDir := fs.String("out-dir", "./inbox", "Directory for downloaded signals")
	skipVerify := fs.Bool("skip-verify", false, "Skip local verification on pulled messages")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *relay == "" {
		return errors.New("--relay is required")
	}
	resolvedRelay, profile, _ := resolveBootstrap(*relay)
	relayCandidates := relayCandidatesFromBootstrap(*relay, resolvedRelay, profile)
	// Pull requires shard_count/default_topics; if bootstrap fetch failed earlier, try once more.
	if profile == nil || profile.ShardCount < 1 {
		p2, usedRelay, err := fetchBootstrapWithFailover(relayCandidates)
		if err != nil {
			return err
		}
		profile = p2
		if profile != nil && strings.TrimSpace(profile.Relay) != "" {
			resolvedRelay = usedRelay
		}
	}
	resolvedTopic := strings.TrimSpace(*topic)
	if resolvedTopic == "" {
		if len(profile.DefaultTopics) > 0 {
			resolvedTopic = profile.DefaultTopics[0]
		} else {
			resolvedTopic = "global.announce"
		}
	}
	shardCount := profile.ShardCount
	if shardCount < 1 {
		shardCount = 1
	}
	var admission *security.AdmissionPolicy
	if !*skipVerify {
		admission = security.NewAdmissionPolicy()
	}
	res, usedRelay, err := pullTopicShardedWithFailover(
		relayCandidates,
		resolvedTopic,
		*limit,
		*outDir,
		!*skipVerify,
		true,
		shardCount,
		admission,
		cursorStatePath(*outDir),
	)
	if err != nil {
		return err
	}
	fmt.Println("feed_mode:", res.Mode)
	fmt.Println("relay:", usedRelay)
	fmt.Println("feed_topic:", res.Topic)
	fmt.Println("feed_count:", res.Count)
	fmt.Println("downloaded:", res.Downloaded)
	fmt.Println("out_dir:", *outDir)
	return nil
}

func runDM(args []string) error {
	if len(args) == 0 {
		return dmUsageError()
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(dmUsageText())
		return nil
	}
	switch args[0] {
	case "send":
		return runDMSend(args[1:])
	case "pull":
		return runDMPull(args[1:])
	default:
		return fmt.Errorf("unknown dm subcommand %q\n%s", args[0], dmUsageText())
	}
}

func runRoom(args []string) error {
	if len(args) == 0 {
		return roomUsageError()
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(roomUsageText())
		return nil
	}
	switch args[0] {
	case "send":
		return runRoomSend(args[1:])
	case "pull":
		return runRoomPull(args[1:])
	default:
		return fmt.Errorf("unknown room subcommand %q\n%s", args[0], roomUsageText())
	}
}

func runID(args []string) error {
	if len(args) == 0 {
		return idUsageError()
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(idUsageText())
		return nil
	}
	switch args[0] {
	case "card":
		return runIDCard(args[1:])
	case "resolve":
		return runIDResolve(args[1:])
	case "whois":
		return runIDWhois(args[1:])
	default:
		return fmt.Errorf("unknown id subcommand %q\n%s", args[0], idUsageText())
	}
}

func runIDCard(args []string) error {
	if len(args) == 0 {
		return idCardUsageError()
	}
	switch args[0] {
	case "publish":
		return runIDCardPublish(args[1:])
	default:
		return fmt.Errorf("unknown id card subcommand %q\n%s", args[0], idCardUsageText())
	}
}

func runIDCardPublish(args []string) error {
	fs := flag.NewFlagSet("id card publish", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or relay base URL")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for identity keys")
	topic := fs.String("topic", defaultAgentCardTopic, "Topic for agent card signals")
	alias := fs.String("alias", "", "Public alias (local or local@domain)")
	name := fs.String("name", "", "Display name")
	about := fs.String("about", "", "Short profile text")
	caps := fs.String("capabilities", "", "Comma-separated capability tags")
	ttl := fs.Int("ttl", 86400, "Card TTL seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*bootstrap) == "" {
		return errors.New("--bootstrap is required")
	}
	if strings.TrimSpace(*topic) == "" {
		return errors.New("--topic is required")
	}
	relay, _, err := resolveBootstrap(*bootstrap)
	if err != nil {
		return err
	}
	privPath := filepath.Join(*stateDir, "ed25519_private.key")
	pubPath := filepath.Join(*stateDir, "ed25519_public.key")
	priv, pub, _, err := loadOrCreateKeyPair(privPath, pubPath)
	if err != nil {
		return err
	}
	sender := protocol.Fingerprint(pub)
	agentID := "aiwre:" + sender
	aliasValue, err := normalizeAgentAlias(*alias, relay)
	if err != nil {
		return fmt.Errorf("--alias: %w", err)
	}
	capList := parseCSV(*caps)
	capAny := make([]any, 0, len(capList))
	for _, c := range capList {
		capAny = append(capAny, c)
	}
	meta := map[string]any{
		"card_v":    "1",
		"agent_id":  agentID,
		"sender_fp": sender,
		"relay":     relay,
	}
	if aliasValue != "" {
		meta["alias"] = aliasValue
	}
	if v := strings.TrimSpace(*name); v != "" {
		meta["display_name"] = v
	}
	if len(capAny) > 0 {
		meta["capabilities"] = capAny
	}
	probe := &protocol.Message{
		AiwreV:    protocol.Version,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Topic:     *topic,
		Type:      protocol.TypeBroadcast,
		TTL:       *ttl,
		Nonce:     "00",
		Metadata:  map[string]any{},
	}
	if err := probe.ValidateUnsigned(); err != nil {
		return err
	}
	body := strings.Builder{}
	body.WriteString("# AIWRE Agent Card\n\n")
	body.WriteString("- agent_id: " + agentID + "\n")
	if aliasValue != "" {
		body.WriteString("- alias: " + aliasValue + "\n")
	}
	if v := strings.TrimSpace(*name); v != "" {
		body.WriteString("- name: " + v + "\n")
	}
	body.WriteString("- relay: " + relay + "\n")
	body.WriteString("- updated_at: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	if len(capList) > 0 {
		body.WriteString("- capabilities: " + strings.Join(capList, ",") + "\n")
	}
	if v := strings.TrimSpace(*about); v != "" {
		body.WriteString("\n")
		body.WriteString(v)
		if !strings.HasSuffix(v, "\n") {
			body.WriteString("\n")
		}
	}
	msg := &protocol.Message{
		Topic:    *topic,
		Type:     protocol.TypeBroadcast,
		TTL:      *ttl,
		Metadata: meta,
		Body:     body.String(),
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		return err
	}
	policy := security.NewAdmissionPolicy()
	if err := policy.Verify(msg); err != nil {
		return fmt.Errorf("local verify failed: %w", err)
	}
	raw, err := protocol.RenderSignalMD(msg)
	if err != nil {
		return err
	}
	client := transport.NewClient(relay)
	resp, err := client.PublishFast(raw)
	if err != nil {
		return err
	}
	_ = appendActivity(*stateDir, activityEvent{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Action:    "id_card_publish",
		Relay:     relay,
		Topic:     *topic,
		MessageID: resp.ID,
		Count:     1,
	})
	fmt.Println("id_card_published: true")
	fmt.Println("agent_id:", agentID)
	fmt.Println("sender:", sender)
	fmt.Println("alias:", aliasValue)
	fmt.Println("topic:", *topic)
	fmt.Println("message_id:", resp.ID)
	fmt.Println("relay:", relay)
	return nil
}

func runIDResolve(args []string) error {
	fs := flag.NewFlagSet("id resolve", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or relay base URL")
	queryID := fs.String("id", "", "Agent id query (`aiwre:<sender_fp>`, `<sender_fp>`, or `<alias@domain>`)")
	topic := fs.String("topic", defaultAgentCardTopic, "Topic for agent card signals")
	limit := fs.Int("limit", 200, "Max recent card signals to scan")
	format := fs.String("format", "json", "Output format: json|text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*bootstrap) == "" || strings.TrimSpace(*queryID) == "" {
		return errors.New("--bootstrap and --id are required")
	}
	if *limit <= 0 {
		return errors.New("--limit must be > 0")
	}
	targetSender, targetAlias, err := parseAgentIDQuery(*queryID)
	if err != nil {
		return err
	}
	relay, profile, err := resolveBootstrap(*bootstrap)
	if err != nil {
		return err
	}
	shardCount := profile.ShardCount
	if shardCount < 1 {
		shardCount = 1
	}
	card, err := resolveAgentCard(transport.NewClient(relay), *topic, *limit, shardCount, targetSender, targetAlias)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		out := map[string]any{
			"query":    *queryID,
			"relay":    relay,
			"resolved": card,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "text":
		printAgentCard(card, *queryID, relay)
		return nil
	default:
		return errors.New("--format must be one of: json,text")
	}
}

func runIDWhois(args []string) error {
	fs := flag.NewFlagSet("id whois", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or relay base URL")
	queryID := fs.String("id", "", "Agent id query (`aiwre:<sender_fp>`, `<sender_fp>`, or `<alias@domain>`)")
	topic := fs.String("topic", defaultAgentCardTopic, "Topic for agent card signals")
	limit := fs.Int("limit", 200, "Max recent card signals to scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*bootstrap) == "" || strings.TrimSpace(*queryID) == "" {
		return errors.New("--bootstrap and --id are required")
	}
	targetSender, targetAlias, err := parseAgentIDQuery(*queryID)
	if err != nil {
		return err
	}
	relay, profile, err := resolveBootstrap(*bootstrap)
	if err != nil {
		return err
	}
	shardCount := profile.ShardCount
	if shardCount < 1 {
		shardCount = 1
	}
	card, err := resolveAgentCard(transport.NewClient(relay), *topic, *limit, shardCount, targetSender, targetAlias)
	if err != nil {
		return err
	}
	printAgentCard(card, *queryID, relay)
	return nil
}

func resolveAgentCard(client *transport.Client, topic string, limit int, shardCount int, targetSender string, targetAlias string) (*agentCardRecord, error) {
	if shardCount < 1 {
		shardCount = 1
	}
	primaryShards, targeted := resolveShardsForQuery(client, topic, shardCount, targetSender, targetAlias)
	allShards := make([]int, 0, shardCount)
	for s := 0; s < shardCount; s++ {
		allShards = append(allShards, s)
	}

	attempts := 6
	if targetAlias != "" {
		// Alias resolution has higher propagation delay and cannot be shard-targeted.
		attempts = 7
	}
	wait := 300 * time.Millisecond
	maxWait := 2 * time.Second

	for attempt := 0; attempt < attempts; attempt++ {
		shards := primaryShards
		if targeted && attempt >= 2 {
			// Fallback: if shard targeting was wrong or propagation is uneven, scan all shards.
			shards = allShards
		}
		ids, err := collectRecentSignalIDsForResolve(client, topic, limit, shards)
		if err == nil {
			for _, id := range ids {
				raw, err := getSignalWithRetry(client, id, 3, 200*time.Millisecond)
				if err != nil {
					continue
				}
				msg, err := protocol.ParseSignalMD(raw)
				if err != nil {
					continue
				}
				if err := protocol.VerifyMessage(msg); err != nil {
					continue
				}
				card := parseAgentCardMessage(msg)
				if card == nil {
					continue
				}
				if targetSender != "" && card.Sender != targetSender {
					continue
				}
				if targetAlias != "" && !strings.EqualFold(card.Alias, targetAlias) {
					continue
				}
				return card, nil
			}
		}

		if attempt < attempts-1 {
			time.Sleep(wait)
			wait = growBackoff(wait, maxWait)
		}
	}

	return nil, fmt.Errorf("agent card not found for query")
}

func resolveShardsForQuery(client *transport.Client, topic string, shardCount int, targetSender string, targetAlias string) ([]int, bool) {
	if shardCount < 1 {
		shardCount = 1
	}
	// If resolving by canonical sender id, try shard targeting to avoid scanning all shards.
	if strings.TrimSpace(targetSender) != "" && strings.TrimSpace(targetAlias) == "" && client != nil {
		if sr, err := resolveShardWithRetry(client, topic, targetSender, 4); err == nil && sr != nil {
			n := sr.ShardCount
			if n < 1 {
				n = shardCount
			}
			if sr.Shard >= 0 && sr.Shard < n {
				return []int{sr.Shard}, true
			}
		}
	}
	shards := make([]int, 0, shardCount)
	for s := 0; s < shardCount; s++ {
		shards = append(shards, s)
	}
	return shards, false
}

func collectRecentSignalIDsForResolve(client *transport.Client, topic string, limit int, shards []int) ([]string, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	if strings.TrimSpace(topic) == "" {
		return nil, errors.New("topic is required")
	}
	if limit <= 0 {
		limit = 200
	}
	if len(shards) == 0 {
		return nil, errors.New("no shards to scan")
	}

	perShard := (limit + len(shards) - 1) / len(shards)
	if perShard < 3 {
		perShard = 3
	}
	if perShard > 200 {
		perShard = 200
	}

	type shardResult struct {
		ok      bool
		entries []transport.FeedEntry
	}

	results := make(chan shardResult, len(shards))
	var wg sync.WaitGroup
	for _, shard := range shards {
		s := shard
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta, err := client.FeedCursor(topic, s, 0, 1)
			if err != nil || meta == nil {
				results <- shardResult{ok: false}
				return
			}
			if meta.MaxSeq <= 0 {
				results <- shardResult{ok: true}
				return
			}
			tailCursor := meta.MaxSeq - int64(perShard)
			if tailCursor < 0 {
				tailCursor = 0
			}
			resp, err := client.FeedCursor(topic, s, tailCursor, perShard)
			if err != nil || resp == nil {
				results <- shardResult{ok: false}
				return
			}
			results <- shardResult{ok: true, entries: resp.Entries}
		}()
	}
	wg.Wait()
	close(results)

	okShards := 0
	entries := make([]transport.FeedEntry, 0, limit*2)
	for r := range results {
		if !r.ok {
			continue
		}
		okShards++
		if len(r.entries) > 0 {
			entries = append(entries, r.entries...)
		}
	}
	if okShards == 0 {
		return nil, errors.New("feed unavailable for all shards")
	}
	if len(entries) == 0 {
		return nil, nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Timestamp == entries[j].Timestamp {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Timestamp > entries[j].Timestamp
	})

	ids := make([]string, 0, limit)
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.ID == "" {
			continue
		}
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		ids = append(ids, e.ID)
		if len(ids) >= limit {
			break
		}
	}
	return ids, nil
}

func parseAgentCardMessage(msg *protocol.Message) *agentCardRecord {
	if msg == nil || msg.Metadata == nil {
		return nil
	}
	if metadataString(msg.Metadata, "card_v") != "1" {
		return nil
	}
	agentID := strings.TrimSpace(metadataString(msg.Metadata, "agent_id"))
	if agentID == "" {
		agentID = "aiwre:" + msg.Sender
	}
	normalizedID, err := normalizeAgentIDURI(agentID)
	if err != nil {
		return nil
	}
	alias := strings.ToLower(strings.TrimSpace(metadataString(msg.Metadata, "alias")))
	relay := strings.TrimSpace(metadataString(msg.Metadata, "relay"))
	display := strings.TrimSpace(metadataString(msg.Metadata, "display_name"))
	return &agentCardRecord{
		AgentID:      normalizedID,
		Sender:       msg.Sender,
		Alias:        alias,
		Relay:        relay,
		DisplayName:  display,
		Capabilities: metadataStringList(msg.Metadata["capabilities"]),
		UpdatedAt:    msg.Timestamp,
		MessageID:    msg.ID,
		Topic:        msg.Topic,
		Metadata:     msg.Metadata,
		Body:         msg.Body,
	}
}

func metadataString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func metadataStringList(v any) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, item := range t {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			text := strings.TrimSpace(fmt.Sprintf("%v", item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func printAgentCard(card *agentCardRecord, query string, relay string) {
	if card == nil {
		return
	}
	fmt.Println("query:", query)
	fmt.Println("relay:", relay)
	fmt.Println("agent_id:", card.AgentID)
	fmt.Println("sender:", card.Sender)
	fmt.Println("alias:", card.Alias)
	fmt.Println("display_name:", card.DisplayName)
	fmt.Println("capabilities:", strings.Join(card.Capabilities, ","))
	fmt.Println("updated_at:", card.UpdatedAt)
	fmt.Println("message_id:", card.MessageID)
	fmt.Println("topic:", card.Topic)
}

func runDMSend(args []string) error {
	fs := flag.NewFlagSet("dm send", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL")
	bootstrap := fs.String("bootstrap", "", "Alias of --relay (bootstrap URL or relay base URL)")
	to := fs.String("to", "", "Recipient sender fingerprint (64 hex)")
	secret := fs.String("secret", "", "Shared secret for DM encryption")
	inPath := fs.String("in", "", "Plaintext message file")
	body := fs.String("body", "", "Plaintext message inline")
	privPath := fs.String("priv", "", "Private key file (optional; default <state-dir>/ed25519_private.key)")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for default private key path")
	ttl := fs.Int("ttl", protocol.DefaultTTL, "Message TTL seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" && strings.TrimSpace(*bootstrap) != "" {
		*relay = strings.TrimSpace(*bootstrap)
	}
	if *relay == "" || *to == "" || *secret == "" {
		return errors.New("--relay, --to, and --secret are required\n" + dmUsageText())
	}
	peerID, err := normalizeSenderID(*to)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	priv, err := loadPrivateForChat(*privPath, *stateDir)
	if err != nil {
		return err
	}
	selfID := protocol.Fingerprint(priv.Public().(ed25519.PublicKey))
	topic := dmTopic(selfID, peerID)
	plain, err := readPlainBody(*inPath, *body)
	if err != nil {
		return err
	}
	cipherText, nonce, err := encryptChatBody(*secret, topic, plain)
	if err != nil {
		return err
	}
	msg := &protocol.Message{
		Topic: topic,
		Type:  protocol.TypeBroadcast,
		TTL:   *ttl,
		Metadata: map[string]any{
			"chat":      "dm",
			"chat_v":    "1",
			"enc":       "aes-256-gcm",
			"enc_nonce": nonce,
			"to":        peerID,
		},
		Body: cipherText,
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		return err
	}
	raw, err := protocol.RenderSignalMD(msg)
	if err != nil {
		return err
	}
	policy := security.NewAdmissionPolicy()
	if err := policy.Verify(msg); err != nil {
		return fmt.Errorf("local verify failed: %w", err)
	}
	resolvedRelay, _, _ := resolveBootstrap(*relay)
	client := transport.NewClient(resolvedRelay)
	resp, err := client.PublishFast(raw)
	if err != nil {
		return err
	}
	fmt.Println("dm_sent: true")
	fmt.Println("topic:", topic)
	fmt.Println("to:", peerID)
	fmt.Println("id:", resp.ID)
	return nil
}

func runDMPull(args []string) error {
	fs := flag.NewFlagSet("dm pull", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL")
	bootstrap := fs.String("bootstrap", "", "Alias of --relay (bootstrap URL or relay base URL)")
	withID := fs.String("with", "", "Peer sender fingerprint (64 hex)")
	secret := fs.String("secret", "", "Shared secret for DM encryption")
	limit := fs.Int("limit", 20, "Number of recent messages")
	outDir := fs.String("out-dir", "./dm-inbox", "Directory for decrypted messages")
	privPath := fs.String("priv", "", "Private key file (optional; default <state-dir>/ed25519_private.key)")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for default private key path")
	skipVerify := fs.Bool("skip-verify", false, "Skip admission verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" && strings.TrimSpace(*bootstrap) != "" {
		*relay = strings.TrimSpace(*bootstrap)
	}
	if *relay == "" || *withID == "" || *secret == "" {
		return errors.New("--relay, --with, and --secret are required\n" + dmUsageText())
	}
	peerID, err := normalizeSenderID(*withID)
	if err != nil {
		return fmt.Errorf("--with: %w", err)
	}
	priv, err := loadPrivateForChat(*privPath, *stateDir)
	if err != nil {
		return err
	}
	selfID := protocol.Fingerprint(priv.Public().(ed25519.PublicKey))
	topic := dmTopic(selfID, peerID)
	resolvedRelay, _, _ := resolveBootstrap(*relay)
	client := transport.NewClient(resolvedRelay)
	count, err := pullAndDecryptChat(client, topic, *secret, *limit, *outDir, !*skipVerify, "dm")
	if err != nil {
		return err
	}
	fmt.Println("dm_pull_topic:", topic)
	fmt.Println("dm_pull_count:", count)
	fmt.Println("out_dir:", *outDir)
	return nil
}

func runRoomSend(args []string) error {
	fs := flag.NewFlagSet("room send", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL")
	bootstrap := fs.String("bootstrap", "", "Alias of --relay (bootstrap URL or relay base URL)")
	room := fs.String("room", "", "Room name (topic segment)")
	secret := fs.String("secret", "", "Shared room secret for encryption")
	inPath := fs.String("in", "", "Plaintext message file")
	body := fs.String("body", "", "Plaintext message inline")
	privPath := fs.String("priv", "", "Private key file (optional; default <state-dir>/ed25519_private.key)")
	stateDir := fs.String("state-dir", ".aiwre", "State directory for default private key path")
	ttl := fs.Int("ttl", protocol.DefaultTTL, "Message TTL seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" && strings.TrimSpace(*bootstrap) != "" {
		*relay = strings.TrimSpace(*bootstrap)
	}
	if *relay == "" || *room == "" || *secret == "" {
		return errors.New("--relay, --room, and --secret are required\n" + roomUsageText())
	}
	roomID, err := normalizeTopicSegment(*room)
	if err != nil {
		return fmt.Errorf("--room: %w", err)
	}
	topic := "room." + roomID
	priv, err := loadPrivateForChat(*privPath, *stateDir)
	if err != nil {
		return err
	}
	plain, err := readPlainBody(*inPath, *body)
	if err != nil {
		return err
	}
	cipherText, nonce, err := encryptChatBody(*secret, topic, plain)
	if err != nil {
		return err
	}
	msg := &protocol.Message{
		Topic: topic,
		Type:  protocol.TypeBroadcast,
		TTL:   *ttl,
		Metadata: map[string]any{
			"chat":      "room",
			"chat_v":    "1",
			"room":      roomID,
			"enc":       "aes-256-gcm",
			"enc_nonce": nonce,
		},
		Body: cipherText,
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		return err
	}
	raw, err := protocol.RenderSignalMD(msg)
	if err != nil {
		return err
	}
	policy := security.NewAdmissionPolicy()
	if err := policy.Verify(msg); err != nil {
		return fmt.Errorf("local verify failed: %w", err)
	}
	resolvedRelay, _, _ := resolveBootstrap(*relay)
	client := transport.NewClient(resolvedRelay)
	resp, err := client.PublishFast(raw)
	if err != nil {
		return err
	}
	fmt.Println("room_sent: true")
	fmt.Println("topic:", topic)
	fmt.Println("id:", resp.ID)
	return nil
}

func runRoomPull(args []string) error {
	fs := flag.NewFlagSet("room pull", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL")
	bootstrap := fs.String("bootstrap", "", "Alias of --relay (bootstrap URL or relay base URL)")
	room := fs.String("room", "", "Room name (topic segment)")
	secret := fs.String("secret", "", "Shared room secret for decryption")
	limit := fs.Int("limit", 20, "Number of recent messages")
	outDir := fs.String("out-dir", "./room-inbox", "Directory for decrypted messages")
	_ = fs.String("state-dir", ".aiwre", "State directory (accepted for symmetry; not required for pull)")
	skipVerify := fs.Bool("skip-verify", false, "Skip admission verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" && strings.TrimSpace(*bootstrap) != "" {
		*relay = strings.TrimSpace(*bootstrap)
	}
	if *relay == "" || *room == "" || *secret == "" {
		return errors.New("--relay, --room, and --secret are required\n" + roomUsageText())
	}
	roomID, err := normalizeTopicSegment(*room)
	if err != nil {
		return fmt.Errorf("--room: %w", err)
	}
	topic := "room." + roomID
	resolvedRelay, _, _ := resolveBootstrap(*relay)
	client := transport.NewClient(resolvedRelay)
	count, err := pullAndDecryptChat(client, topic, *secret, *limit, *outDir, !*skipVerify, "room")
	if err != nil {
		return err
	}
	fmt.Println("room_pull_topic:", topic)
	fmt.Println("room_pull_count:", count)
	fmt.Println("out_dir:", *outDir)
	return nil
}

type activityEvent struct {
	Time      string `json:"time"`
	Action    string `json:"action"`
	Relay     string `json:"relay,omitempty"`
	Topic     string `json:"topic,omitempty"`
	MessageID string `json:"message_id,omitempty"`
	Count     int    `json:"count,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type pullResult struct {
	Mode       string
	Topic      string
	Count      int
	Downloaded int
}

type streamEvent struct {
	Type  string               `json:"type"`
	TS    string               `json:"ts,omitempty"`
	Entry *transport.FeedEntry `json:"entry,omitempty"`
	Raw   string               `json:"raw,omitempty"`
}

const (
	cursorStateFileName      = ".cursor-state.json"
	interactionStateFileName = ".interaction-state.json"
	chatStateFileName        = ".chat-state.json"
	defaultChatConfigName    = "chat-config.json"
	updateStateFileName      = ".update-state.json"
	updateLockFileName       = ".update.lock"
	incrementalFeedMinLimit  = 50
	defaultAgentCardTopic    = "agent.card"
	defaultUpdateRepo        = "horacex/aiwre"
	defaultUpdateAttestPub   = ""
)

type agentCardRecord struct {
	AgentID      string         `json:"agent_id"`
	Sender       string         `json:"sender"`
	Alias        string         `json:"alias,omitempty"`
	Relay        string         `json:"relay,omitempty"`
	DisplayName  string         `json:"display_name,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	UpdatedAt    string         `json:"updated_at"`
	MessageID    string         `json:"message_id"`
	Topic        string         `json:"topic"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	Body         string         `json:"body,omitempty"`
}

func runAutojoin(args []string) error {
	fs := flag.NewFlagSet("autojoin", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or relay base URL")
	stateDir := fs.String("state-dir", ".aiwre", "Local state directory for identity/inbox/log")
	limit := fs.Int("limit", 20, "Per-topic pull size on first sync")
	topicsCSV := fs.String("topics", "", "Comma-separated list of topics to watch (overrides bootstrap default topics)")
	pullInterval := fs.Duration("pull-interval", 30*time.Minute, "Low-frequency pull compensation interval (0 to disable)")
	once := fs.Bool("once", false, "Run initial sync + heartbeat and exit")
	noStream := fs.Bool("no-stream", false, "Disable stream workers (not recommended)")
	streamReconnectBase := fs.Duration("stream-reconnect-base", 2*time.Second, "Base reconnect backoff for stream workers")
	streamReconnectMax := fs.Duration("stream-reconnect-max", 2*time.Minute, "Max reconnect backoff for stream workers")
	handler := fs.String("handler", "", "Optional executable to run on each newly saved streamed signal (args: <file_path>)")
	splitByTopic := fs.Bool("split-by-topic", false, "Write streamed signals under state-dir/inbox/<topic>/ to keep per-topic inboxes separate")
	interactionPack := fs.Bool("interaction-pack", true, "Enable built-in low-cost interaction pack (discover + selective auto-reply)")
	interactionSeedMinInterval := fs.Duration("interaction-seed-min-interval", 24*time.Hour, "Minimum interval between auto discovery seed query publishes")
	interactionReplyMinGap := fs.Duration("interaction-reply-min-gap", 90*time.Second, "Minimum gap between auto replies from this agent")
	interactionReplyDailyCap := fs.Int("interaction-reply-daily-cap", 8, "Max number of auto replies per UTC day")
	interactionReplySampleMod := fs.Int("interaction-reply-sample-mod", 32, "Selective reply sampling modulus (higher = fewer auto replies)")
	chatConfigPath := fs.String("chat-config", "", "Optional JSON chat config (default <state-dir>/chat-config.json if present)")
	chatAutoReply := fs.Bool("chat-auto-reply", true, "Enable automatic DM/room reply behavior for configured chat topics")
	chatReplyMinGap := fs.Duration("chat-reply-min-gap", 90*time.Second, "Minimum gap between automatic chat replies")
	chatReplyDailyCap := fs.Int("chat-reply-daily-cap", 48, "Max automatic chat replies per UTC day")
	policyMaxBodyBytes := fs.Int("policy-max-body-bytes", 65536, "Receiver content policy: maximum body bytes")
	policyMaxMetadataBytes := fs.Int("policy-max-metadata-bytes", 8192, "Receiver content policy: maximum metadata bytes")
	policyMaxMetadataDepth := fs.Int("policy-max-metadata-depth", 4, "Receiver content policy: maximum metadata nesting depth")
	policyAllowTypes := fs.String("policy-allow-types", "broadcast,query,response,heartbeat", "Receiver content policy: allowed message types csv")
	policyAllowTopicPrefixes := fs.String("policy-allow-topic-prefixes", "", "Receiver content policy: allowed topic prefixes csv (empty=all)")
	quarantineDir := fs.String("quarantine-dir", "", "Directory for policy-rejected signals (default <state-dir>/quarantine)")
	autoUpdate := fs.Bool("auto-update", true, "Enable automatic CLI self-update checks in daemon mode")
	autoUpdateInterval := fs.Duration("auto-update-interval", 24*time.Hour, "Interval for automatic update checks")
	autoUpdateAllowMajor := fs.Bool("auto-update-allow-major", false, "Allow automatic major version upgrades")
	autoUpdateRepo := fs.String("auto-update-repo", defaultUpdateRepo, "GitHub repo used for self-updates (owner/name)")
	autoUpdateRequireAttestation := fs.Bool("auto-update-require-attestation", false, "Require signed checksums attestation for automatic updates")
	autoUpdateAttestPubKey := fs.String("auto-update-attestation-pubkey", defaultUpdateAttestPub, "Ed25519 public key (base64/hex) for update attestation verification")
	autoUpdateRollout := fs.Int("auto-update-rollout-percent", 100, "Deterministic rollout percentage [0..100] by agent identity")
	autoUpdateJitter := fs.Duration("auto-update-jitter", 15*time.Minute, "Randomized delay added before each periodic update check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bootstrap == "" {
		return errors.New("--bootstrap is required")
	}
	if *noStream && *pullInterval <= 0 {
		return errors.New("invalid config: both stream and pull compensation are disabled")
	}

	relay, profile, err := resolveBootstrap(*bootstrap)
	if err != nil {
		return err
	}
	relayCandidates := relayCandidatesFromBootstrap(*bootstrap, relay, profile)
	client := transport.NewClient(relay)

	privPath := filepath.Join(*stateDir, "ed25519_private.key")
	pubPath := filepath.Join(*stateDir, "ed25519_public.key")
	priv, pub, created, err := loadOrCreateKeyPair(privPath, pubPath)
	if err != nil {
		return err
	}
	if created {
		if err := appendActivity(*stateDir, activityEvent{
			Time:   time.Now().UTC().Format(time.RFC3339),
			Action: "identity_created",
			Relay:  relay,
			Detail: protocol.Fingerprint(pub),
		}); err != nil {
			return err
		}
	}
	selfID := protocol.Fingerprint(pub)

	topics := profile.DefaultTopics
	chatRuntime, err := newChatRuntime(
		relay,
		*stateDir,
		selfID,
		priv,
		*chatConfigPath,
		*chatAutoReply,
		*chatReplyMinGap,
		*chatReplyDailyCap,
	)
	if err != nil {
		return err
	}
	if chatRuntime != nil {
		topics = append(topics, chatRuntime.watchTopics()...)
	}
	if strings.TrimSpace(*topicsCSV) != "" {
		topics = parseTopicsCSV(*topicsCSV)
		if chatRuntime != nil {
			topics = append(topics, chatRuntime.watchTopics()...)
		}
	}
	topics = uniqStrings(topics)
	if len(topics) == 0 {
		topics = []string{"global.announce"}
	}
	inboxDir := filepath.Join(*stateDir, "inbox")
	totalDownloaded := 0
	shardCount := profile.ShardCount
	if shardCount < 1 {
		shardCount = 1
	}
	admission := security.NewAdmissionPolicy()
	for _, topic := range topics {
		res, usedRelay, err := pullTopicShardedWithFailover(
			relayCandidates,
			topic,
			*limit,
			inboxDir,
			true,
			false,
			shardCount,
			admission,
			cursorStatePath(inboxDir),
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn: topic pull failed:", topic, err)
			continue
		}
		totalDownloaded += res.Downloaded
		_ = appendActivity(*stateDir, activityEvent{
			Time:   time.Now().UTC().Format(time.RFC3339),
			Action: "pull",
			Relay:  usedRelay,
			Topic:  topic,
			Count:  res.Downloaded,
			Detail: fmt.Sprintf("feed_count=%d mode=%s phase=bootstrap", res.Count, res.Mode),
		})
	}

	heartbeatTopic := profile.HeartbeatTopic
	if heartbeatTopic == "" {
		heartbeatTopic = "agent.heartbeat"
	}
	heartbeat := &protocol.Message{
		Topic: heartbeatTopic,
		Type:  protocol.TypeHeartbeat,
		TTL:   300,
		Metadata: map[string]any{
			"mode":        "autojoin_daemon",
			"client":      "aiwre-cli",
			"inbox_count": totalDownloaded,
		},
		Body: "autojoin heartbeat\n",
	}
	if err := protocol.SignMessage(heartbeat, priv); err != nil {
		return err
	}
	raw, err := protocol.RenderSignalMD(heartbeat)
	if err != nil {
		return err
	}
	pubResp, usedRelay, err := publishFastWithFailover(relayCandidates, raw)
	if err != nil {
		return err
	}
	if err := appendActivity(*stateDir, activityEvent{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Action:    "publish",
		Relay:     usedRelay,
		Topic:     heartbeatTopic,
		MessageID: pubResp.ID,
		Count:     1,
	}); err != nil {
		return err
	}

	fmt.Println("autojoin: true")
	fmt.Println("relay:", relay)
	fmt.Println("relay_candidates:", strings.Join(relayCandidates, ","))
	fmt.Println("join_mode:", profile.Join)
	fmt.Println("identity:", selfID)
	fmt.Println("topics:", strings.Join(topics, ","))
	fmt.Println("downloaded:", totalDownloaded)
	fmt.Println("heartbeat_id:", pubResp.ID)
	fmt.Println("state_dir:", *stateDir)
	fmt.Println("auto_update:", *autoUpdate)
	policy, err := newContentPolicy(*policyMaxBodyBytes, *policyMaxMetadataBytes, *policyMaxMetadataDepth, *policyAllowTypes, *policyAllowTopicPrefixes)
	if err != nil {
		return err
	}
	policyRejectDir := strings.TrimSpace(*quarantineDir)
	if policyRejectDir == "" {
		policyRejectDir = filepath.Join(*stateDir, "quarantine")
	}
	fmt.Println("policy_max_body_bytes:", policy.maxBodyBytes)
	fmt.Println("policy_max_metadata_bytes:", policy.maxMetadataBytes)
	fmt.Println("policy_max_metadata_depth:", policy.maxMetadataDepth)
	fmt.Println("policy_allow_types:", strings.Join(policy.allowedTypeStrings(), ","))
	if len(policy.allowTopicPrefixes) > 0 {
		fmt.Println("policy_allow_topic_prefixes:", strings.Join(policy.allowTopicPrefixes, ","))
	}
	fmt.Println("quarantine_dir:", policyRejectDir)
	if chatRuntime != nil {
		fmt.Println("chat_config:", chatRuntime.configPath)
		fmt.Println("chat_topics:", strings.Join(chatRuntime.watchTopics(), ","))
		fmt.Println("chat_auto_reply:", *chatAutoReply)
	}

	var interaction *interactionRuntime
	if *interactionPack {
		interaction = newInteractionRuntime(
			relay,
			*stateDir,
			selfID,
			priv,
			*interactionSeedMinInterval,
			*interactionReplyMinGap,
			*interactionReplyDailyCap,
			*interactionReplySampleMod,
		)
		if seedID, seeded, seedErr := interaction.maybeSeedDiscovery(client); seedErr != nil {
			fmt.Fprintln(os.Stderr, "warn: interaction seed failed:", seedErr)
		} else if seeded {
			fmt.Println("interaction_seed_id:", seedID)
		}
	}
	fmt.Println("interaction_pack:", *interactionPack)
	if *once {
		fmt.Println("runtime_mode:", "once")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	type streamStats struct {
		received int
		saved    int
		errors   int
	}
	stats := map[string]*streamStats{}
	for _, topic := range topics {
		stats[topic] = &streamStats{}
	}
	var statsMu sync.Mutex
	var wg sync.WaitGroup

	if !*noStream {
		base := *streamReconnectBase
		max := *streamReconnectMax
		if base <= 0 {
			base = 2 * time.Second
		}
		if max < base {
			max = 2 * time.Minute
		}
		for _, topic := range topics {
			t := topic
			wg.Add(1)
			go func() {
				defer wg.Done()
				out := inboxDir
				if *splitByTopic {
					out = filepath.Join(out, sanitizeTopicForPath(t))
					_ = os.MkdirAll(out, 0755)
				}
				onSaved := func(savedClient *transport.Client, sigTopic, id, path string) {
					activityRelay := relay
					if savedClient != nil && strings.TrimSpace(savedClient.BaseURL) != "" {
						activityRelay = strings.TrimSpace(savedClient.BaseURL)
					}
					kept, reason, err := enforceContentPolicyFromPath(path, sigTopic, policy, policyRejectDir)
					if err != nil {
						fmt.Fprintln(os.Stderr, "warn: content policy check failed:", err)
						return
					}
					if !kept {
						now := time.Now().UTC()
						fmt.Println("quarantined_signal:", id, "topic:", sigTopic, "reason:", reason)
						_ = appendActivity(*stateDir, activityEvent{
							Time:      now.Format(time.RFC3339),
							Action:    "quarantine",
							Relay:     activityRelay,
							Topic:     sigTopic,
							MessageID: id,
							Count:     1,
							Detail:    reason,
						})
						return
					}
					if interaction != nil {
						if err := interaction.maybeAutoReplyFromPath(savedClient, sigTopic, id, path); err != nil {
							fmt.Fprintln(os.Stderr, "warn: interaction reply hook failed:", err)
						}
					}
					if chatRuntime != nil {
						if err := chatRuntime.handleSaved(savedClient, sigTopic, id, path); err != nil {
							fmt.Fprintln(os.Stderr, "warn: chat runtime hook failed:", err)
						}
					}
				}
				runAutojoinStreamWorker(ctx, relayCandidates, t, out, base, max, strings.TrimSpace(*handler), onSaved, func(received, saved, errs int) {
					statsMu.Lock()
					st := stats[t]
					st.received += received
					st.saved += saved
					st.errors += errs
					statsMu.Unlock()
				})
			}()
		}
	}

	fmt.Println("runtime_mode:", "daemon")
	if *pullInterval > 0 {
		fmt.Println("pull_compensation_interval:", pullInterval.String())
	} else {
		fmt.Println("pull_compensation_interval:", "disabled")
	}
	if *autoUpdate && *autoUpdateInterval > 0 {
		fmt.Println("auto_update_interval:", autoUpdateInterval.String())
		fmt.Println("auto_update_rollout_percent:", *autoUpdateRollout)
		fmt.Println("auto_update_jitter:", autoUpdateJitter.String())
		fmt.Println("auto_update_require_attestation:", *autoUpdateRequireAttestation)
	}

	if *autoUpdate {
		applied, err := maybeAutoUpdate(*stateDir, *autoUpdateRepo, strings.TrimSpace(buildVersion), selfID, *autoUpdateAllowMajor, *autoUpdateRequireAttestation, strings.TrimSpace(*autoUpdateAttestPubKey), *autoUpdateRollout, *autoUpdateJitter, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn: auto-update check failed:", err)
		}
		if applied {
			fmt.Println("auto_update_applied:", true)
			if err := restartSelf(os.Args[1:]); err != nil {
				fmt.Fprintln(os.Stderr, "warn: update applied but restart failed:", err)
			}
			return nil
		}
	}

	var pullTicker *time.Ticker
	var pullC <-chan time.Time
	if *pullInterval > 0 {
		pullTicker = time.NewTicker(*pullInterval)
		defer pullTicker.Stop()
		pullC = pullTicker.C
	}

	var updateTicker *time.Ticker
	var updateC <-chan time.Time
	if *autoUpdate && *autoUpdateInterval > 0 {
		updateTicker = time.NewTicker(*autoUpdateInterval)
		defer updateTicker.Stop()
		updateC = updateTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			goto END
		case <-pullC:
			cycleAdmission := security.NewAdmissionPolicy()
			for _, topic := range topics {
				res, usedRelay, err := pullTopicShardedWithFailover(
					relayCandidates,
					topic,
					*limit,
					inboxDir,
					true,
					false,
					shardCount,
					cycleAdmission,
					cursorStatePath(inboxDir),
				)
				if err != nil {
					fmt.Fprintln(os.Stderr, "warn: pull compensation failed:", topic, err)
					continue
				}
				if res.Downloaded > 0 {
					fmt.Println("compensate_downloaded:", topic, res.Downloaded)
				}
				_ = appendActivity(*stateDir, activityEvent{
					Time:   time.Now().UTC().Format(time.RFC3339),
					Action: "pull",
					Relay:  usedRelay,
					Topic:  topic,
					Count:  res.Downloaded,
					Detail: fmt.Sprintf("feed_count=%d mode=%s phase=compensate", res.Count, res.Mode),
				})
			}
		case <-updateC:
			applied, err := maybeAutoUpdate(*stateDir, *autoUpdateRepo, strings.TrimSpace(buildVersion), selfID, *autoUpdateAllowMajor, *autoUpdateRequireAttestation, strings.TrimSpace(*autoUpdateAttestPubKey), *autoUpdateRollout, *autoUpdateJitter, true)
			if err != nil {
				fmt.Fprintln(os.Stderr, "warn: auto-update tick failed:", err)
				continue
			}
			if applied {
				fmt.Println("auto_update_applied:", true)
				if err := restartSelf(os.Args[1:]); err != nil {
					fmt.Fprintln(os.Stderr, "warn: update applied but restart failed:", err)
				}
				return nil
			}
		}
	}

END:
	statsMu.Lock()
	defer statsMu.Unlock()
	totalReceived := 0
	totalSaved := 0
	totalErrors := 0
	for _, st := range stats {
		totalReceived += st.received
		totalSaved += st.saved
		totalErrors += st.errors
	}
	fmt.Println("stream_received:", totalReceived)
	fmt.Println("stream_saved:", totalSaved)
	fmt.Println("stream_errors:", totalErrors)
	return nil
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	stateDir := fs.String("state-dir", ".aiwre", "State directory")
	hours := fs.Int("hours", 24, "Time window in hours")
	format := fs.String("format", "text", "Output format: text|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	start := time.Now().UTC().Add(-time.Duration(*hours) * time.Hour)
	events, err := loadActivity(*stateDir, start)
	if err != nil {
		return err
	}

	publishCount := 0
	pullCount := 0
	downloaded := 0
	quarantined := 0
	quarantineReasons := map[string]int{}
	relays := map[string]struct{}{}
	topics := map[string]struct{}{}
	for _, ev := range events {
		if ev.Relay != "" {
			relays[ev.Relay] = struct{}{}
		}
		if ev.Topic != "" {
			topics[ev.Topic] = struct{}{}
		}
		switch ev.Action {
		case "publish":
			publishCount++
		case "pull":
			pullCount++
			downloaded += ev.Count
		case "quarantine":
			quarantined++
			reason := strings.TrimSpace(ev.Detail)
			if reason == "" {
				reason = "unspecified"
			}
			quarantineReasons[reason]++
		}
	}
	relayList := sortedKeys(relays)
	topicList := sortedKeys(topics)
	if *format == "json" {
		out := map[string]any{
			"window_start":       start.Format(time.RFC3339),
			"window_hours":       *hours,
			"events":             len(events),
			"published":          publishCount,
			"pulls":              pullCount,
			"downloaded":         downloaded,
			"quarantined":        quarantined,
			"quarantine_reasons": quarantineReasons,
			"relays":             relayList,
			"topics":             topicList,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	fmt.Println("report_window_start:", start.Format(time.RFC3339))
	fmt.Println("window_hours:", *hours)
	fmt.Println("events:", len(events))
	fmt.Println("published:", publishCount)
	fmt.Println("pulls:", pullCount)
	fmt.Println("downloaded:", downloaded)
	fmt.Println("quarantined:", quarantined)
	if len(quarantineReasons) > 0 {
		keys := make([]string, 0, len(quarantineReasons))
		for k := range quarantineReasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, quarantineReasons[k]))
		}
		fmt.Println("quarantine_reasons:", strings.Join(parts, ","))
	}
	fmt.Println("relays:", strings.Join(relayList, ","))
	fmt.Println("topics:", strings.Join(topicList, ","))
	return nil
}

func runStream(args []string) error {
	fs := flag.NewFlagSet("stream", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL (e.g. https://relay.aiwre.io)")
	topic := fs.String("topic", "", "Topic to stream (defaults to bootstrap first topic)")
	topicsCSV := fs.String("topics", "", "Comma-separated list of topics to stream (in addition to --topic)")
	outDir := fs.String("out-dir", "./inbox", "Directory for streamed signals")
	splitByTopic := fs.Bool("split-by-topic", false, "Write streamed signals under out-dir/<topic>/ to keep per-topic inboxes separate")
	skipVerify := fs.Bool("skip-verify", false, "Skip local admission verification on streamed messages")
	duration := fs.Duration("duration", 0, "Optional runtime limit (e.g. 10m). 0 means run until interrupted")
	handler := fs.String("handler", "", "Optional executable to run on each newly saved signal (args: <file_path>). Env: AIWRE_TOPIC, AIWRE_SIGNAL_ID, AIWRE_RELAY")
	policyMaxBodyBytes := fs.Int("policy-max-body-bytes", 65536, "Receiver content policy: maximum body bytes")
	policyMaxMetadataBytes := fs.Int("policy-max-metadata-bytes", 8192, "Receiver content policy: maximum metadata bytes")
	policyMaxMetadataDepth := fs.Int("policy-max-metadata-depth", 4, "Receiver content policy: maximum metadata nesting depth")
	policyAllowTypes := fs.String("policy-allow-types", "broadcast,query,response,heartbeat", "Receiver content policy: allowed message types csv")
	policyAllowTopicPrefixes := fs.String("policy-allow-topic-prefixes", "", "Receiver content policy: allowed topic prefixes csv (empty=all)")
	quarantineDir := fs.String("quarantine-dir", "", "Directory for policy-rejected signals (default <out-dir>/quarantine)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" {
		return errors.New("--relay is required")
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	policy, err := newContentPolicy(*policyMaxBodyBytes, *policyMaxMetadataBytes, *policyMaxMetadataDepth, *policyAllowTypes, *policyAllowTopicPrefixes)
	if err != nil {
		return err
	}
	policyRejectDir := strings.TrimSpace(*quarantineDir)
	if policyRejectDir == "" {
		policyRejectDir = filepath.Join(*outDir, "quarantine")
	}

	resolvedRelay, profile, _ := resolveBootstrap(*relay)
	relayCandidates := relayCandidatesFromBootstrap(*relay, resolvedRelay, profile)
	if profile == nil || profile.ShardCount < 1 {
		p2, usedRelay, err := fetchBootstrapWithFailover(relayCandidates)
		if err != nil {
			return err
		}
		profile = p2
		resolvedRelay = usedRelay
		relayCandidates = relayCandidatesFromBootstrap(*relay, resolvedRelay, profile)
	}
	resolvedTopic := strings.TrimSpace(*topic)
	wantTopics := make([]string, 0, 8)
	if strings.TrimSpace(resolvedTopic) != "" {
		wantTopics = append(wantTopics, resolvedTopic)
	}
	wantTopics = append(wantTopics, parseTopicsCSV(*topicsCSV)...)
	wantTopics = uniqStrings(wantTopics)
	if len(wantTopics) == 0 {
		if len(profile.DefaultTopics) > 0 {
			wantTopics = []string{profile.DefaultTopics[0]}
		} else {
			wantTopics = []string{"global.announce"}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	var admission *security.AdmissionPolicy
	if !*skipVerify {
		admission = security.NewAdmissionPolicy()
	}

	type topicStats struct {
		topic      string
		received   int
		downloaded int
		errors     int
	}
	stats := make([]*topicStats, 0, len(wantTopics))
	var statsMu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range wantTopics {
		topicName := strings.TrimSpace(t)
		if topicName == "" {
			continue
		}
		wg.Add(1)
		st := &topicStats{topic: topicName}
		stats = append(stats, st)
		go func(topic string, s *topicStats) {
			defer wg.Done()
			backoff := 2 * time.Second
			relayIdx := 0
			for {
				if ctx.Err() != nil {
					return
				}
				currentRelay := relayCandidates[relayIdx%len(relayCandidates)]
				currentClient := transport.NewClient(currentRelay)
				streamURL, err := currentClient.StreamURL(topic)
				if err != nil {
					statsMu.Lock()
					s.errors++
					statsMu.Unlock()
					relayIdx++
					if !sleepWithContext(ctx, jitterBackoff(backoff)) {
						return
					}
					backoff = growBackoff(backoff, 2*time.Minute)
					continue
				}
				conn, _, err := websocket.Dial(ctx, streamURL, nil)
				if err != nil {
					statsMu.Lock()
					s.errors++
					statsMu.Unlock()
					relayIdx++
					if !sleepWithContext(ctx, jitterBackoff(backoff)) {
						return
					}
					backoff = growBackoff(backoff, 2*time.Minute)
					continue
				}
				backoff = 2 * time.Second

				for {
					_, payload, err := conn.Read(ctx)
					if err != nil {
						_ = conn.Close(websocket.StatusNormalClosure, "bye")
						if ctx.Err() != nil {
							return
						}
						statsMu.Lock()
						s.errors++
						statsMu.Unlock()
						relayIdx++
						break
					}
					var ev streamEvent
					if err := json.Unmarshal(payload, &ev); err != nil {
						statsMu.Lock()
						s.errors++
						statsMu.Unlock()
						continue
					}
					if ev.Type == "welcome" {
						fmt.Println("stream_welcome:", ev.TS, "topic:", topic, "relay:", currentRelay)
						continue
					}
					if ev.Type != "signal" || ev.Entry == nil || ev.Entry.ID == "" {
						continue
					}
					statsMu.Lock()
					s.received++
					statsMu.Unlock()

					writeDir := *outDir
					if *splitByTopic {
						writeDir = filepath.Join(writeDir, sanitizeTopicForPath(topic))
						_ = os.MkdirAll(writeDir, 0755)
					}
					ok, err := storeStreamSignal(currentClient, &ev, writeDir, !*skipVerify, admission)
					if err != nil {
						fmt.Fprintln(os.Stderr, "warn: stream signal skipped:", ev.Entry.ID, err)
						continue
					}
					if ok {
						outPath := filepath.Join(writeDir, ev.Entry.ID+".signal.md")
						kept, reason, err := enforceContentPolicyFromPath(outPath, topic, policy, policyRejectDir)
						if err != nil {
							fmt.Fprintln(os.Stderr, "warn: stream policy check failed:", err)
							continue
						}
						if !kept {
							fmt.Println("quarantined_signal:", ev.Entry.ID, "topic:", topic, "reason:", reason)
							continue
						}
						statsMu.Lock()
						s.downloaded++
						statsMu.Unlock()
						fmt.Println("stream_saved:", ev.Entry.ID, "topic:", topic, "relay:", currentRelay)
						if strings.TrimSpace(*handler) != "" {
							go runSignalHandler(ctx, *handler, currentRelay, topic, ev.Entry.ID, outPath)
						}
					}
				}
				if !sleepWithContext(ctx, jitterBackoff(backoff)) {
					return
				}
				backoff = growBackoff(backoff, 2*time.Minute)
			}
		}(topicName, st)
	}

	<-ctx.Done()
	wg.Wait()

	// Summary
	statsMu.Lock()
	defer statsMu.Unlock()
	totalReceived := 0
	totalDownloaded := 0
	totalErrors := 0
	for _, s := range stats {
		totalReceived += s.received
		totalDownloaded += s.downloaded
		totalErrors += s.errors
	}
	if len(stats) == 1 {
		fmt.Println("stream_topic:", stats[0].topic)
		fmt.Println("stream_received:", totalReceived)
		fmt.Println("stream_downloaded:", totalDownloaded)
		fmt.Println("out_dir:", *outDir)
		return nil
	}
	fmt.Println("stream_topics:", strings.Join(wantTopics, ","))
	fmt.Println("stream_received:", totalReceived)
	fmt.Println("stream_downloaded:", totalDownloaded)
	fmt.Println("stream_errors:", totalErrors)
	fmt.Println("out_dir:", *outDir)
	return nil
}

func runAutojoinStreamWorker(
	ctx context.Context,
	relays []string,
	topic string,
	outDir string,
	reconnectBase time.Duration,
	reconnectMax time.Duration,
	handler string,
	onSaved func(client *transport.Client, topic, id, path string),
	onUpdate func(received, saved, errs int),
) {
	if onUpdate == nil {
		onUpdate = func(int, int, int) {}
	}
	if onSaved == nil {
		onSaved = func(*transport.Client, string, string, string) {}
	}
	if len(relays) == 0 {
		onUpdate(0, 0, 1)
		return
	}
	relayIdx := 0
	backoff := reconnectBase
	for {
		if ctx.Err() != nil {
			return
		}
		currentRelay := relays[relayIdx%len(relays)]
		client := transport.NewClient(currentRelay)
		streamURL, err := client.StreamURL(topic)
		if err != nil {
			onUpdate(0, 0, 1)
			relayIdx++
			if !sleepWithContext(ctx, jitterBackoff(backoff)) {
				return
			}
			backoff = growBackoff(backoff, reconnectMax)
			continue
		}
		conn, _, err := websocket.Dial(ctx, streamURL, nil)
		if err != nil {
			onUpdate(0, 0, 1)
			relayIdx++
			if !sleepWithContext(ctx, jitterBackoff(backoff)) {
				return
			}
			backoff = growBackoff(backoff, reconnectMax)
			continue
		}
		backoff = reconnectBase
		admission := security.NewAdmissionPolicy()
		for {
			_, payload, err := conn.Read(ctx)
			if err != nil {
				_ = conn.Close(websocket.StatusNormalClosure, "bye")
				if ctx.Err() != nil {
					return
				}
				onUpdate(0, 0, 1)
				break
			}
			var ev streamEvent
			if err := json.Unmarshal(payload, &ev); err != nil {
				onUpdate(0, 0, 1)
				continue
			}
			if ev.Type == "welcome" {
				continue
			}
			if ev.Type != "signal" || ev.Entry == nil || ev.Entry.ID == "" {
				continue
			}
			ok, err := storeStreamSignal(client, &ev, outDir, true, admission)
			if err != nil {
				onUpdate(1, 0, 1)
				continue
			}
			if ok {
				outPath := filepath.Join(outDir, ev.Entry.ID+".signal.md")
				onSaved(client, topic, ev.Entry.ID, outPath)
				if strings.TrimSpace(handler) != "" {
					go runSignalHandler(ctx, handler, currentRelay, topic, ev.Entry.ID, outPath)
				}
				onUpdate(1, 1, 0)
				continue
			}
			onUpdate(1, 0, 0)
		}
		if !sleepWithContext(ctx, jitterBackoff(backoff)) {
			return
		}
		relayIdx++
		backoff = growBackoff(backoff, reconnectMax)
	}
}

func growBackoff(current, max time.Duration) time.Duration {
	if current <= 0 {
		current = 2 * time.Second
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func jitterBackoff(base time.Duration) time.Duration {
	if base <= 0 {
		return time.Second
	}
	jitter := time.Duration(time.Now().UnixNano() % int64(base/2+1))
	return base + jitter
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func pullTopicSharded(client *transport.Client, topic string, limit int, outDir string, verifyAdmission bool, warn bool, shardCount int, admission *security.AdmissionPolicy, cursorFile string) (*pullResult, error) {
	ids := []string{}
	var err error
	// Chat topics are single-shard by design; avoid unnecessary multi-shard scanning.
	if strings.HasPrefix(topic, "dm.") || strings.HasPrefix(topic, "room.") {
		if sr, rerr := resolveShardWithRetry(client, topic, topic, 4); rerr == nil && sr != nil && sr.Shard >= 0 && sr.Shard < sr.ShardCount {
			ids, err = collectRecentSignalIDsForShard(client, topic, sr.Shard, limit, cursorFile)
		} else {
			ids, err = collectRecentSignalIDs(client, topic, limit, shardCount, cursorFile)
		}
	} else {
		ids, err = collectRecentSignalIDs(client, topic, limit, shardCount, cursorFile)
	}
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return &pullResult{
			Mode:       "v1",
			Topic:      topic,
			Count:      0,
			Downloaded: 0,
		}, nil
	}
	downloaded := downloadAndStoreSignals(client, ids, outDir, verifyAdmission, admission, warn)
	return &pullResult{
		Mode:       "v1",
		Topic:      topic,
		Count:      len(ids),
		Downloaded: downloaded,
	}, nil
}

func pullTopicShardedWithFailover(relays []string, topic string, limit int, outDir string, verifyAdmission bool, warn bool, shardCount int, admission *security.AdmissionPolicy, cursorFile string) (*pullResult, string, error) {
	if len(relays) == 0 {
		return nil, "", errors.New("no relay candidates")
	}
	var lastErr error
	for _, relay := range relays {
		client := transport.NewClient(relay)
		res, err := pullTopicSharded(client, topic, limit, outDir, verifyAdmission, warn, shardCount, admission, cursorFile)
		if err == nil {
			return res, relay, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("pull failed on all relays")
	}
	return nil, "", lastErr
}

func publishFastWithFailover(relays []string, raw string) (*transport.PublishResponse, string, error) {
	if len(relays) == 0 {
		return nil, "", errors.New("no relay candidates")
	}
	var lastErr error
	for _, relay := range relays {
		client := transport.NewClient(relay)
		resp, err := client.PublishFast(raw)
		if err == nil {
			return resp, relay, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("publish failed on all relays")
	}
	return nil, "", lastErr
}

func fetchBootstrapWithFailover(relays []string) (*transport.BootstrapProfile, string, error) {
	if len(relays) == 0 {
		return nil, "", errors.New("no relay candidates")
	}
	var lastErr error
	for _, relay := range relays {
		client := transport.NewClient(relay)
		profile, err := client.FetchBootstrap()
		if err == nil && profile != nil {
			return profile, relay, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("bootstrap fetch failed on all relays")
	}
	return nil, "", lastErr
}

func collectRecentSignalIDs(client *transport.Client, topic string, limit int, shardCount int, cursorFile string) ([]string, error) {
	if limit <= 0 {
		limit = 20
	}
	if shardCount < 1 {
		shardCount = 1
	}
	// Pulling from every shard in parallel is expensive and can trigger relay rate/budget guards.
	// Instead, we:
	// 1) fetch shard heads (cursor=0,limit=1) with a small concurrency limit
	// 2) prioritize shards that appear most active (or have the most new data since last cursor)
	// 3) pull tail windows from a limited number of shards and merge results by timestamp
	const shardTargetMax = 8
	targetShards := shardCount
	if targetShards > shardTargetMax {
		targetShards = shardTargetMax
	}
	perShard := (limit + targetShards - 1) / targetShards
	if perShard < 1 {
		perShard = 1
	}
	incrementalLimit := perShard
	if incrementalLimit < incrementalFeedMinLimit {
		// Same cost unit as <=50, but better catch-up after bursts.
		incrementalLimit = incrementalFeedMinLimit
	}
	state := loadCursorState(cursorFile)

	type shardMeta struct {
		shard int
		max   int64
		delta int64 // max - savedCursor (0 if no saved cursor)
	}
	type metaResult struct {
		m   shardMeta
		err error
	}
	sem := make(chan struct{}, 4)
	metaCh := make(chan metaResult, shardCount)
	var wg sync.WaitGroup
	for shard := 0; shard < shardCount; shard++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			head, err := feedCursorWithRetry(client, topic, s, 0, 1, 5)
			if err != nil || head == nil {
				metaCh <- metaResult{err: err}
				return
			}
			saved, ok := state.get(topic, s)
			delta := int64(0)
			if ok && head.MaxSeq > saved {
				delta = head.MaxSeq - saved
			}
			metaCh <- metaResult{m: shardMeta{shard: s, max: head.MaxSeq, delta: delta}, err: nil}
		}(shard)
	}
	wg.Wait()
	close(metaCh)

	metas := make([]shardMeta, 0, shardCount)
	okShards := 0
	for r := range metaCh {
		if r.err != nil {
			continue
		}
		okShards++
		metas = append(metas, r.m)
	}
	if okShards == 0 {
		return nil, errors.New("feed unavailable for all shards")
	}

	// Prefer shards with the most unseen data; otherwise fall back to the most active shards.
	sort.Slice(metas, func(i, j int) bool {
		if metas[i].delta == metas[j].delta {
			return metas[i].max > metas[j].max
		}
		return metas[i].delta > metas[j].delta
	})
	if len(metas) > targetShards {
		metas = metas[:targetShards]
	}

	type shardResp struct {
		shard int
		resp  *transport.CursorFeedResponse
		err   error
	}
	respCh := make(chan shardResp, len(metas))
	wg = sync.WaitGroup{}
	for _, m := range metas {
		wg.Add(1)
		go func(s int, maxSeq int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if savedCursor, ok := state.get(topic, s); ok && maxSeq > savedCursor {
				// Incremental catch-up.
				resp, err := feedCursorWithRetry(client, topic, s, savedCursor, incrementalLimit, 5)
				if err == nil && resp != nil {
					respCh <- shardResp{shard: s, resp: resp, err: nil}
					return
				}
			}

			// Fallback: read tail window.
			tailCursor := maxSeq - int64(perShard)
			if tailCursor < 0 {
				tailCursor = 0
			}
			resp, err := feedCursorWithRetry(client, topic, s, tailCursor, perShard, 5)
			respCh <- shardResp{shard: s, resp: resp, err: err}
		}(m.shard, m.max)
	}
	wg.Wait()
	close(respCh)

	entries := make([]transport.FeedEntry, 0, limit*2)
	okPulled := 0
	for item := range respCh {
		if item.err != nil || item.resp == nil {
			continue
		}
		okPulled++
		state.set(topic, item.shard, item.resp.NextCursor)
		entries = append(entries, item.resp.Entries...)
	}
	if okPulled == 0 {
		return nil, errors.New("feed unavailable for all shards")
	}
	_ = saveCursorState(cursorFile, state)
	if len(entries) == 0 {
		return nil, nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Timestamp == entries[j].Timestamp {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Timestamp > entries[j].Timestamp
	})

	ids := make([]string, 0, limit)
	seen := map[string]struct{}{}
	for _, e := range entries {
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		ids = append(ids, e.ID)
		if len(ids) >= limit {
			break
		}
	}
	return ids, nil
}

func downloadAndStoreSignals(client *transport.Client, ids []string, outDir string, verifyAdmission bool, admission *security.AdmissionPolicy, warn bool) int {
	if verifyAdmission && admission == nil {
		admission = security.NewAdmissionPolicy()
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return 0
	}
	downloaded := 0
	for _, id := range ids {
		outPath := filepath.Join(outDir, id+".signal.md")
		if _, err := os.Stat(outPath); err == nil {
			// Already cached locally: skip remote payload fetch to reduce relay read costs.
			continue
		}
		signal, err := getSignalWithRetry(client, id, 4, 250*time.Millisecond)
		if err != nil {
			if warn {
				fmt.Fprintln(os.Stderr, "warn: skip", id, ":", err)
			}
			continue
		}
		msg, err := protocol.ParseSignalMD(signal)
		if err != nil {
			if warn {
				fmt.Fprintln(os.Stderr, "warn: parse fail", id, ":", err)
			}
			continue
		}
		if verifyAdmission {
			if err := admission.Verify(msg); err != nil {
				if warn {
					fmt.Fprintln(os.Stderr, "warn: verify fail", id, ":", err)
				}
				continue
			}
		} else if err := protocol.VerifyMessage(msg); err != nil {
			if warn {
				fmt.Fprintln(os.Stderr, "warn: sig fail", id, ":", err)
			}
			continue
		}
		if err := os.WriteFile(outPath, []byte(signal), 0644); err != nil {
			if warn {
				fmt.Fprintln(os.Stderr, "warn: write fail", id, ":", err)
			}
			continue
		}
		downloaded++
	}
	return downloaded
}

func getSignalWithRetry(client *transport.Client, id string, attempts int, wait time.Duration) (string, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		signal, err := client.GetSignal(id)
		if err == nil {
			return signal, nil
		}
		lastErr = err
		if i < attempts-1 {
			time.Sleep(wait)
		}
	}
	return "", lastErr
}

func storeStreamSignal(client *transport.Client, ev *streamEvent, outDir string, verifyAdmission bool, admission *security.AdmissionPolicy) (bool, error) {
	if ev == nil || ev.Entry == nil || ev.Entry.ID == "" {
		return false, nil
	}
	id := ev.Entry.ID
	outPath := filepath.Join(outDir, id+".signal.md")
	if _, err := os.Stat(outPath); err == nil {
		return false, nil
	}

	raw := strings.TrimSpace(ev.Raw)
	if raw == "" {
		s, err := getSignalWithRetry(client, id, 3, 200*time.Millisecond)
		if err != nil {
			return false, err
		}
		raw = s
	}
	msg, err := protocol.ParseSignalMD(raw)
	if err != nil {
		return false, err
	}
	if verifyAdmission {
		if admission == nil {
			admission = security.NewAdmissionPolicy()
		}
		if err := admission.Verify(msg); err != nil {
			return false, err
		}
	} else if err := protocol.VerifyMessage(msg); err != nil {
		return false, err
	}
	if ev.Entry.Topic != "" && msg.Topic != ev.Entry.Topic {
		return false, errors.New("topic mismatch")
	}
	if err := os.WriteFile(outPath, []byte(raw), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func resolveBootstrap(raw string) (string, *transport.BootstrapProfile, error) {
	candidates := parseRelayCandidates(raw)
	if len(candidates) == 0 {
		return "", nil, errors.New("bootstrap is required")
	}
	var lastErr error
	for _, candidate := range candidates {
		relay := strings.TrimRight(candidate, "/")
		client := transport.NewClient(relay)
		profile, err := client.FetchBootstrap()
		if err != nil {
			lastErr = err
			continue
		}
		if profile == nil {
			continue
		}
		if profile.Relay != "" {
			relay = strings.TrimRight(profile.Relay, "/")
		}
		if profile.Join == "" {
			profile.Join = "permissionless"
		}
		profile.Relays = relayCandidatesFromBootstrap(raw, relay, profile)
		return relay, profile, nil
	}
	// Fallback: treat first input as direct relay endpoint.
	relay := strings.TrimRight(candidates[0], "/")
	_ = lastErr
	return relay, &transport.BootstrapProfile{
		AiwreV:         protocol.Version,
		Relay:          relay,
		Relays:         []string{relay},
		Join:           "permissionless",
		Capabilities:   []string{"v1"},
		ShardCount:     0,
		DefaultTopics:  []string{"global.announce"},
		HeartbeatTopic: "agent.heartbeat",
		ReportTopic:    "human.report",
		HumanReport:    true,
	}, nil
}

func parseRelayCandidates(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		v = strings.TrimRight(v, "/")
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func relayCandidatesFromBootstrap(rawInput, selected string, profile *transport.BootstrapProfile) []string {
	out := make([]string, 0, 8)
	push := func(v string) {
		v = strings.TrimRight(strings.TrimSpace(v), "/")
		if v == "" {
			return
		}
		for _, existing := range out {
			if strings.EqualFold(existing, v) {
				return
			}
		}
		out = append(out, v)
	}
	push(selected)
	for _, r := range parseRelayCandidates(rawInput) {
		push(r)
	}
	if profile != nil {
		push(profile.Relay)
		for _, r := range profile.Relays {
			push(r)
		}
	}
	if len(out) == 0 && strings.TrimSpace(selected) != "" {
		out = append(out, strings.TrimRight(strings.TrimSpace(selected), "/"))
	}
	return out
}

func loadOrCreateKeyPair(privPath string, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	priv, err := loadPrivateKey(privPath)
	if err == nil {
		pubRaw, err := os.ReadFile(pubPath)
		if err == nil {
			pubBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(pubRaw)))
			if err == nil && len(pubBytes) == ed25519.PublicKeySize {
				return priv, ed25519.PublicKey(pubBytes), false, nil
			}
		}
		pub := priv.Public().(ed25519.PublicKey)
		if err := os.WriteFile(pubPath, []byte(base64.RawStdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
			return nil, nil, false, err
		}
		return priv, pub, false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		// If Spark identity exists, import it in-place so CLI and Spark can share identity.
		base := filepath.Dir(privPath)
		if _, _, imported, impErr := maybeImportSparkIdentity(base); impErr == nil && imported {
			priv2, err2 := loadPrivateKey(privPath)
			if err2 == nil {
				pub := priv2.Public().(ed25519.PublicKey)
				_ = os.WriteFile(pubPath, []byte(base64.RawStdEncoding.EncodeToString(pub)+"\n"), 0644)
				return priv2, pub, false, nil
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(privPath), 0755); err != nil {
		return nil, nil, false, err
	}
	pub, newPriv, genErr := protocol.GenerateKeyPair()
	if genErr != nil {
		return nil, nil, false, genErr
	}
	if err := os.WriteFile(privPath, []byte(base64.RawStdEncoding.EncodeToString(newPriv)+"\n"), 0600); err != nil {
		return nil, nil, false, err
	}
	if err := os.WriteFile(pubPath, []byte(base64.RawStdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
		return nil, nil, false, err
	}
	return newPriv, pub, true, nil
}

func appendActivity(stateDir string, ev activityEvent) error {
	logPath := filepath.Join(stateDir, "activity.jsonl")
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	return err
}

func loadActivity(stateDir string, start time.Time) ([]activityEvent, error) {
	logPath := filepath.Join(stateDir, "activity.jsonl")
	f, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	out := make([]activityEvent, 0, 64)
	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			var ev activityEvent
			if decErr := json.Unmarshal(line, &ev); decErr == nil {
				t, parseErr := time.Parse(time.RFC3339, ev.Time)
				if parseErr == nil && !t.Before(start) {
					out = append(out, ev)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	return out, nil
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d", len(key))
	}
	return ed25519.PrivateKey(key), nil
}

// Spark (JS) stores identity in JWK format. Importing it makes Spark/CLI interoperable.
func maybeImportSparkIdentity(stateDir string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	base := strings.TrimSpace(stateDir)
	if base == "" {
		base = ".aiwre"
	}
	idPath := filepath.Join(base, "identity.json")
	raw, err := os.ReadFile(idPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, false, err
		}
		return nil, nil, false, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, false, fmt.Errorf("invalid spark identity.json: %w", err)
	}
	pjwkAny, ok := doc["private_jwk"]
	if !ok || pjwkAny == nil {
		return nil, nil, false, errors.New("spark identity.json missing private_jwk")
	}
	pjwk, ok := pjwkAny.(map[string]any)
	if !ok {
		return nil, nil, false, errors.New("spark private_jwk must be an object")
	}
	kty, _ := pjwk["kty"].(string)
	crv, _ := pjwk["crv"].(string)
	d, _ := pjwk["d"].(string)
	x, _ := pjwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || d == "" || x == "" {
		return nil, nil, false, errors.New("spark private_jwk must be OKP/Ed25519 with d/x")
	}
	seed, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid jwk.d: %w", err)
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid jwk.x: %w", err)
	}
	if len(seed) != ed25519.SeedSize || len(pubRaw) != ed25519.PublicKeySize {
		return nil, nil, false, errors.New("invalid jwk key sizes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, pubRaw) {
		// Still import, but warn via error to avoid silent mismatch.
		return nil, nil, false, errors.New("spark jwk public key mismatch")
	}

	privPath := filepath.Join(base, "ed25519_private.key")
	pubPath := filepath.Join(base, "ed25519_public.key")
	if err := os.MkdirAll(filepath.Dir(privPath), 0755); err != nil {
		return nil, nil, false, err
	}
	if err := os.WriteFile(privPath, []byte(base64.RawStdEncoding.EncodeToString(priv)+"\n"), 0600); err != nil {
		return nil, nil, false, err
	}
	if err := os.WriteFile(pubPath, []byte(base64.RawStdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
		return nil, nil, false, err
	}
	return priv, pub, true, nil
}

func loadPrivateForChat(privPath, stateDir string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(privPath) != "" {
		return loadPrivateKey(privPath)
	}
	base := strings.TrimSpace(stateDir)
	if base == "" {
		base = ".aiwre"
	}
	keyPath := filepath.Join(base, "ed25519_private.key")
	priv, err := loadPrivateKey(keyPath)
	if err == nil {
		return priv, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if _, _, imported, impErr := maybeImportSparkIdentity(base); impErr == nil && imported {
			return loadPrivateKey(keyPath)
		}
	}
	return nil, err
}

func normalizeSenderID(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if len(id) != 64 {
		return "", errors.New("sender fingerprint must be 64 hex chars")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", errors.New("sender fingerprint must be lowercase hex")
	}
	return id, nil
}

func parseAgentIDQuery(raw string) (sender string, alias string, err error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", "", errors.New("agent id query is empty")
	}
	if strings.HasPrefix(v, "aiwre:") {
		id, err := normalizeAgentIDURI(v)
		if err != nil {
			return "", "", err
		}
		return strings.TrimPrefix(id, "aiwre:"), "", nil
	}
	if strings.Contains(v, "@") {
		alias, err := normalizeAgentAlias(v, "")
		if err != nil {
			return "", "", fmt.Errorf("invalid alias query: %w", err)
		}
		return "", alias, nil
	}
	sender, err = normalizeSenderID(v)
	if err != nil {
		return "", "", errors.New("id query must be `aiwre:<sender_fp>`, `<sender_fp>`, or `<alias@domain>`")
	}
	return sender, "", nil
}

func normalizeAgentIDURI(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(v, "aiwre:") {
		return "", errors.New("agent id must start with aiwre:")
	}
	sender, err := normalizeSenderID(strings.TrimPrefix(v, "aiwre:"))
	if err != nil {
		return "", err
	}
	return "aiwre:" + sender, nil
}

func normalizeAgentAlias(raw string, relay string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", nil
	}
	local := v
	domain := ""
	if strings.Contains(v, "@") {
		parts := strings.Split(v, "@")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return "", errors.New("alias must be local@domain")
		}
		local = parts[0]
		domain = parts[1]
	} else if strings.TrimSpace(relay) != "" {
		domain = relayHost(relay)
		if domain == "" {
			return "", errors.New("cannot derive alias domain from relay")
		}
	} else {
		return "", errors.New("alias without domain requires relay host context")
	}
	if err := validateAliasLocal(local); err != nil {
		return "", err
	}
	if err := validateAliasDomain(domain); err != nil {
		return "", err
	}
	return local + "@" + domain, nil
}

func validateAliasLocal(local string) error {
	if len(local) < 3 || len(local) > 64 {
		return errors.New("alias local part length must be 3..64")
	}
	for i, ch := range local {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'
		if !ok {
			return fmt.Errorf("alias local has invalid character %q", ch)
		}
		if (i == 0 || i == len(local)-1) && !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
			return errors.New("alias local must start/end with alnum")
		}
	}
	return nil
}

func validateAliasDomain(domain string) error {
	if len(domain) < 3 || len(domain) > 253 {
		return errors.New("alias domain length must be 3..253")
	}
	for _, ch := range domain {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-'
		if !ok {
			return fmt.Errorf("alias domain has invalid character %q", ch)
		}
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return errors.New("alias domain format is invalid")
	}
	return nil
}

func relayHost(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	u, err = url.Parse("https://" + v)
	if err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

func normalizeTopicSegment(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", errors.New("value is empty")
	}
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return "", fmt.Errorf("invalid character %q", ch)
	}
	return s, nil
}

func parseTopicsCSV(raw string) []string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.ToLower(strings.TrimSpace(p))
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func uniqStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		s := strings.TrimSpace(v)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func sanitizeTopicForPath(topic string) string {
	// Convert topic to a safe directory name without introducing platform-specific semantics.
	// Keep it deterministic so different agents share the same layout.
	s := strings.ToLower(strings.TrimSpace(topic))
	if s == "" {
		return "topic"
	}
	var b strings.Builder
	for _, ch := range s {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_'
		if ok {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "topic"
	}
	return out
}

func runSignalHandler(parent context.Context, handler string, relay string, topic string, id string, path string) {
	h := strings.TrimSpace(handler)
	if h == "" {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, h, path)
	cmd.Env = append(os.Environ(),
		"AIWRE_RELAY="+strings.TrimSpace(relay),
		"AIWRE_TOPIC="+strings.TrimSpace(topic),
		"AIWRE_SIGNAL_ID="+strings.TrimSpace(id),
		"AIWRE_SIGNAL_PATH="+strings.TrimSpace(path),
	)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		out := strings.TrimSpace(buf.String())
		if out != "" {
			fmt.Fprintln(os.Stderr, "warn: handler failed:", err, "output:", out)
			return
		}
		fmt.Fprintln(os.Stderr, "warn: handler failed:", err)
	}
}

type contentPolicy struct {
	maxBodyBytes       int
	maxMetadataBytes   int
	maxMetadataDepth   int
	allowTypes         map[protocol.MessageType]struct{}
	allowTopicPrefixes []string
}

func newContentPolicy(maxBodyBytes, maxMetadataBytes, maxMetadataDepth int, allowTypesCSV, allowTopicPrefixesCSV string) (*contentPolicy, error) {
	if maxBodyBytes < 0 {
		return nil, errors.New("policy-max-body-bytes must be >= 0")
	}
	if maxMetadataBytes < 0 {
		return nil, errors.New("policy-max-metadata-bytes must be >= 0")
	}
	if maxMetadataDepth < 0 {
		return nil, errors.New("policy-max-metadata-depth must be >= 0")
	}
	types, err := parseAllowedMessageTypes(allowTypesCSV)
	if err != nil {
		return nil, err
	}
	prefixes := parseTopicsCSV(allowTopicPrefixesCSV)
	return &contentPolicy{
		maxBodyBytes:       maxBodyBytes,
		maxMetadataBytes:   maxMetadataBytes,
		maxMetadataDepth:   maxMetadataDepth,
		allowTypes:         types,
		allowTopicPrefixes: prefixes,
	}, nil
}

func parseAllowedMessageTypes(raw string) (map[protocol.MessageType]struct{}, error) {
	parts := parseCSV(raw)
	if len(parts) == 0 {
		return map[protocol.MessageType]struct{}{}, nil
	}
	out := map[protocol.MessageType]struct{}{}
	for _, p := range parts {
		mt := protocol.MessageType(strings.TrimSpace(strings.ToLower(p)))
		switch mt {
		case protocol.TypeBroadcast, protocol.TypeQuery, protocol.TypeResponse, protocol.TypeHeartbeat:
			out[mt] = struct{}{}
		default:
			return nil, fmt.Errorf("invalid policy message type: %s", p)
		}
	}
	return out, nil
}

func (p *contentPolicy) allowedTypeStrings() []string {
	if p == nil || len(p.allowTypes) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.allowTypes))
	for t := range p.allowTypes {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}

func (p *contentPolicy) check(msg *protocol.Message, topicHint string) error {
	if p == nil || msg == nil {
		return nil
	}
	if p.maxBodyBytes > 0 && len([]byte(msg.Body)) > p.maxBodyBytes {
		return fmt.Errorf("body too large: %d > %d", len([]byte(msg.Body)), p.maxBodyBytes)
	}
	if p.maxMetadataBytes > 0 && msg.Metadata != nil {
		metaRaw, err := json.Marshal(msg.Metadata)
		if err != nil {
			return fmt.Errorf("metadata marshal failed: %w", err)
		}
		if len(metaRaw) > p.maxMetadataBytes {
			return fmt.Errorf("metadata too large: %d > %d", len(metaRaw), p.maxMetadataBytes)
		}
	}
	if p.maxMetadataDepth > 0 {
		depth := metadataDepth(msg.Metadata)
		if depth > p.maxMetadataDepth {
			return fmt.Errorf("metadata depth exceeds limit: %d > %d", depth, p.maxMetadataDepth)
		}
	}
	if len(p.allowTypes) > 0 {
		if _, ok := p.allowTypes[msg.Type]; !ok {
			return fmt.Errorf("message type %s not allowed by policy", msg.Type)
		}
	}
	if len(p.allowTopicPrefixes) > 0 {
		topic := strings.TrimSpace(msg.Topic)
		if topic == "" {
			topic = strings.TrimSpace(topicHint)
		}
		allowed := false
		for _, prefix := range p.allowTopicPrefixes {
			if strings.HasPrefix(topic, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("topic %s not allowed by policy prefixes", topic)
		}
	}
	return nil
}

func metadataDepth(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case map[string]any:
		maxD := 1
		for _, child := range t {
			d := 1 + metadataDepth(child)
			if d > maxD {
				maxD = d
			}
		}
		return maxD
	case []any:
		maxD := 1
		for _, child := range t {
			d := 1 + metadataDepth(child)
			if d > maxD {
				maxD = d
			}
		}
		return maxD
	default:
		return 1
	}
}

func enforceContentPolicyFromPath(path, topic string, policy *contentPolicy, quarantineDir string) (bool, string, error) {
	if policy == nil {
		return true, "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, "", err
	}
	msg, err := protocol.ParseSignalMD(string(raw))
	if err != nil || msg == nil {
		if err == nil {
			err = errors.New("empty parsed signal")
		}
		reason := "invalid_signal_format"
		qerr := quarantineSignalFile(path, topic, quarantineDir, reason)
		if qerr != nil {
			return false, reason, qerr
		}
		return false, reason, nil
	}
	if err := policy.check(msg, topic); err != nil {
		reason := sanitizePolicyReason(err.Error())
		qerr := quarantineSignalFile(path, topic, quarantineDir, reason)
		if qerr != nil {
			return false, reason, qerr
		}
		return false, reason, nil
	}
	return true, "", nil
}

func sanitizePolicyReason(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "policy_reject"
	}
	var b strings.Builder
	for _, ch := range s {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if ok {
			b.WriteRune(ch)
			continue
		}
		if ch == '_' || ch == '-' {
			b.WriteRune(ch)
			continue
		}
		if ch == ' ' {
			b.WriteRune('_')
			continue
		}
	}
	out := strings.Trim(b.String(), "_-")
	if out == "" {
		return "policy_reject"
	}
	return out
}

func quarantineSignalFile(srcPath, topic, baseDir, reason string) error {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "./quarantine"
	}
	targetDir := filepath.Join(baseDir, sanitizeTopicForPath(topic), reason)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	targetPath := filepath.Join(targetDir, filepath.Base(srcPath))
	if err := os.Rename(srcPath, targetPath); err == nil {
		return nil
	}
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(targetPath, raw, 0644); err != nil {
		return err
	}
	return os.Remove(srcPath)
}

type chatConfigFile struct {
	DM    []chatDMConfig   `json:"dm"`
	Rooms []chatRoomConfig `json:"rooms"`
}

type chatDMConfig struct {
	Peer      string `json:"peer"`
	Secret    string `json:"secret"`
	AutoReply *bool  `json:"auto_reply,omitempty"`
	ReplyMode string `json:"reply_mode,omitempty"`
	ReplyText string `json:"reply_text,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

type chatRoomConfig struct {
	Room      string `json:"room"`
	Secret    string `json:"secret"`
	AutoReply *bool  `json:"auto_reply,omitempty"`
	ReplyMode string `json:"reply_mode,omitempty"`
	ReplyText string `json:"reply_text,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

type chatSubscription struct {
	Kind      string
	Topic     string
	Secret    string
	Peer      string
	Room      string
	AutoReply bool
	ReplyMode string
	ReplyText string
}

type chatRuntime struct {
	mu            sync.Mutex
	relay         string
	stateDir      string
	configPath    string
	inboxDir      string
	statePath     string
	selfID        string
	priv          ed25519.PrivateKey
	autoReply     bool
	replyMinGap   time.Duration
	replyDailyCap int
	subByTopic    map[string]chatSubscription
	topics        []string
	state         *chatRuntimeState
}

type chatRuntimeState struct {
	Version      int               `json:"version"`
	UpdatedAt    string            `json:"updated_at"`
	Day          string            `json:"day"`
	RepliesToday int               `json:"replies_today"`
	LastReplyAt  string            `json:"last_reply_at,omitempty"`
	Handled      map[string]string `json:"handled,omitempty"`
	Replied      map[string]string `json:"replied,omitempty"`
}

func newChatRuntime(relay, stateDir, selfID string, priv ed25519.PrivateKey, configPath string, autoReply bool, replyMinGap time.Duration, replyDailyCap int) (*chatRuntime, error) {
	base := strings.TrimSpace(stateDir)
	if base == "" {
		base = ".aiwre"
	}
	cfgPath, ok, err := resolveChatConfigPath(base, configPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	cfg, err := loadChatConfigFile(cfgPath)
	if err != nil {
		return nil, err
	}
	self := strings.ToLower(strings.TrimSpace(selfID))
	if self == "" {
		return nil, errors.New("self id is required for chat runtime")
	}
	if replyMinGap < 0 {
		replyMinGap = 0
	}
	if replyDailyCap < 0 {
		replyDailyCap = 0
	}

	subByTopic := map[string]chatSubscription{}
	topics := make([]string, 0, len(cfg.DM)+len(cfg.Rooms))
	for _, entry := range cfg.DM {
		if !boolWithDefault(entry.Enabled, true) {
			continue
		}
		peer, err := normalizeSenderID(entry.Peer)
		if err != nil {
			return nil, fmt.Errorf("chat config dm.peer: %w", err)
		}
		secret := strings.TrimSpace(entry.Secret)
		if secret == "" {
			return nil, fmt.Errorf("chat config dm.peer=%s: secret is required", peer)
		}
		topic := dmTopic(self, peer)
		mode := normalizeChatReplyMode(entry.ReplyMode, "always")
		subByTopic[topic] = chatSubscription{
			Kind:      "dm",
			Topic:     topic,
			Secret:    secret,
			Peer:      peer,
			AutoReply: boolWithDefault(entry.AutoReply, true),
			ReplyMode: mode,
			ReplyText: strings.TrimSpace(entry.ReplyText),
		}
		topics = append(topics, topic)
	}
	for _, entry := range cfg.Rooms {
		if !boolWithDefault(entry.Enabled, true) {
			continue
		}
		room, err := normalizeTopicSegment(entry.Room)
		if err != nil {
			return nil, fmt.Errorf("chat config room: %w", err)
		}
		secret := strings.TrimSpace(entry.Secret)
		if secret == "" {
			return nil, fmt.Errorf("chat config room=%s: secret is required", room)
		}
		topic := "room." + room
		mode := normalizeChatReplyMode(entry.ReplyMode, "query")
		subByTopic[topic] = chatSubscription{
			Kind:      "room",
			Topic:     topic,
			Secret:    secret,
			Room:      room,
			AutoReply: boolWithDefault(entry.AutoReply, true),
			ReplyMode: mode,
			ReplyText: strings.TrimSpace(entry.ReplyText),
		}
		topics = append(topics, topic)
	}
	topics = uniqStrings(topics)
	if len(topics) == 0 {
		return nil, nil
	}

	return &chatRuntime{
		relay:         strings.TrimSpace(relay),
		stateDir:      base,
		configPath:    cfgPath,
		inboxDir:      filepath.Join(base, "chat-inbox"),
		statePath:     filepath.Join(base, chatStateFileName),
		selfID:        self,
		priv:          priv,
		autoReply:     autoReply,
		replyMinGap:   replyMinGap,
		replyDailyCap: replyDailyCap,
		subByTopic:    subByTopic,
		topics:        topics,
		state:         loadChatRuntimeState(filepath.Join(base, chatStateFileName)),
	}, nil
}

func (r *chatRuntime) watchTopics() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.topics))
	out = append(out, r.topics...)
	sort.Strings(out)
	return out
}

func (r *chatRuntime) handleSaved(client *transport.Client, topic string, id string, path string) error {
	if r == nil || client == nil {
		return nil
	}
	sub, ok := r.subByTopic[strings.TrimSpace(topic)]
	if !ok {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	msg, err := protocol.ParseSignalMD(string(raw))
	if err != nil || msg == nil {
		return err
	}
	if strings.TrimSpace(msg.ID) == "" {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(msg.Sender)) == r.selfID {
		return nil
	}
	if strings.TrimSpace(msg.Topic) != sub.Topic {
		return nil
	}

	r.mu.Lock()
	now := time.Now().UTC()
	r.rollDay(now)
	r.pruneState(now)
	if _, seen := r.state.Handled[msg.ID]; seen {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	if interactionMetaString(msg.Metadata, "chat") != sub.Kind {
		return nil
	}
	if interactionMetaString(msg.Metadata, "enc") != "aes-256-gcm" {
		return nil
	}
	nonce := interactionMetaString(msg.Metadata, "enc_nonce")
	if nonce == "" {
		return nil
	}
	plain, err := decryptChatBody(sub.Secret, sub.Topic, msg.Body, nonce)
	if err != nil {
		return nil
	}
	if err := r.writeDecrypted(sub, msg, plain); err != nil {
		return err
	}

	shouldReply := false
	reserveReply := false
	now = time.Now().UTC()
	r.mu.Lock()
	r.rollDay(now)
	r.pruneState(now)
	r.state.Handled[msg.ID] = now.Format(time.RFC3339)
	if r.autoReply && sub.AutoReply && !isChatAutoReplyMessage(msg.Metadata) && r.shouldAutoReply(sub, msg, plain) {
		if _, exists := r.state.Replied[msg.ID]; !exists {
			if r.replyDailyCap <= 0 || r.state.RepliesToday < r.replyDailyCap {
				if r.replyMinGap <= 0 || r.lastReplyGapEnough(now) {
					shouldReply = true
					reserveReply = true
					r.state.Replied[msg.ID] = "pending"
					r.state.RepliesToday++
					r.state.LastReplyAt = now.Format(time.RFC3339)
				}
			}
		}
	}
	if err := saveChatRuntimeState(r.statePath, r.state); err != nil {
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()

	if !shouldReply {
		return nil
	}
	replyID, err := r.publishAutoReply(client, sub, msg)
	if err != nil {
		if reserveReply {
			r.mu.Lock()
			delete(r.state.Replied, msg.ID)
			if r.state.RepliesToday > 0 {
				r.state.RepliesToday--
			}
			_ = saveChatRuntimeState(r.statePath, r.state)
			r.mu.Unlock()
		}
		return err
	}
	now = time.Now().UTC()
	r.mu.Lock()
	r.state.Replied[msg.ID] = now.Format(time.RFC3339)
	_ = saveChatRuntimeState(r.statePath, r.state)
	r.mu.Unlock()
	_ = appendActivity(r.stateDir, activityEvent{
		Time:      now.Format(time.RFC3339),
		Action:    "publish",
		Relay:     r.relay,
		Topic:     sub.Topic,
		MessageID: replyID,
		Count:     1,
		Detail:    fmt.Sprintf("phase=chat_auto_reply kind=%s reply_to=%s", sub.Kind, msg.ID),
	})
	fmt.Println("chat_auto_reply:", replyID, "topic:", sub.Topic, "reply_to:", msg.ID)
	return nil
}

func (r *chatRuntime) lastReplyGapEnough(now time.Time) bool {
	if r == nil || r.state == nil {
		return true
	}
	if r.replyMinGap <= 0 || strings.TrimSpace(r.state.LastReplyAt) == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339, r.state.LastReplyAt)
	if err != nil {
		return true
	}
	return now.Sub(last) >= r.replyMinGap
}

func (r *chatRuntime) shouldAutoReply(sub chatSubscription, msg *protocol.Message, plain string) bool {
	if r == nil || msg == nil {
		return false
	}
	mode := normalizeChatReplyMode(sub.ReplyMode, "always")
	switch mode {
	case "never":
		return false
	case "query":
		return msg.Type == protocol.TypeQuery
	case "mention":
		to := strings.ToLower(strings.TrimSpace(interactionMetaString(msg.Metadata, "to")))
		if to != "" && to == r.selfID {
			return true
		}
		needle := "@" + shortFingerprint(r.selfID)
		return strings.Contains(strings.ToLower(plain), strings.ToLower(needle))
	default:
		return true
	}
}

func (r *chatRuntime) publishAutoReply(client *transport.Client, sub chatSubscription, incoming *protocol.Message) (string, error) {
	if r == nil || client == nil {
		return "", errors.New("chat runtime unavailable")
	}
	replyText := strings.TrimSpace(sub.ReplyText)
	if replyText == "" {
		if sub.Kind == "dm" {
			replyText = fmt.Sprintf("ack: received %s from %s", shortFingerprint(incoming.ID), shortFingerprint(incoming.Sender))
		} else {
			replyText = fmt.Sprintf("ack: %s received in room %s", shortFingerprint(incoming.ID), sub.Room)
		}
	}
	if !strings.HasSuffix(replyText, "\n") {
		replyText += "\n"
	}
	cipherText, nonce, err := encryptChatBody(sub.Secret, sub.Topic, replyText)
	if err != nil {
		return "", err
	}
	meta := map[string]any{
		"chat":            sub.Kind,
		"chat_v":          "1",
		"enc":             "aes-256-gcm",
		"enc_nonce":       nonce,
		"chat_auto_reply": true,
		"reply_to":        incoming.ID,
	}
	if sub.Kind == "room" {
		meta["room"] = sub.Room
	}
	if sub.Kind == "dm" {
		meta["peer"] = sub.Peer
		meta["to"] = incoming.Sender
	}
	reply := &protocol.Message{
		Topic:    sub.Topic,
		Type:     protocol.TypeResponse,
		TTL:      protocol.DefaultTTL,
		Metadata: meta,
		Body:     cipherText,
	}
	return publishSignedMessage(client, r.priv, reply)
}

func (r *chatRuntime) writeDecrypted(sub chatSubscription, msg *protocol.Message, plain string) error {
	if r == nil || msg == nil {
		return nil
	}
	dir := filepath.Join(r.inboxDir, sanitizeTopicForPath(sub.Topic))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	outPath := filepath.Join(dir, msg.ID+".txt")
	if _, err := os.Stat(outPath); err == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("id: " + msg.ID + "\n")
	b.WriteString("timestamp: " + msg.Timestamp + "\n")
	b.WriteString("sender: " + msg.Sender + "\n")
	b.WriteString("topic: " + msg.Topic + "\n")
	b.WriteString("type: " + string(msg.Type) + "\n")
	if sub.Kind == "dm" && sub.Peer != "" {
		b.WriteString("peer: " + sub.Peer + "\n")
	}
	if sub.Kind == "room" && sub.Room != "" {
		b.WriteString("room: " + sub.Room + "\n")
	}
	b.WriteString("---\n")
	b.WriteString(plain)
	if !strings.HasSuffix(plain, "\n") {
		b.WriteString("\n")
	}
	return os.WriteFile(outPath, []byte(b.String()), 0644)
}

func (r *chatRuntime) rollDay(now time.Time) {
	if r == nil || r.state == nil {
		return
	}
	day := now.Format("2006-01-02")
	if r.state.Day == day {
		return
	}
	r.state.Day = day
	r.state.RepliesToday = 0
}

func (r *chatRuntime) pruneState(now time.Time) {
	if r == nil || r.state == nil {
		return
	}
	cutoff := now.Add(-72 * time.Hour)
	for id, ts := range r.state.Handled {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(ts))
		if err != nil || t.Before(cutoff) {
			delete(r.state.Handled, id)
		}
	}
	for id, ts := range r.state.Replied {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(ts))
		if err != nil || t.Before(cutoff) {
			delete(r.state.Replied, id)
		}
	}
	if len(r.state.Handled) > 8192 {
		i := 0
		for id := range r.state.Handled {
			delete(r.state.Handled, id)
			i++
			if len(r.state.Handled) <= 4096 || i > 8192 {
				break
			}
		}
	}
	if len(r.state.Replied) > 8192 {
		i := 0
		for id := range r.state.Replied {
			delete(r.state.Replied, id)
			i++
			if len(r.state.Replied) <= 4096 || i > 8192 {
				break
			}
		}
	}
}

func resolveChatConfigPath(stateDir, raw string) (string, bool, error) {
	if strings.TrimSpace(raw) != "" {
		path := strings.TrimSpace(raw)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return "", false, fmt.Errorf("chat config file not found: %s", path)
			}
			return "", false, err
		}
		return path, true, nil
	}
	path := filepath.Join(stateDir, defaultChatConfigName)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return path, true, nil
}

func loadChatConfigFile(path string) (*chatConfigFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg chatConfigFile
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid chat config json: %w", err)
	}
	return &cfg, nil
}

func boolWithDefault(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}

func normalizeChatReplyMode(v, fallback string) string {
	mode := strings.ToLower(strings.TrimSpace(v))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(fallback))
	}
	switch mode {
	case "always", "query", "mention", "never":
		return mode
	default:
		return strings.ToLower(strings.TrimSpace(fallback))
	}
}

func isChatAutoReplyMessage(meta map[string]any) bool {
	raw := strings.ToLower(strings.TrimSpace(interactionMetaString(meta, "chat_auto_reply")))
	return raw == "true" || raw == "1" || raw == "yes"
}

func loadChatRuntimeState(path string) *chatRuntimeState {
	out := &chatRuntimeState{
		Version: 1,
		Day:     time.Now().UTC().Format("2006-01-02"),
		Handled: map[string]string{},
		Replied: map[string]string{},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var parsed chatRuntimeState
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out
	}
	if parsed.Version == 0 {
		parsed.Version = 1
	}
	if parsed.Day == "" {
		parsed.Day = out.Day
	}
	if parsed.Handled == nil {
		parsed.Handled = map[string]string{}
	}
	if parsed.Replied == nil {
		parsed.Replied = map[string]string{}
	}
	return &parsed
}

func saveChatRuntimeState(path string, state *chatRuntimeState) error {
	if strings.TrimSpace(path) == "" || state == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type interactionRuntime struct {
	mu              sync.Mutex
	relay           string
	stateDir        string
	statePath       string
	selfID          string
	priv            ed25519.PrivateKey
	seedMinInterval time.Duration
	replyMinGap     time.Duration
	replyDailyCap   int
	replySampleMod  int
	state           *interactionState
}

type interactionState struct {
	Version      int               `json:"version"`
	UpdatedAt    string            `json:"updated_at"`
	Day          string            `json:"day"`
	RepliesToday int               `json:"replies_today"`
	LastReplyAt  string            `json:"last_reply_at,omitempty"`
	LastSeedAt   string            `json:"last_seed_at,omitempty"`
	Replied      map[string]string `json:"replied,omitempty"`
}

func newInteractionRuntime(relay, stateDir, selfID string, priv ed25519.PrivateKey, seedMinInterval, replyMinGap time.Duration, replyDailyCap, replySampleMod int) *interactionRuntime {
	base := strings.TrimSpace(stateDir)
	if base == "" {
		base = ".aiwre"
	}
	if seedMinInterval < 0 {
		seedMinInterval = 0
	}
	if replyMinGap < 0 {
		replyMinGap = 0
	}
	if replyDailyCap < 0 {
		replyDailyCap = 0
	}
	if replySampleMod < 1 {
		replySampleMod = 1
	}
	if replySampleMod > 4096 {
		replySampleMod = 4096
	}
	return &interactionRuntime{
		relay:           strings.TrimSpace(relay),
		stateDir:        base,
		statePath:       filepath.Join(base, interactionStateFileName),
		selfID:          strings.ToLower(strings.TrimSpace(selfID)),
		priv:            priv,
		seedMinInterval: seedMinInterval,
		replyMinGap:     replyMinGap,
		replyDailyCap:   replyDailyCap,
		replySampleMod:  replySampleMod,
		state:           loadInteractionState(filepath.Join(base, interactionStateFileName)),
	}
}

func (r *interactionRuntime) maybeSeedDiscovery(client *transport.Client) (id string, seeded bool, err error) {
	if r == nil || client == nil {
		return "", false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	r.rollDay(now)
	if r.seedMinInterval > 0 && strings.TrimSpace(r.state.LastSeedAt) != "" {
		if last, parseErr := time.Parse(time.RFC3339, r.state.LastSeedAt); parseErr == nil && now.Sub(last) < r.seedMinInterval {
			return "", false, nil
		}
	}

	msg := &protocol.Message{
		Topic: "global.announce",
		Type:  protocol.TypeQuery,
		TTL:   300,
		Metadata: map[string]any{
			"client":           "aiwre-cli",
			"client_v":         "1.0",
			"interaction_pack": "v1",
			"interaction_kind": "discover",
			"from":             r.selfID,
			"reply_sample_mod": r.replySampleMod,
		},
		Body: "discover ping: online agent seeking peers. reply with type=response.\n",
	}
	pubID, pubErr := publishSignedMessage(client, r.priv, msg)
	if pubErr != nil {
		return "", false, pubErr
	}

	r.state.LastSeedAt = now.Format(time.RFC3339)
	if saveErr := saveInteractionState(r.statePath, r.state); saveErr != nil {
		return pubID, true, saveErr
	}
	_ = appendActivity(r.stateDir, activityEvent{
		Time:      now.Format(time.RFC3339),
		Action:    "publish",
		Relay:     r.relay,
		Topic:     msg.Topic,
		MessageID: pubID,
		Count:     1,
		Detail:    "phase=interaction_seed type=query",
	})
	return pubID, true, nil
}

func (r *interactionRuntime) maybeAutoReplyFromPath(client *transport.Client, topic string, id string, path string) error {
	if r == nil || client == nil {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	msg, err := protocol.ParseSignalMD(string(raw))
	if err != nil || msg == nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(msg.Sender)) == r.selfID {
		return nil
	}
	if msg.Type != protocol.TypeQuery {
		return nil
	}
	if strings.TrimSpace(msg.ID) == "" {
		return nil
	}
	if strings.TrimSpace(msg.Topic) == "" || strings.TrimSpace(msg.Topic) != strings.TrimSpace(topic) {
		return nil
	}
	kind := interactionMetaString(msg.Metadata, "interaction_kind")
	if kind != "discover" {
		return nil
	}
	toID := strings.ToLower(strings.TrimSpace(interactionMetaString(msg.Metadata, "to")))
	if toID != "" && toID != r.selfID {
		return nil
	}

	// Never allow inbound metadata to make us reply more aggressively.
	// Peers may only request sparser replies (higher mod), not denser ones.
	sampleMod := r.replySampleMod
	inboundSampleMod := interactionMetaInt(msg.Metadata, "reply_sample_mod", sampleMod)
	if inboundSampleMod > sampleMod {
		sampleMod = inboundSampleMod
	}
	if sampleMod < 1 {
		sampleMod = 1
	}
	if sampleMod > 4096 {
		sampleMod = 4096
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	r.rollDay(now)
	r.pruneReplied(now)
	if _, ok := r.state.Replied[msg.ID]; ok {
		return nil
	}
	if r.replyDailyCap > 0 && r.state.RepliesToday >= r.replyDailyCap {
		return nil
	}
	if r.replyMinGap > 0 && strings.TrimSpace(r.state.LastReplyAt) != "" {
		if last, parseErr := time.Parse(time.RFC3339, r.state.LastReplyAt); parseErr == nil && now.Sub(last) < r.replyMinGap {
			return nil
		}
	}
	if !interactionSelectedForReply(r.selfID, msg.ID, sampleMod) {
		return nil
	}

	reply := &protocol.Message{
		Topic: msg.Topic,
		Type:  protocol.TypeResponse,
		TTL:   300,
		Metadata: map[string]any{
			"client":           "aiwre-cli",
			"client_v":         "1.0",
			"interaction_pack": "v1",
			"interaction_kind": "discover_ack",
			"reply_to":         msg.ID,
			"to":               msg.Sender,
		},
		Body: fmt.Sprintf("discover ack from %s\n", shortFingerprint(r.selfID)),
	}
	replyID, pubErr := publishSignedMessage(client, r.priv, reply)
	if pubErr != nil {
		return pubErr
	}

	if r.state.Replied == nil {
		r.state.Replied = map[string]string{}
	}
	r.state.Replied[msg.ID] = now.Format(time.RFC3339)
	r.state.RepliesToday++
	r.state.LastReplyAt = now.Format(time.RFC3339)
	if saveErr := saveInteractionState(r.statePath, r.state); saveErr != nil {
		return saveErr
	}
	_ = appendActivity(r.stateDir, activityEvent{
		Time:      now.Format(time.RFC3339),
		Action:    "publish",
		Relay:     r.relay,
		Topic:     reply.Topic,
		MessageID: replyID,
		Count:     1,
		Detail:    fmt.Sprintf("phase=interaction_reply reply_to=%s", msg.ID),
	})
	fmt.Println("interaction_reply:", replyID, "to:", shortFingerprint(msg.Sender), "reply_to:", msg.ID)
	return nil
}

func (r *interactionRuntime) rollDay(now time.Time) {
	if r == nil || r.state == nil {
		return
	}
	day := now.Format("2006-01-02")
	if strings.TrimSpace(r.state.Day) == day {
		return
	}
	r.state.Day = day
	r.state.RepliesToday = 0
}

func (r *interactionRuntime) pruneReplied(now time.Time) {
	if r == nil || r.state == nil || len(r.state.Replied) == 0 {
		return
	}
	cutoff := now.Add(-48 * time.Hour)
	for id, ts := range r.state.Replied {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(ts))
		if err != nil || t.Before(cutoff) {
			delete(r.state.Replied, id)
		}
	}
	if len(r.state.Replied) <= 4096 {
		return
	}
	// Hard cap in case clocks/parse issues keep old entries around.
	i := 0
	for id := range r.state.Replied {
		delete(r.state.Replied, id)
		i++
		if len(r.state.Replied) <= 2048 || i > 4096 {
			break
		}
	}
}

func interactionMetaString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func interactionMetaInt(meta map[string]any, key string, fallback int) int {
	if meta == nil {
		return fallback
	}
	v, ok := meta[key]
	if !ok || v == nil {
		return fallback
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return int(n)
		}
		return fallback
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
		return fallback
	default:
		return fallback
	}
}

func interactionSelectedForReply(selfID, queryID string, mod int) bool {
	if mod <= 1 {
		return true
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(selfID)) + "|" + strings.ToLower(strings.TrimSpace(queryID))))
	n := binary.BigEndian.Uint32(sum[:4])
	return int(n%uint32(mod)) == 0
}

func publishSignedMessage(client *transport.Client, priv ed25519.PrivateKey, msg *protocol.Message) (string, error) {
	if client == nil {
		return "", errors.New("relay client is nil")
	}
	if msg == nil {
		return "", errors.New("message is nil")
	}
	if err := protocol.SignMessage(msg, priv); err != nil {
		return "", err
	}
	raw, err := protocol.RenderSignalMD(msg)
	if err != nil {
		return "", err
	}
	policy := security.NewAdmissionPolicy()
	if err := policy.Verify(msg); err != nil {
		return "", fmt.Errorf("local verify failed: %w", err)
	}
	resp, err := client.PublishFast(raw)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

func shortFingerprint(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func loadInteractionState(path string) *interactionState {
	out := &interactionState{
		Version: 1,
		Day:     time.Now().UTC().Format("2006-01-02"),
		Replied: map[string]string{},
	}
	if strings.TrimSpace(path) == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var parsed interactionState
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out
	}
	if parsed.Version == 0 {
		parsed.Version = 1
	}
	if parsed.Day == "" {
		parsed.Day = out.Day
	}
	if parsed.Replied == nil {
		parsed.Replied = map[string]string{}
	}
	return &parsed
}

func saveInteractionState(path string, state *interactionState) error {
	if strings.TrimSpace(path) == "" || state == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func dmTopic(a, b string) string {
	if a <= b {
		return "dm." + a + "." + b
	}
	return "dm." + b + "." + a
}

func readPlainBody(inPath, inline string) (string, error) {
	hasInline := strings.TrimSpace(inline) != ""
	hasFile := strings.TrimSpace(inPath) != ""
	if hasInline == hasFile {
		return "", errors.New("provide exactly one of --in or --body")
	}
	if hasInline {
		return inline, nil
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func encryptChatBody(secret, topic, plain string) (string, string, error) {
	key := sha256.Sum256([]byte("aiwre-chat-v1|" + topic + "|" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	cipherRaw := gcm.Seal(nil, nonce, []byte(plain), nil)
	return base64.RawStdEncoding.EncodeToString(cipherRaw), base64.RawStdEncoding.EncodeToString(nonce), nil
}

func decryptChatBody(secret, topic, cipherB64, nonceB64 string) (string, error) {
	key := sha256.Sum256([]byte("aiwre-chat-v1|" + topic + "|" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(nonceB64))
	if err != nil {
		return "", fmt.Errorf("invalid nonce encoding: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return "", errors.New("invalid nonce size")
	}
	cipherRaw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cipherB64))
	if err != nil {
		return "", fmt.Errorf("invalid cipher body encoding: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, cipherRaw, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func pullAndDecryptChat(client *transport.Client, topic, secret string, limit int, outDir string, verifyAdmission bool, chatMode string) (int, error) {
	// Chat topics (dm./room.) are designed to be pullable without scanning all shards.
	// Prefer deterministic shard targeting via /v1/resolve-shard using key=topic.
	shard := -1
	if sr, err := resolveShardWithRetry(client, topic, topic, 4); err == nil && sr != nil {
		if sr.Shard >= 0 && sr.Shard < sr.ShardCount {
			shard = sr.Shard
		}
	}
	var ids []string
	var err error
	if shard >= 0 {
		ids, err = collectRecentSignalIDsForShard(client, topic, shard, limit, cursorStatePath(outDir))
	} else {
		// Fallback: scan shards (may be rate-limited).
		profile, bootErr := client.FetchBootstrap()
		if bootErr != nil {
			return 0, bootErr
		}
		shardCount := profile.ShardCount
		if shardCount < 1 {
			shardCount = 1
		}
		ids, err = collectRecentSignalIDs(client, topic, limit, shardCount, cursorStatePath(outDir))
	}
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return 0, err
	}
	var admission *security.AdmissionPolicy
	if verifyAdmission {
		admission = security.NewAdmissionPolicy()
	}
	saved := 0
	for _, id := range ids {
		outPath := filepath.Join(outDir, id+".txt")
		if _, err := os.Stat(outPath); err == nil {
			// Deterministic file naming avoids re-downloading/decrypting the same message on every pull.
			continue
		}
		signal, err := getSignalWithRetry(client, id, 4, 250*time.Millisecond)
		if err != nil {
			continue
		}
		msg, err := protocol.ParseSignalMD(signal)
		if err != nil {
			continue
		}
		if verifyAdmission {
			if err := admission.Verify(msg); err != nil {
				continue
			}
		} else if err := protocol.VerifyMessage(msg); err != nil {
			continue
		}
		if msg.Topic != topic {
			continue
		}
		mode, _ := msg.Metadata["chat"].(string)
		if mode != chatMode {
			continue
		}
		enc, _ := msg.Metadata["enc"].(string)
		if enc != "aes-256-gcm" {
			continue
		}
		nonce, _ := msg.Metadata["enc_nonce"].(string)
		if nonce == "" {
			continue
		}
		plain, err := decryptChatBody(secret, topic, msg.Body, nonce)
		if err != nil {
			continue
		}
		out := strings.Builder{}
		out.WriteString("id: " + msg.ID + "\n")
		out.WriteString("timestamp: " + msg.Timestamp + "\n")
		out.WriteString("sender: " + msg.Sender + "\n")
		out.WriteString("topic: " + msg.Topic + "\n")
		out.WriteString("type: " + string(msg.Type) + "\n")
		out.WriteString("---\n")
		out.WriteString(plain)
		if !strings.HasSuffix(plain, "\n") {
			out.WriteString("\n")
		}
		if err := os.WriteFile(outPath, []byte(out.String()), 0644); err != nil {
			continue
		}
		saved++
	}
	return saved, nil
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	// Transport errors include: "feed cursor failed: status=429 body=..."
	return strings.Contains(err.Error(), "status=429")
}

func resolveShardWithRetry(client *transport.Client, topic string, key string, attempts int) (*transport.ShardResolveResponse, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	if attempts < 1 {
		attempts = 1
	}
	wait := 200 * time.Millisecond
	for i := 0; i < attempts; i++ {
		resp, err := client.ResolveShard(topic, key)
		if err == nil {
			return resp, nil
		}
		if !isRateLimitError(err) || i == attempts-1 {
			return nil, err
		}
		time.Sleep(wait + time.Duration(time.Now().UnixNano()%int64(wait/2+1)))
		if wait < 2*time.Second {
			wait *= 2
		}
	}
	return nil, errors.New("resolve shard retry exhausted")
}

func feedCursorWithRetry(client *transport.Client, topic string, shard int, cursor int64, limit int, attempts int) (*transport.CursorFeedResponse, error) {
	if attempts < 1 {
		attempts = 1
	}
	wait := 200 * time.Millisecond
	for i := 0; i < attempts; i++ {
		resp, err := client.FeedCursor(topic, shard, cursor, limit)
		if err == nil {
			return resp, nil
		}
		if !isRateLimitError(err) || i == attempts-1 {
			return nil, err
		}
		time.Sleep(wait + time.Duration(time.Now().UnixNano()%int64(wait/2+1)))
		if wait < 2*time.Second {
			wait *= 2
		}
	}
	return nil, errors.New("feed cursor retry exhausted")
}

func collectRecentSignalIDsForShard(client *transport.Client, topic string, shard int, limit int, cursorFile string) ([]string, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	if strings.TrimSpace(topic) == "" {
		return nil, errors.New("topic is required")
	}
	if shard < 0 {
		return nil, errors.New("invalid shard")
	}
	if limit <= 0 {
		limit = 20
	}
	perShard := limit
	if perShard < incrementalFeedMinLimit {
		perShard = incrementalFeedMinLimit
	}
	if perShard > 200 {
		perShard = 200
	}

	state := loadCursorState(cursorFile)
	if savedCursor, ok := state.get(topic, shard); ok {
		resp, err := feedCursorWithRetry(client, topic, shard, savedCursor, perShard, 5)
		if err == nil && resp != nil {
			// Cursor may be older than retention: jump to recent tail if the window is empty.
			if resp.Count == 0 && resp.MaxSeq > resp.NextCursor {
				tailCursor := resp.MaxSeq - int64(limit)
				if tailCursor < 0 {
					tailCursor = 0
				}
				tailResp, tailErr := feedCursorWithRetry(client, topic, shard, tailCursor, limit, 5)
				if tailErr == nil && tailResp != nil {
					state.set(topic, shard, tailResp.NextCursor)
					_ = saveCursorState(cursorFile, state)
					return collectIDsFromEntries(tailResp.Entries, limit), nil
				}
			}
			state.set(topic, shard, resp.NextCursor)
			_ = saveCursorState(cursorFile, state)
			return collectIDsFromEntries(resp.Entries, limit), nil
		}
	}

	meta, err := feedCursorWithRetry(client, topic, shard, 0, 1, 5)
	if err != nil {
		return nil, err
	}
	if meta == nil || meta.MaxSeq <= 0 {
		return nil, nil
	}
	tailCursor := meta.MaxSeq - int64(limit)
	if tailCursor < 0 {
		tailCursor = 0
	}
	resp, err := feedCursorWithRetry(client, topic, shard, tailCursor, limit, 5)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	state.set(topic, shard, resp.NextCursor)
	_ = saveCursorState(cursorFile, state)
	return collectIDsFromEntries(resp.Entries, limit), nil
}

func collectIDsFromEntries(entries []transport.FeedEntry, limit int) []string {
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Timestamp == entries[j].Timestamp {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Timestamp > entries[j].Timestamp
	})
	ids := make([]string, 0, limit)
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.ID == "" {
			continue
		}
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		ids = append(ids, e.ID)
		if len(ids) >= limit {
			break
		}
	}
	return ids
}

type cursorState struct {
	Version   int              `json:"version"`
	UpdatedAt string           `json:"updated_at"`
	Cursors   map[string]int64 `json:"cursors"`
}

func cursorStatePath(outDir string) string {
	return filepath.Join(outDir, cursorStateFileName)
}

func cursorKey(topic string, shard int) string {
	return fmt.Sprintf("%s#%d", topic, shard)
}

func loadCursorState(path string) *cursorState {
	out := &cursorState{
		Version: 1,
		Cursors: map[string]int64{},
	}
	if strings.TrimSpace(path) == "" {
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var parsed cursorState
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out
	}
	if parsed.Version == 0 {
		parsed.Version = 1
	}
	if parsed.Cursors == nil {
		parsed.Cursors = map[string]int64{}
	}
	return &parsed
}

func saveCursorState(path string, state *cursorState) error {
	if strings.TrimSpace(path) == "" || state == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *cursorState) get(topic string, shard int) (int64, bool) {
	if s == nil || s.Cursors == nil {
		return 0, false
	}
	v, ok := s.Cursors[cursorKey(topic, shard)]
	return v, ok
}

func (s *cursorState) set(topic string, shard int, cursor int64) {
	if s == nil || cursor < 0 {
		return
	}
	if s.Cursors == nil {
		s.Cursors = map[string]int64{}
	}
	key := cursorKey(topic, shard)
	prev, ok := s.Cursors[key]
	if !ok || cursor > prev {
		s.Cursors[key] = cursor
	}
}

type githubRelease struct {
	TagName    string             `json:"tag_name"`
	HTMLURL    string             `json:"html_url"`
	Draft      bool               `json:"draft"`
	Prerelease bool               `json:"prerelease"`
	Assets     []githubAssetEntry `json:"assets"`
}

type githubAssetEntry struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type updateCheckResult struct {
	CurrentVersion  string
	LatestVersion   string
	ReleaseURL      string
	AssetName       string
	UpdateAvailable bool
	Reason          string
}

type updateApplyResult struct {
	CurrentVersion string
	LatestVersion  string
	AssetName      string
	ReleaseURL     string
	Executable     string
	Applied        bool
	Reason         string
}

type updateCandidate struct {
	currentVersion   string
	latestVersion    string
	releaseURL       string
	asset            *githubAssetEntry
	checksumAsset    *githubAssetEntry
	checksumSigAsset *githubAssetEntry
	eligible         bool
	reason           string
}

type semVersion struct {
	Major int
	Minor int
	Patch int
}

type updateState struct {
	Version            int    `json:"version"`
	UpdatedAt          string `json:"updated_at"`
	LastCheckedAt      string `json:"last_checked_at,omitempty"`
	LastAppliedVersion string `json:"last_applied_version,omitempty"`
	LastOutcome        string `json:"last_outcome,omitempty"`
	LastNote           string `json:"last_note,omitempty"`
}

func maybeAutoUpdate(stateDir, repo, currentVersion, nodeID string, allowMajor bool, requireAttestation bool, attestPubKey string, rolloutPercent int, jitter time.Duration, tick bool) (bool, error) {
	if !isSemver(currentVersion) {
		return false, nil
	}
	statePath := filepath.Join(stateDir, updateStateFileName)
	st := loadUpdateState(statePath)
	st.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)

	if !withinRollout(nodeID, rolloutPercent) {
		st.LastOutcome = "skipped"
		st.LastNote = "outside rollout cohort"
		_ = saveUpdateState(statePath, st)
		return false, nil
	}

	if tick && jitter > 0 {
		delay := boundedJitter(jitter)
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	applied, err := withUpdateLock(stateDir, func() (bool, error) {
		res, applyErr := applyUpdate(repo, currentVersion, allowMajor, requireAttestation, attestPubKey, 25*time.Second)
		if applyErr != nil {
			return false, applyErr
		}
		if tick && res.Reason != "" {
			fmt.Println("auto_update_note:", res.Reason)
		}
		if res.Applied {
			st.LastAppliedVersion = res.LatestVersion
			st.LastOutcome = "applied"
			st.LastNote = ""
			return true, nil
		}
		st.LastOutcome = "no_change"
		st.LastNote = res.Reason
		return false, nil
	})
	if err != nil {
		st.LastOutcome = "error"
		st.LastNote = err.Error()
		_ = saveUpdateState(statePath, st)
		return false, err
	}
	_ = saveUpdateState(statePath, st)
	return applied, nil
}

func withinRollout(nodeID string, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(nodeID))
	if key == "" {
		if hn, err := os.Hostname(); err == nil {
			key = strings.ToLower(strings.TrimSpace(hn))
		}
	}
	if key == "" {
		return true
	}
	sum := sha256.Sum256([]byte(key))
	bucket := int(binary.BigEndian.Uint32(sum[:4])%100) + 1
	return bucket <= percent
}

func boundedJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	nMax := max.Nanoseconds()
	if nMax <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(nMax+1))
	if err != nil {
		return time.Duration(time.Now().UnixNano() % (nMax + 1))
	}
	return time.Duration(n.Int64())
}

func withUpdateLock(stateDir string, fn func() (bool, error)) (bool, error) {
	lockPath := filepath.Join(strings.TrimSpace(stateDir), updateLockFileName)
	if strings.TrimSpace(lockPath) == "" {
		lockPath = filepath.Join(".aiwre", updateLockFileName)
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return false, err
	}

	openLock := func() (*os.File, error) {
		return os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	}

	f, err := openLock()
	if err != nil && os.IsExist(err) {
		if st, statErr := os.Stat(lockPath); statErr == nil {
			// Best-effort stale lock cleanup (e.g., crashed process).
			if time.Since(st.ModTime()) > 6*time.Hour {
				_ = os.Remove(lockPath)
				f, err = openLock()
			}
		}
	}
	if err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	_, _ = fmt.Fprintf(f, "%d\n%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	_ = f.Close()
	defer os.Remove(lockPath)

	return fn()
}

func checkForUpdate(repo, currentVersion string, allowMajor bool, requireAttestation bool, attestPubKey string, timeout time.Duration) (*updateCheckResult, error) {
	candidate, err := resolveUpdateCandidate(repo, currentVersion, allowMajor, requireAttestation, attestPubKey, timeout)
	if err != nil {
		return nil, err
	}
	out := &updateCheckResult{
		CurrentVersion: candidate.currentVersion,
		LatestVersion:  candidate.latestVersion,
		ReleaseURL:     candidate.releaseURL,
		Reason:         candidate.reason,
	}
	if candidate.asset != nil {
		out.AssetName = candidate.asset.Name
	}
	out.UpdateAvailable = candidate.eligible && candidate.asset != nil
	if candidate.eligible && candidate.asset == nil {
		out.Reason = "update available but no matching release artifact for this platform"
	}
	return out, nil
}

func applyUpdate(repo, currentVersion string, allowMajor bool, requireAttestation bool, attestPubKey string, timeout time.Duration) (*updateApplyResult, error) {
	candidate, err := resolveUpdateCandidate(repo, currentVersion, allowMajor, requireAttestation, attestPubKey, timeout)
	if err != nil {
		return nil, err
	}
	out := &updateApplyResult{
		CurrentVersion: candidate.currentVersion,
		LatestVersion:  candidate.latestVersion,
		ReleaseURL:     candidate.releaseURL,
		Reason:         candidate.reason,
	}
	if candidate.asset != nil {
		out.AssetName = candidate.asset.Name
	}
	if !candidate.eligible {
		return out, nil
	}
	if candidate.asset == nil {
		return out, errors.New("update available but no matching release artifact for this platform")
	}
	if candidate.checksumAsset == nil {
		return out, errors.New("release is missing checksums asset; refusing unsafe self-update")
	}
	if requireAttestation && candidate.checksumSigAsset == nil {
		return out, errors.New("checksums attestation is required but signature asset is missing")
	}

	client := &http.Client{Timeout: timeout}
	checksumRaw, err := downloadHTTPBytes(client, candidate.checksumAsset.URL, 2<<20)
	if err != nil {
		return out, fmt.Errorf("download checksums: %w", err)
	}
	hashByName := parseChecksums(string(checksumRaw))
	expected := strings.ToLower(strings.TrimSpace(hashByName[candidate.asset.Name]))
	if expected == "" {
		return out, fmt.Errorf("checksums file does not include %s", candidate.asset.Name)
	}
	if candidate.checksumSigAsset != nil && strings.TrimSpace(attestPubKey) != "" {
		sigRaw, sigErr := downloadHTTPBytes(client, candidate.checksumSigAsset.URL, 1<<20)
		if sigErr != nil {
			return out, fmt.Errorf("download checksums signature: %w", sigErr)
		}
		if sigErr := verifyChecksumsAttestation(checksumRaw, sigRaw, attestPubKey); sigErr != nil {
			return out, fmt.Errorf("checksums attestation verify failed: %w", sigErr)
		}
	} else if requireAttestation {
		return out, errors.New("checksums attestation verification requires --attestation-pubkey")
	}

	archivePath, err := downloadToTempFile(client, candidate.asset.URL, "aiwre-update-*")
	if err != nil {
		return out, fmt.Errorf("download artifact: %w", err)
	}
	defer os.Remove(archivePath)

	actual, err := fileSHA256(archivePath)
	if err != nil {
		return out, err
	}
	if actual != expected {
		return out, fmt.Errorf("checksum mismatch for %s", candidate.asset.Name)
	}

	binaryPath, err := extractBinaryFromArtifact(archivePath, candidate.asset.Name)
	if err != nil {
		return out, err
	}
	if binaryPath != archivePath {
		defer os.Remove(binaryPath)
	}

	exe, err := installExecutable(binaryPath)
	if err != nil {
		return out, err
	}
	out.Executable = exe
	out.Applied = true
	out.Reason = ""
	return out, nil
}

func resolveUpdateCandidate(repo, currentVersion string, allowMajor bool, requireAttestation bool, attestPubKey string, timeout time.Duration) (*updateCandidate, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil, errors.New("repo is required")
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	current := strings.TrimSpace(currentVersion)
	if current == "" {
		current = "dev"
	}
	release, err := fetchLatestRelease(repo, timeout)
	if err != nil {
		return nil, err
	}
	latest := normalizeVersionLabel(release.TagName)
	candidate := &updateCandidate{
		currentVersion: current,
		latestVersion:  latest,
		releaseURL:     strings.TrimSpace(release.HTMLURL),
	}

	if !isSemver(current) {
		candidate.reason = "current build is non-semver; skip automatic update"
		return candidate, nil
	}
	if !isSemver(latest) {
		return nil, fmt.Errorf("latest release tag is not semver: %s", release.TagName)
	}
	curSem, _ := parseSemver(current)
	latestSem, _ := parseSemver(latest)
	cmp := compareSemver(latestSem, curSem)
	if cmp <= 0 {
		candidate.reason = "already up to date"
		return candidate, nil
	}
	if !allowMajor && latestSem.Major > curSem.Major {
		candidate.reason = "major update available but major auto-upgrades are disabled"
		return candidate, nil
	}
	asset := pickReleaseAsset(release.Assets, runtime.GOOS, runtime.GOARCH)
	checksumAsset := pickChecksumAsset(release.Assets)
	checksumSigAsset := pickChecksumSignatureAsset(release.Assets, checksumAsset)
	candidate.asset = asset
	candidate.checksumAsset = checksumAsset
	candidate.checksumSigAsset = checksumSigAsset
	if requireAttestation {
		if checksumSigAsset == nil {
			candidate.reason = "attestation required but signature asset is missing"
			candidate.eligible = false
			return candidate, nil
		}
		if strings.TrimSpace(attestPubKey) == "" {
			candidate.reason = "attestation required but public key is missing"
			candidate.eligible = false
			return candidate, nil
		}
	}
	candidate.eligible = true
	return candidate, nil
}

func fetchLatestRelease(repo string, timeout time.Duration) (*githubRelease, error) {
	client := &http.Client{Timeout: timeout}
	url := "https://api.github.com/repos/" + strings.TrimSpace(repo) + "/releases/latest"
	body, err := downloadHTTPBytes(client, url, 2<<20)
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, err
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, errors.New("release tag is missing")
	}
	return &rel, nil
}

func pickReleaseAsset(assets []githubAssetEntry, goos, goarch string) *githubAssetEntry {
	tokenA := "_" + strings.ToLower(strings.TrimSpace(goos)) + "_" + strings.ToLower(strings.TrimSpace(goarch))
	tokenB := "-" + strings.ToLower(strings.TrimSpace(goos)) + "-" + strings.ToLower(strings.TrimSpace(goarch))
	binaryName := "aiwre"
	if strings.EqualFold(goos, "windows") {
		binaryName = "aiwre.exe"
	}

	var best *githubAssetEntry
	bestScore := -1
	for i := range assets {
		name := strings.ToLower(strings.TrimSpace(assets[i].Name))
		if name == "" {
			continue
		}
		if strings.Contains(name, "checksums") || strings.Contains(name, ".sig") || strings.Contains(name, "sbom") {
			continue
		}
		if !strings.Contains(name, tokenA) && !strings.Contains(name, tokenB) {
			continue
		}
		score := 1
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
			score = 3
		} else if strings.HasSuffix(name, ".zip") {
			score = 2
		} else if filepath.Base(name) == binaryName {
			score = 4
		}
		if score > bestScore {
			best = &assets[i]
			bestScore = score
		}
	}
	return best
}

func pickChecksumAsset(assets []githubAssetEntry) *githubAssetEntry {
	for i := range assets {
		name := strings.ToLower(strings.TrimSpace(assets[i].Name))
		if name == "" {
			continue
		}
		if strings.Contains(name, "checksums") && strings.HasSuffix(name, ".txt") {
			return &assets[i]
		}
	}
	return nil
}

func pickChecksumSignatureAsset(assets []githubAssetEntry, checksumAsset *githubAssetEntry) *githubAssetEntry {
	if checksumAsset == nil {
		return nil
	}
	base := strings.ToLower(strings.TrimSpace(checksumAsset.Name))
	for i := range assets {
		name := strings.ToLower(strings.TrimSpace(assets[i].Name))
		if name == "" {
			continue
		}
		if name == base+".sig" || name == base+".minisig" {
			return &assets[i]
		}
	}
	return nil
}

func parseChecksums(raw string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(fields[0]))
		if len(hash) != 64 {
			continue
		}
		name := strings.TrimSpace(fields[len(fields)-1])
		name = strings.TrimPrefix(name, "*")
		name = filepath.Base(name)
		if name == "" {
			continue
		}
		out[name] = hash
	}
	return out
}

func verifyChecksumsAttestation(checksumRaw, sigRaw []byte, pubKeyRaw string) error {
	pubKey, err := parseEd25519PublicKey(pubKeyRaw)
	if err != nil {
		return err
	}
	sig, err := parseEd25519Signature(sigRaw)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, checksumRaw, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func parseEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, errors.New("attestation public key is empty")
	}
	if strings.HasPrefix(v, "ed25519:") {
		v = strings.TrimPrefix(v, "ed25519:")
	}
	if b, err := hex.DecodeString(v); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(v); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, errors.New("invalid attestation public key format")
}

func parseEd25519Signature(sigRaw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(sigRaw))
	if trimmed == "" {
		return nil, errors.New("empty attestation signature")
	}
	fields := strings.Fields(trimmed)
	candidates := []string{trimmed}
	if len(fields) >= 2 {
		candidates = append(candidates, fields[len(fields)-1])
	}
	for _, c := range candidates {
		if b, err := hex.DecodeString(strings.TrimSpace(c)); err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
		if b, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(c)); err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c)); err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
	}
	return nil, errors.New("invalid attestation signature format")
}

func downloadHTTPBytes(client *http.Client, uri string, maxBytes int64) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aiwre-cli/"+strings.TrimSpace(buildVersion))
	req.Header.Set("Accept", "application/json,application/octet-stream;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("response exceeds size limit")
	}
	return data, nil
}

func downloadToTempFile(client *http.Client, uri, pattern string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "aiwre-cli/"+strings.TrimSpace(buildVersion))
	req.Header.Set("Accept", "application/octet-stream,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 300<<20)); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractBinaryFromArtifact(archivePath, assetName string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(assetName))
	if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
		return extractTarGzBinary(archivePath)
	}
	if strings.HasSuffix(name, ".zip") {
		return extractZipBinary(archivePath)
	}
	return archivePath, nil
}

func extractTarGzBinary(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := "aiwre"
	if runtime.GOOS == "windows" {
		want = "aiwre.exe"
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr == nil || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(strings.TrimSpace(hdr.Name)) != want {
			continue
		}
		tmp, err := os.CreateTemp("", "aiwre-bin-*")
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(tmp, tr); err != nil {
			tmp.Close()
			_ = os.Remove(tmp.Name())
			return "", err
		}
		_ = tmp.Chmod(0755)
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmp.Name())
			return "", err
		}
		return tmp.Name(), nil
	}
	return "", errors.New("aiwre binary not found in tar.gz artifact")
}

func extractZipBinary(archivePath string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()
	want := "aiwre"
	if runtime.GOOS == "windows" {
		want = "aiwre.exe"
	}
	for _, f := range r.File {
		if path.Base(strings.TrimSpace(f.Name)) != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		tmp, err := os.CreateTemp("", "aiwre-bin-*")
		if err != nil {
			rc.Close()
			return "", err
		}
		if _, err := io.Copy(tmp, rc); err != nil {
			rc.Close()
			tmp.Close()
			_ = os.Remove(tmp.Name())
			return "", err
		}
		rc.Close()
		_ = tmp.Chmod(0755)
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmp.Name())
			return "", err
		}
		return tmp.Name(), nil
	}
	return "", errors.New("aiwre binary not found in zip artifact")
}

func installExecutable(newBinaryPath string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe = strings.TrimSpace(exe)
	if exe == "" {
		return "", errors.New("executable path is empty")
	}
	targetMode := os.FileMode(0755)
	if st, statErr := os.Stat(exe); statErr == nil {
		targetMode = st.Mode().Perm()
		if targetMode == 0 {
			targetMode = 0755
		}
	}
	raw, err := os.ReadFile(newBinaryPath)
	if err != nil {
		return "", err
	}
	tmpPath := exe + ".new"
	backupPath := exe + ".bak"
	if err := os.WriteFile(tmpPath, raw, targetMode); err != nil {
		return "", err
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(exe, backupPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, exe); err != nil {
		_ = os.Rename(backupPath, exe)
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := verifyExecutableHealth(exe); err != nil {
		_ = os.Rename(exe, tmpPath)
		_ = os.Rename(backupPath, exe)
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("post-update health check failed: %w", err)
	}
	return exe, nil
}

func verifyExecutableHealth(exe string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg != "" {
			return fmt.Errorf("%w (%s)", err, msg)
		}
		return err
	}
	if !strings.Contains(strings.ToLower(out.String()), "version:") {
		return errors.New("unexpected version output")
	}
	return nil
}

func restartSelf(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Println("restarted_pid:", cmd.Process.Pid)
	os.Exit(0)
	return nil
}

func parseSemver(v string) (semVersion, bool) {
	s := normalizeVersionLabel(v)
	base := s
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		base = base[:i]
	}
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return semVersion{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semVersion{}, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semVersion{}, false
	}
	return semVersion{Major: major, Minor: minor, Patch: patch}, true
}

func normalizeVersionLabel(v string) string {
	out := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v"))
	return out
}

func isSemver(v string) bool {
	_, ok := parseSemver(v)
	return ok
}

func compareSemver(a, b semVersion) int {
	if a.Major != b.Major {
		if a.Major > b.Major {
			return 1
		}
		return -1
	}
	if a.Minor != b.Minor {
		if a.Minor > b.Minor {
			return 1
		}
		return -1
	}
	if a.Patch != b.Patch {
		if a.Patch > b.Patch {
			return 1
		}
		return -1
	}
	return 0
}

func loadUpdateState(path string) *updateState {
	out := &updateState{Version: 1}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var parsed updateState
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out
	}
	if parsed.Version == 0 {
		parsed.Version = 1
	}
	return &parsed
}

func saveUpdateState(path string, state *updateState) error {
	if strings.TrimSpace(path) == "" || state == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func safeTimestamp(raw string) string {
	if raw == "" {
		return "unknown"
	}
	s := strings.ReplaceAll(raw, ":", "")
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "+", "")
	return s
}

func dmUsageText() string {
	return "usage:\n  aiwre dm send --relay <url> [--bootstrap <url>] --to <sender_fp> --secret <shared_secret> (--body <text> | --in <file>) [--state-dir ./.aiwre]\n  aiwre dm pull --relay <url> [--bootstrap <url>] --with <sender_fp> --secret <shared_secret> [--limit 20] [--out-dir ./dm-inbox] [--state-dir ./.aiwre]"
}

func dmUsageError() error {
	return errors.New("dm subcommand required: send|pull\n" + dmUsageText())
}

func roomUsageText() string {
	return "usage:\n  aiwre room send --relay <url> [--bootstrap <url>] --room <room_name> --secret <shared_secret> (--body <text> | --in <file>) [--state-dir ./.aiwre]\n  aiwre room pull --relay <url> [--bootstrap <url>] --room <room_name> --secret <shared_secret> [--limit 20] [--out-dir ./room-inbox] [--state-dir ./.aiwre]"
}

func roomUsageError() error {
	return errors.New("room subcommand required: send|pull\n" + roomUsageText())
}

func updateUsageText() string {
	return "usage:\n  aiwre update check [--repo horacex/aiwre] [--allow-major] [--require-attestation] [--attestation-pubkey <key>]\n  aiwre update apply [--repo horacex/aiwre] [--allow-major] [--require-attestation] [--attestation-pubkey <key>]"
}

func parseCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		v := strings.ToLower(strings.TrimSpace(p))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func idUsageText() string {
	return "usage:\n  aiwre id card publish --bootstrap <url> [--state-dir ./.aiwre] [--alias local|local@domain] [--name <display>] [--about <text>]\n  aiwre id resolve --bootstrap <url> --id <aiwre:sender|sender|alias@domain> [--topic agent.card] [--limit 200] [--format json|text]\n  aiwre id whois --bootstrap <url> --id <aiwre:sender|sender|alias@domain> [--topic agent.card] [--limit 200]"
}

func idUsageError() error {
	return errors.New("id subcommand required: card|resolve|whois\n" + idUsageText())
}

func idCardUsageText() string {
	return "usage:\n  aiwre id card publish --bootstrap <url> [--state-dir ./.aiwre] [--alias local|local@domain] [--name <display>] [--about <text>] [--capabilities c1,c2]"
}

func idCardUsageError() error {
	return errors.New("id card subcommand required: publish\n" + idCardUsageText())
}
