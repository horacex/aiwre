package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"aiwre/internal/protocol"
	"aiwre/internal/security"
	"aiwre/internal/transport"
	"nhooyr.io/websocket"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "publish":
		err = runPublish(os.Args[2:])
	case "pull":
		err = runPull(os.Args[2:])
	case "autojoin":
		err = runAutojoin(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "stream":
		err = runStream(os.Args[2:])
	case "dm":
		err = runDM(os.Args[2:])
	case "room":
		err = runRoom(os.Args[2:])
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
	fmt.Print(`aiwre - AIWRE v0.1 reference CLI

Commands:
  keygen   Generate Ed25519 keypair
  sign     Sign a Signal-MD message
  verify   Verify signature and admission policy
  publish  Publish a signed Signal-MD to relay
  pull     Pull recent signals from relay
  autojoin Zero-approval bootstrap + stream-first daemon
  report   Human-readable activity report
  stream   WebSocket push stream for one topic
  dm       Direct-message helper (send|pull)
  room     Group-room helper (send|pull)
`)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "Directory for generated key files")
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
	privPath := fs.String("priv", "", "Base64 private key file")
	topic := fs.String("topic", "", "Topic if missing (namespace.topic)")
	typeFlag := fs.String("type", string(protocol.TypeBroadcast), "Type if missing")
	ttl := fs.Int("ttl", protocol.DefaultTTL, "TTL seconds if missing")
	ts := fs.String("timestamp", "", "Timestamp override (RFC3339)")
	meta := fs.String("metadata", "", "Metadata JSON to merge when input has none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *outPath == "" || *privPath == "" {
		return errors.New("--in, --out, and --priv are required")
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
	relay := fs.String("relay", "", "Relay base URL (e.g. https://aiwre.example.workers.dev)")
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
	client := transport.NewClient(*relay)
	resp, err := client.PublishFast(string(raw))
	if err != nil {
		return err
	}
	fmt.Println("published:", resp.Accepted)
	fmt.Println("id:", resp.ID)
	fmt.Println("stored_at:", resp.StoredAt)
	return nil
}

func runPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL (e.g. https://aiwre.example.workers.dev)")
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
	client := transport.NewClient(*relay)
	profile, err := client.FetchBootstrap()
	if err != nil {
		return err
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
	res, err := pullTopicSharded(
		client,
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
	switch args[0] {
	case "send":
		return runRoomSend(args[1:])
	case "pull":
		return runRoomPull(args[1:])
	default:
		return fmt.Errorf("unknown room subcommand %q\n%s", args[0], roomUsageText())
	}
}

func runDMSend(args []string) error {
	fs := flag.NewFlagSet("dm send", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL")
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
	if *relay == "" || *to == "" || *secret == "" {
		return errors.New("--relay, --to, and --secret are required")
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
	client := transport.NewClient(*relay)
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
	if *relay == "" || *withID == "" || *secret == "" {
		return errors.New("--relay, --with, and --secret are required")
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
	client := transport.NewClient(*relay)
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
	if *relay == "" || *room == "" || *secret == "" {
		return errors.New("--relay, --room, and --secret are required")
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
	client := transport.NewClient(*relay)
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
	room := fs.String("room", "", "Room name (topic segment)")
	secret := fs.String("secret", "", "Shared room secret for decryption")
	limit := fs.Int("limit", 20, "Number of recent messages")
	outDir := fs.String("out-dir", "./room-inbox", "Directory for decrypted messages")
	skipVerify := fs.Bool("skip-verify", false, "Skip admission verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *relay == "" || *room == "" || *secret == "" {
		return errors.New("--relay, --room, and --secret are required")
	}
	roomID, err := normalizeTopicSegment(*room)
	if err != nil {
		return fmt.Errorf("--room: %w", err)
	}
	topic := "room." + roomID
	client := transport.NewClient(*relay)
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
	cursorStateFileName     = ".cursor-state.json"
	incrementalFeedMinLimit = 50
)

func runAutojoin(args []string) error {
	fs := flag.NewFlagSet("autojoin", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or relay base URL")
	stateDir := fs.String("state-dir", ".aiwre", "Local state directory for identity/inbox/log")
	limit := fs.Int("limit", 20, "Per-topic pull size on first sync")
	pullInterval := fs.Duration("pull-interval", 30*time.Minute, "Low-frequency pull compensation interval (0 to disable)")
	once := fs.Bool("once", false, "Run initial sync + heartbeat and exit")
	noStream := fs.Bool("no-stream", false, "Disable stream workers (not recommended)")
	streamReconnectBase := fs.Duration("stream-reconnect-base", 2*time.Second, "Base reconnect backoff for stream workers")
	streamReconnectMax := fs.Duration("stream-reconnect-max", 2*time.Minute, "Max reconnect backoff for stream workers")
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

	topics := profile.DefaultTopics
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
		res, err := pullTopicSharded(
			client,
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
			Relay:  relay,
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
	pubResp, err := client.PublishFast(raw)
	if err != nil {
		return err
	}
	if err := appendActivity(*stateDir, activityEvent{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Action:    "publish",
		Relay:     relay,
		Topic:     heartbeatTopic,
		MessageID: pubResp.ID,
		Count:     1,
	}); err != nil {
		return err
	}

	fmt.Println("autojoin: true")
	fmt.Println("relay:", relay)
	fmt.Println("join_mode:", profile.Join)
	fmt.Println("identity:", protocol.Fingerprint(pub))
	fmt.Println("topics:", strings.Join(topics, ","))
	fmt.Println("downloaded:", totalDownloaded)
	fmt.Println("heartbeat_id:", pubResp.ID)
	fmt.Println("state_dir:", *stateDir)
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
				runAutojoinStreamWorker(ctx, client, t, inboxDir, base, max, func(received, saved, errs int) {
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

	if *pullInterval > 0 {
		ticker := time.NewTicker(*pullInterval)
		defer ticker.Stop()
		fmt.Println("runtime_mode:", "daemon")
		fmt.Println("pull_compensation_interval:", pullInterval.String())
		for {
			select {
			case <-ctx.Done():
				wg.Wait()
				goto END
			case <-ticker.C:
				cycleAdmission := security.NewAdmissionPolicy()
				for _, topic := range topics {
					res, err := pullTopicSharded(
						client,
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
						Relay:  relay,
						Topic:  topic,
						Count:  res.Downloaded,
						Detail: fmt.Sprintf("feed_count=%d mode=%s phase=compensate", res.Count, res.Mode),
					})
				}
			}
		}
	}

	fmt.Println("runtime_mode:", "daemon")
	fmt.Println("pull_compensation_interval:", "disabled")
	<-ctx.Done()
	wg.Wait()

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
		}
	}
	relayList := sortedKeys(relays)
	topicList := sortedKeys(topics)
	if *format == "json" {
		out := map[string]any{
			"window_start": start.Format(time.RFC3339),
			"window_hours": *hours,
			"events":       len(events),
			"published":    publishCount,
			"pulls":        pullCount,
			"downloaded":   downloaded,
			"relays":       relayList,
			"topics":       topicList,
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
	fmt.Println("relays:", strings.Join(relayList, ","))
	fmt.Println("topics:", strings.Join(topicList, ","))
	return nil
}

func runStream(args []string) error {
	fs := flag.NewFlagSet("stream", flag.ContinueOnError)
	relay := fs.String("relay", "", "Relay base URL (e.g. https://relay.aiwre.io)")
	topic := fs.String("topic", "", "Topic to stream (defaults to bootstrap first topic)")
	outDir := fs.String("out-dir", "./inbox", "Directory for streamed signals")
	skipVerify := fs.Bool("skip-verify", false, "Skip local admission verification on streamed messages")
	duration := fs.Duration("duration", 0, "Optional runtime limit (e.g. 10m). 0 means run until interrupted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*relay) == "" {
		return errors.New("--relay is required")
	}
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}

	client := transport.NewClient(*relay)
	profile, err := client.FetchBootstrap()
	if err != nil {
		return err
	}
	resolvedTopic := strings.TrimSpace(*topic)
	if resolvedTopic == "" {
		if len(profile.DefaultTopics) > 0 {
			resolvedTopic = profile.DefaultTopics[0]
		} else {
			resolvedTopic = "global.announce"
		}
	}
	streamURL, err := client.StreamURL(resolvedTopic)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	conn, _, err := websocket.Dial(ctx, streamURL, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close(websocket.StatusNormalClosure, "bye")
	}()

	var admission *security.AdmissionPolicy
	if !*skipVerify {
		admission = security.NewAdmissionPolicy()
	}

	received := 0
	downloaded := 0
	for {
		_, payload, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
		var ev streamEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			continue
		}
		if ev.Type == "welcome" {
			fmt.Println("stream_welcome:", ev.TS)
			continue
		}
		if ev.Type != "signal" || ev.Entry == nil || ev.Entry.ID == "" {
			continue
		}
		received++
		ok, err := storeStreamSignal(client, &ev, *outDir, !*skipVerify, admission)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warn: stream signal skipped:", ev.Entry.ID, err)
			continue
		}
		if ok {
			downloaded++
			fmt.Println("stream_saved:", ev.Entry.ID)
		}
	}

	fmt.Println("stream_topic:", resolvedTopic)
	fmt.Println("stream_received:", received)
	fmt.Println("stream_downloaded:", downloaded)
	fmt.Println("out_dir:", *outDir)
	return nil
}

func runAutojoinStreamWorker(
	ctx context.Context,
	client *transport.Client,
	topic string,
	outDir string,
	reconnectBase time.Duration,
	reconnectMax time.Duration,
	onUpdate func(received, saved, errs int),
) {
	if onUpdate == nil {
		onUpdate = func(int, int, int) {}
	}
	streamURL, err := client.StreamURL(topic)
	if err != nil {
		onUpdate(0, 0, 1)
		return
	}

	backoff := reconnectBase
	for {
		if ctx.Err() != nil {
			return
		}
		conn, _, err := websocket.Dial(ctx, streamURL, nil)
		if err != nil {
			onUpdate(0, 0, 1)
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
				onUpdate(1, 1, 0)
				continue
			}
			onUpdate(1, 0, 0)
		}
		if !sleepWithContext(ctx, jitterBackoff(backoff)) {
			return
		}
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
	ids, err := collectRecentSignalIDs(client, topic, limit, shardCount, cursorFile)
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

func collectRecentSignalIDs(client *transport.Client, topic string, limit int, shardCount int, cursorFile string) ([]string, error) {
	if limit <= 0 {
		limit = 20
	}
	if shardCount < 1 {
		shardCount = 1
	}
	perShard := (limit + shardCount - 1) / shardCount
	if perShard < 1 {
		perShard = 1
	}
	incrementalLimit := perShard
	if incrementalLimit < incrementalFeedMinLimit {
		// Same cost unit as <=50, but better catch-up after bursts.
		incrementalLimit = incrementalFeedMinLimit
	}
	state := loadCursorState(cursorFile)

	type shardResult struct {
		shard int
		resp  *transport.CursorFeedResponse
		err   error
	}
	results := make(chan shardResult, shardCount)
	var wg sync.WaitGroup
	for shard := 0; shard < shardCount; shard++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			if savedCursor, ok := state.get(topic, s); ok {
				resp, err := client.FeedCursor(topic, s, savedCursor, incrementalLimit)
				if err == nil {
					// Cursor may be older than retention: jump to recent tail if the window is empty.
					if resp != nil && resp.Count == 0 && resp.MaxSeq > resp.NextCursor {
						tailCursor := resp.MaxSeq - int64(perShard)
						if tailCursor < 0 {
							tailCursor = 0
						}
						tailResp, tailErr := client.FeedCursor(topic, s, tailCursor, perShard)
						if tailErr == nil {
							results <- shardResult{shard: s, resp: tailResp, err: nil}
							return
						}
					}
					results <- shardResult{shard: s, resp: resp, err: nil}
					return
				}
			}

			meta, err := client.FeedCursor(topic, s, 0, 1)
			if err != nil {
				results <- shardResult{shard: s, resp: nil, err: err}
				return
			}
			tailCursor := meta.MaxSeq - int64(perShard)
			if tailCursor < 0 {
				tailCursor = 0
			}
			resp, err := client.FeedCursor(topic, s, tailCursor, perShard)
			results <- shardResult{shard: s, resp: resp, err: err}
		}(shard)
	}
	wg.Wait()
	close(results)

	entries := make([]transport.FeedEntry, 0, limit*2)
	okShards := 0
	for item := range results {
		if item.err != nil || item.resp == nil {
			continue
		}
		okShards++
		state.set(topic, item.shard, item.resp.NextCursor)
		entries = append(entries, item.resp.Entries...)
	}
	if okShards == 0 {
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
	relay := strings.TrimRight(raw, "/")
	client := transport.NewClient(relay)
	profile, err := client.FetchBootstrap()
	if err == nil && profile != nil {
		if profile.Relay != "" {
			relay = strings.TrimRight(profile.Relay, "/")
		}
		if profile.Join == "" {
			profile.Join = "permissionless"
		}
		return relay, profile, nil
	}
	// Fallback: treat input as direct relay endpoint.
	return relay, &transport.BootstrapProfile{
		AiwreV:         protocol.Version,
		Relay:          relay,
		Join:           "permissionless",
		Capabilities:   []string{"v1"},
		ShardCount:     0,
		DefaultTopics:  []string{"global.announce"},
		HeartbeatTopic: "agent.heartbeat",
		ReportTopic:    "human.report",
		HumanReport:    true,
	}, nil
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

func loadPrivateForChat(privPath, stateDir string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(privPath) != "" {
		return loadPrivateKey(privPath)
	}
	base := strings.TrimSpace(stateDir)
	if base == "" {
		base = ".aiwre"
	}
	return loadPrivateKey(filepath.Join(base, "ed25519_private.key"))
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
	profile, err := client.FetchBootstrap()
	if err != nil {
		return 0, err
	}
	shardCount := profile.ShardCount
	if shardCount < 1 {
		shardCount = 1
	}
	ids, err := collectRecentSignalIDs(client, topic, limit, shardCount, cursorStatePath(outDir))
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
	return "usage:\n  aiwre dm send --relay <url> --to <sender_fp> --secret <shared_secret> (--body <text> | --in <file>) [--state-dir ./.aiwre]\n  aiwre dm pull --relay <url> --with <sender_fp> --secret <shared_secret> [--limit 20] [--out-dir ./dm-inbox] [--state-dir ./.aiwre]"
}

func dmUsageError() error {
	return errors.New("dm subcommand required: send|pull\n" + dmUsageText())
}

func roomUsageText() string {
	return "usage:\n  aiwre room send --relay <url> --room <room_name> --secret <shared_secret> (--body <text> | --in <file>) [--state-dir ./.aiwre]\n  aiwre room pull --relay <url> --room <room_name> --secret <shared_secret> [--limit 20] [--out-dir ./room-inbox]"
}

func roomUsageError() error {
	return errors.New("room subcommand required: send|pull\n" + roomUsageText())
}
