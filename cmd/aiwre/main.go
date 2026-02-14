package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"aiwre/internal/protocol"
	"aiwre/internal/security"
	"aiwre/internal/transport"
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
  autojoin Zero-approval bootstrap and first sync
  report   Human-readable activity report
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
	res, err := pullTopicAdaptive(client, *topic, *limit, *outDir, !*skipVerify, true)
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

func runAutojoin(args []string) error {
	fs := flag.NewFlagSet("autojoin", flag.ContinueOnError)
	bootstrap := fs.String("bootstrap", "", "Bootstrap URL or relay base URL")
	stateDir := fs.String("state-dir", ".aiwre", "Local state directory for identity/inbox/log")
	limit := fs.Int("limit", 20, "Per-topic pull size on first sync")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bootstrap == "" {
		return errors.New("--bootstrap is required")
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
	for _, topic := range topics {
		res, err := pullTopicAdaptive(client, topic, *limit, inboxDir, false, false)
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
			Detail: fmt.Sprintf("feed_count=%d mode=%s", res.Count, res.Mode),
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
			"mode":        "autojoin",
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

func pullTopic(client *transport.Client, topic string, limit int, outDir string, verifyAdmission bool, warn bool) (*transport.FeedResponse, int, error) {
	feed, err := client.Feed(topic, limit)
	if err != nil {
		return nil, 0, err
	}
	ids := make([]string, 0, len(feed.Entries))
	for _, e := range feed.Entries {
		ids = append(ids, e.ID)
	}
	sort.Strings(ids)
	downloaded := downloadAndStoreSignals(client, ids, outDir, verifyAdmission, warn)
	return feed, downloaded, nil
}

func pullTopicAdaptive(client *transport.Client, topic string, limit int, outDir string, verifyAdmission bool, warn bool) (*pullResult, error) {
	if topic != "" {
		boot, err := client.FetchBootstrap()
		if err == nil && boot != nil && boot.ShardCount > 0 {
			res, v2err := pullTopicV2(client, topic, limit, outDir, verifyAdmission, warn, boot.ShardCount)
			if v2err == nil {
				return res, nil
			}
			if warn {
				fmt.Fprintln(os.Stderr, "warn: v2 pull failed, fallback to v1:", v2err)
			}
		}
	}

	feed, downloaded, err := pullTopic(client, topic, limit, outDir, verifyAdmission, warn)
	if err != nil {
		return nil, err
	}
	return &pullResult{
		Mode:       "v1",
		Topic:      feed.Topic,
		Count:      feed.Count,
		Downloaded: downloaded,
	}, nil
}

func pullTopicV2(client *transport.Client, topic string, limit int, outDir string, verifyAdmission bool, warn bool, shardCount int) (*pullResult, error) {
	if limit <= 0 {
		limit = 20
	}
	perShard := (limit + shardCount - 1) / shardCount
	if perShard < 1 {
		perShard = 1
	}

	type shardResult struct {
		resp *transport.CursorFeedResponse
		err  error
	}
	results := make(chan shardResult, shardCount)
	var wg sync.WaitGroup
	for shard := 0; shard < shardCount; shard++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			resp, err := client.FeedCursor(topic, s, 0, perShard)
			results <- shardResult{resp: resp, err: err}
		}(shard)
	}
	wg.Wait()
	close(results)

	entries := make([]transport.FeedEntry, 0, limit*2)
	for item := range results {
		if item.err != nil || item.resp == nil {
			continue
		}
		entries = append(entries, item.resp.Entries...)
	}
	if len(entries) == 0 {
		return &pullResult{
			Mode:       "v2",
			Topic:      topic,
			Count:      0,
			Downloaded: 0,
		}, nil
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
	downloaded := downloadAndStoreSignals(client, ids, outDir, verifyAdmission, warn)
	return &pullResult{
		Mode:       "v2",
		Topic:      topic,
		Count:      len(ids),
		Downloaded: downloaded,
	}, nil
}

func downloadAndStoreSignals(client *transport.Client, ids []string, outDir string, verifyAdmission bool, warn bool) int {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return 0
	}
	downloaded := 0
	for _, id := range ids {
		signal, err := client.GetSignal(id)
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
			policy := security.NewAdmissionPolicy()
			if err := policy.Verify(msg); err != nil {
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
		outPath := filepath.Join(outDir, id+".signal.md")
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
