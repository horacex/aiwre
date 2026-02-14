package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientV1Endpoints(t *testing.T) {
	t.Parallel()

	signalBody := "---\naiwre_v: 1.0\n---\nhello"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/publish-batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
			t.Fatalf("content-type=%s", got)
		}
		_ = json.NewEncoder(w).Encode(BatchPublishResponse{
			Accepted: 1,
			Entries: []struct {
				ID    string `json:"id"`
				Topic string `json:"topic"`
				Shard int    `json:"shard"`
			}{
				{ID: "abc123", Topic: "global.announce", Shard: 0},
			},
		})
	})
	mux.HandleFunc("/v1/feed", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("topic") != "global.announce" {
			t.Fatalf("unexpected topic query")
		}
		if r.URL.Query().Get("shard") != "0" {
			t.Fatalf("unexpected shard query")
		}
		_ = json.NewEncoder(w).Encode(CursorFeedResponse{
			Topic:      "global.announce",
			Shard:      0,
			Cursor:     0,
			NextCursor: 1,
			MaxSeq:     1,
			Count:      1,
			Entries: []FeedEntry{
				{ID: "abc123", Topic: "global.announce", Timestamp: "2026-02-14T00:00:00Z", Seq: 1},
			},
		})
	})
	mux.HandleFunc("/v1/resolve-shard", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ShardResolveResponse{
			Topic:      "global.announce",
			Key:        "abc123",
			Shard:      0,
			ShardCount: 32,
		})
	})
	mux.HandleFunc("/v1/signals/abc123", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signalBody))
	})
	mux.HandleFunc("/.well-known/aiwre-bootstrap.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(BootstrapProfile{
			AiwreV:         "1.0",
			Relay:          "https://relay.example",
			Join:           "permissionless",
			Capabilities:   []string{"v1.batch", "v1.feed"},
			ShardCount:     32,
			DefaultTopics:  []string{"global.announce"},
			HeartbeatTopic: "agent.heartbeat",
			ReportTopic:    "human.report",
			HumanReport:    true,
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := NewClient(ts.URL)
	pub, err := c.Publish(signalBody)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Accepted || pub.ID != "abc123" {
		t.Fatalf("unexpected publish response: %+v", pub)
	}
	fast, err := c.PublishFast(signalBody)
	if err != nil {
		t.Fatal(err)
	}
	if fast.ID != "abc123" {
		t.Fatalf("unexpected publish fast response: %+v", fast)
	}
	cursorFeed, err := c.FeedCursor("global.announce", 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if cursorFeed.Count != 1 || cursorFeed.NextCursor != 1 {
		t.Fatalf("unexpected cursor feed response: %+v", cursorFeed)
	}
	shard, err := c.ResolveShard("global.announce", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if shard.ShardCount != 32 {
		t.Fatalf("unexpected shard response: %+v", shard)
	}
	got, err := c.GetSignal("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got != signalBody {
		t.Fatalf("unexpected signal body: %q", got)
	}
	boot, err := c.FetchBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if boot.Join != "permissionless" || boot.HeartbeatTopic != "agent.heartbeat" || boot.ShardCount != 32 {
		t.Fatalf("unexpected bootstrap response: %+v", boot)
	}
}

func TestPublishErrorIncludesBody(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad input", http.StatusBadRequest)
	}))
	defer ts.Close()

	_, err := NewClient(ts.URL).Publish("x")
	if err == nil || !strings.Contains(err.Error(), "bad input") {
		t.Fatalf("expected detailed error, got %v", err)
	}
}

func TestStreamURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		base  string
		topic string
		want  string
	}{
		{
			base:  "https://relay.aiwre.io",
			topic: "global.announce",
			want:  "wss://relay.aiwre.io/v1/stream?topic=global.announce",
		},
		{
			base:  "http://localhost:8787",
			topic: "agent.heartbeat",
			want:  "ws://localhost:8787/v1/stream?topic=agent.heartbeat",
		},
	}

	for _, tt := range tests {
		got, err := NewClient(tt.base).StreamURL(tt.topic)
		if err != nil {
			t.Fatalf("base=%s err=%v", tt.base, err)
		}
		if got != tt.want {
			t.Fatalf("base=%s got=%s want=%s", tt.base, got, tt.want)
		}
	}
}
