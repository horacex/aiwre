package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

type FeedEntry struct {
	ID        string `json:"id"`
	Topic     string `json:"topic"`
	Timestamp string `json:"timestamp"`
	Sender    string `json:"sender"`
	Type      string `json:"type"`
	Seq       int64  `json:"seq,omitempty"`
}

type PublishResponse struct {
	Accepted bool   `json:"accepted"`
	ID       string `json:"id"`
	StoredAt string `json:"stored_at"`
}

type BatchPublishResponse struct {
	Accepted   int `json:"accepted"`
	Rejected   int `json:"rejected"`
	Routed     int `json:"routed"`
	ShardCount int `json:"shard_count"`
	Entries    []struct {
		ID    string `json:"id"`
		Topic string `json:"topic"`
		Shard int    `json:"shard"`
	} `json:"entries"`
	Errors []struct {
		Reason string `json:"reason"`
	} `json:"errors"`
}

type CursorFeedResponse struct {
	Topic      string      `json:"topic"`
	Shard      int         `json:"shard"`
	Cursor     int64       `json:"cursor"`
	NextCursor int64       `json:"next_cursor"`
	MaxSeq     int64       `json:"max_seq"`
	Count      int         `json:"count"`
	Entries    []FeedEntry `json:"entries"`
}

type ShardResolveResponse struct {
	Topic      string `json:"topic"`
	Key        string `json:"key"`
	Shard      int    `json:"shard"`
	ShardCount int    `json:"shard_count"`
}

type BootstrapProfile struct {
	AiwreV         string   `json:"aiwre_v"`
	Relay          string   `json:"relay"`
	Join           string   `json:"join"`
	Capabilities   []string `json:"capabilities"`
	ShardCount     int      `json:"shard_count"`
	DefaultTopics  []string `json:"default_topics"`
	HeartbeatTopic string   `json:"heartbeat_topic"`
	ReportTopic    string   `json:"report_topic"`
	HumanReport    bool     `json:"human_report"`
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *Client) Publish(signal string) (*PublishResponse, error) {
	batch, err := c.PublishBatch([]string{signal})
	if err != nil {
		return nil, err
	}
	if batch.Accepted > 0 && len(batch.Entries) > 0 {
		return &PublishResponse{Accepted: true, ID: batch.Entries[0].ID, StoredAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}
	if len(batch.Errors) > 0 && batch.Errors[0].Reason != "" {
		return nil, fmt.Errorf("publish failed: %s", batch.Errors[0].Reason)
	}
	return nil, fmt.Errorf("publish failed")
}

func (c *Client) PublishBatch(signals []string) (*BatchPublishResponse, error) {
	raw, err := json.Marshal(map[string]any{"signals": signals})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/v1/publish-batch", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("publish batch failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out BatchPublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PublishFast(signal string) (*PublishResponse, error) {
	return c.Publish(signal)
}

func (c *Client) FeedCursor(topic string, shard int, cursor int64, limit int) (*CursorFeedResponse, error) {
	q := url.Values{}
	q.Set("topic", topic)
	q.Set("shard", strconv.Itoa(shard))
	q.Set("cursor", strconv.FormatInt(cursor, 10))
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	u := c.BaseURL + "/v1/feed?" + q.Encode()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("feed cursor failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out CursorFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResolveShard(topic, key string) (*ShardResolveResponse, error) {
	q := url.Values{}
	q.Set("topic", topic)
	q.Set("key", key)
	u := c.BaseURL + "/v1/resolve-shard?" + q.Encode()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("resolve shard failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out ShardResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetSignal(id string) (string, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, "/v1/signals/", id)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return "", fmt.Errorf("get signal failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	buf := bytes.Buffer{}
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (c *Client) FetchBootstrap() (*BootstrapProfile, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/.well-known/aiwre-bootstrap.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("bootstrap fetch failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out BootstrapProfile
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
