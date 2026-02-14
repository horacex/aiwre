package main

import (
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"aiwre/internal/protocol"
	"aiwre/internal/transport"
)

func main() {
	relay := flag.String("relay", "", "Relay base URL")
	topic := flag.String("topic", "global.announce", "Topic")
	total := flag.Int("total", 1000, "Total messages")
	concurrency := flag.Int("concurrency", 20, "Concurrent workers")
	ttl := flag.Int("ttl", 300, "Message TTL seconds")
	flag.Parse()

	if *relay == "" {
		panic("--relay is required")
	}
	if *total <= 0 || *concurrency <= 0 {
		panic("--total and --concurrency must be > 0")
	}

	_, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	client := transport.NewClient(*relay)

	start := time.Now()
	var cursor int64
	var success int64
	var failed int64

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				idx := int(atomic.AddInt64(&cursor, 1))
				if idx > *total {
					return
				}
				msg := &protocol.Message{
					Topic: *topic,
					Type:  protocol.TypeBroadcast,
					TTL:   *ttl,
					Metadata: map[string]any{
						"loadgen": true,
						"worker":  workerID,
						"seq":     idx,
					},
					Body: fmt.Sprintf("loadgen message %d\n", idx),
				}
				if err := protocol.SignMessage(msg, priv); err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				raw, err := protocol.RenderSignalMD(msg)
				if err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				if _, err := client.PublishFast(raw); err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				atomic.AddInt64(&success, 1)
			}
		}(i)
	}
	wg.Wait()

	d := time.Since(start)
	totalDone := atomic.LoadInt64(&success) + atomic.LoadInt64(&failed)
	qps := float64(totalDone) / d.Seconds()

	fmt.Println("relay:", *relay)
	fmt.Println("topic:", *topic)
	fmt.Println("duration:", d.Round(time.Millisecond))
	fmt.Println("success:", atomic.LoadInt64(&success))
	fmt.Println("failed:", atomic.LoadInt64(&failed))
	fmt.Printf("throughput_msg_per_sec: %.2f\n", qps)
}
