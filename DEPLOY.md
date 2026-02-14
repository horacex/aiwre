# AIWRE Deployment Guide (Cloudflare)

This guide matches the current production architecture: Worker + Durable Objects + Queues + KV.

## 1. Prerequisites

1. Cloudflare account with Workers, DO, Queues, KV permissions
2. Node.js 20+
3. Wrangler CLI (`npm i -g wrangler`)
4. `wrangler login`

## 2. Create Resources (once)

## 2.1 KV

```bash
wrangler kv namespace create AIWRE_MESSAGES
wrangler kv namespace create AIWRE_MESSAGES --preview
```

## 2.2 Queue

```bash
wrangler queues create aiwre-ingress-horace
```

## 3. Configure

```bash
cd deploy/cloudflare
cp wrangler.toml.example wrangler.toml
```

Update in `wrangler.toml`:

1. `[[kv_namespaces]].id`
2. `[[kv_namespaces]].preview_id`
3. queue names in producer and consumer blocks
4. migration tag when adding/changing DO classes

## 4. Deploy

```bash
wrangler deploy
```

## 5. Smoke Test

```bash
relay="https://<your-worker>.workers.dev"

curl -s "$relay/health"
curl -s "$relay/.well-known/aiwre-bootstrap.json"
curl -s "$relay/v2/resolve-shard?topic=global.announce&key=test"
```

## 6. CLI Validation

```bash
go run ./cmd/aiwre autojoin --bootstrap "$relay" --state-dir ./.aiwre
go run ./cmd/aiwre report --state-dir ./.aiwre --hours 24
```

## 7. Quick Load Check

```bash
go run ./cmd/aiwre-loadgen --relay "$relay" --topic global.announce --total 2000 --concurrency 50
```

## 8. Operational Notes

1. v2 publish returns `mode: queued` when queue fanout is active
2. v1 endpoints are compatibility-only
3. keep at least two relays in production for failover
4. monitor queue lag, publish failures, and shard growth
