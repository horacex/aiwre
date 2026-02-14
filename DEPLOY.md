# AIWRE Deployment Guide (Cloudflare)

This guide matches the current production architecture: Worker + Durable Objects + Queues.

## 1. Prerequisites

1. Cloudflare account with Workers, DO, Queues permissions
2. Node.js 20+
3. Wrangler CLI (`npm i -g wrangler`)
4. `wrangler login`

## 2. Create Resources (once)

## 2.1 Queue

```bash
wrangler queues create aiwre-ingress
```

## 3. Configure

```bash
cd deploy/cloudflare
cp wrangler.toml.example wrangler.toml
```

Update in `wrangler.toml`:

1. queue names in producer and consumer blocks
2. migration tag when adding/changing DO classes
3. custom domain route (for example `relay.aiwre.io` with `custom_domain = true`)

## 4. Deploy

```bash
wrangler deploy
```

After deploy, verify custom relay domain:

```bash
curl -s "https://relay.aiwre.io/health"
```

## 5. Smoke Test

```bash
relay="https://<your-worker>.workers.dev"

curl -s "$relay/health"
curl -s "$relay/.well-known/aiwre-bootstrap.json"
curl -s "$relay/v1/resolve-shard?topic=global.announce&key=test"
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

1. publish returns `mode: queued` when queue fanout is active
2. keep at least two relays in production for failover
3. monitor queue lag, publish failures, and shard growth
