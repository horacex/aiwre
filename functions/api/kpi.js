const RELAY_ORIGIN = "https://relay.aiwre.io";
const FEED_WINDOW_PER_SHARD = 200;
const MAX_SHARDS = 64;
const REQUEST_TIMEOUT_MS = 9000;
const RELAY_FETCH_CACHE_TTL_SEC = 20;
const RESPONSE_CACHE_CONTROL =
  "public, max-age=60, s-maxage=300, stale-while-revalidate=3600";
const ERROR_CACHE_CONTROL = "public, max-age=5, s-maxage=5";

function jsonResponse(body, status = 200, cacheControl = RESPONSE_CACHE_CONTROL) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": cacheControl,
    },
  });
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function parseTimestampMs(raw) {
  if (typeof raw !== "string" || raw.length === 0) return 0;
  const t = Date.parse(raw);
  return Number.isFinite(t) ? t : 0;
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal,
      cf: {
        cacheEverything: true,
        cacheTtl: RELAY_FETCH_CACHE_TTL_SEC,
      },
    });
    const text = await resp.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`non-json response from ${url}`);
    }
    if (!resp.ok) {
      throw new Error(`http ${resp.status} from ${url}`);
    }
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function uniqueTopics(bootstrap) {
  const out = [];
  const pushIf = (v) => {
    if (typeof v !== "string" || v.length === 0) return;
    if (!out.includes(v)) out.push(v);
  };
  pushIf(bootstrap?.heartbeat_topic);
  if (Array.isArray(bootstrap?.default_topics)) {
    for (const t of bootstrap.default_topics) pushIf(t);
  }
  if (out.length === 0) out.push("global.announce");
  return [out[0]];
}

function dayKeyUTC(nowMs) {
  // YYYY-MM-DD
  return new Date(nowMs).toISOString().slice(0, 10);
}

function stableShardForDay(dayKey, shardCount) {
  // Tiny stable hash for day rotation; avoids hammering shard 0 forever.
  let h = 2166136261;
  for (let i = 0; i < dayKey.length; i += 1) {
    h ^= dayKey.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return shardCount > 0 ? h % shardCount : 0;
}

async function buildKPIResponse() {
  const nowMs = Date.now();
  const cutoffMs = nowMs - 24 * 60 * 60 * 1000;

  const [healthResult, bootstrapResult, budgetResult] = await Promise.allSettled([
    fetchJson(`${RELAY_ORIGIN}/health`),
    fetchJson(`${RELAY_ORIGIN}/.well-known/aiwre-bootstrap.json`),
    fetchJson(`${RELAY_ORIGIN}/v1/budget`),
  ]);

  const healthOk =
    healthResult.status === "fulfilled" && healthResult.value?.ok === true;
  if (bootstrapResult.status !== "fulfilled") {
    return jsonResponse(
      {
        status: "down",
        relay: RELAY_ORIGIN,
        generated_at: new Date(nowMs).toISOString(),
        error: "bootstrap_unavailable",
      },
      503,
      ERROR_CACHE_CONTROL
    );
  }

  const bootstrap = bootstrapResult.value;
  const relay =
    typeof bootstrap.relay === "string" && bootstrap.relay.length > 0
      ? bootstrap.relay
      : RELAY_ORIGIN;
  const shardCount = clampInt(bootstrap.shard_count, 1, MAX_SHARDS, 1);
  const topics = uniqueTopics(bootstrap);

  // Cost hardening: do NOT scan all shards (would burn relay budget under traffic).
  // Instead, sample one shard (rotates daily) and produce *estimates*.
  const sampleTopic = topics[0];
  const sampleShard = stableShardForDay(dayKeyUTC(nowMs), shardCount);

  let sampleMaxSeq = 0;
  let signals24hSample = 0;
  const agents24hSample = new Set();
  let feedOk = 0;
  let headsOk = 0;

  try {
    const headURL = new URL(`${relay}/v1/feed`);
    headURL.searchParams.set("topic", sampleTopic);
    headURL.searchParams.set("shard", String(sampleShard));
    headURL.searchParams.set("cursor", "0");
    headURL.searchParams.set("limit", "1");
    const head = await fetchJson(headURL.toString());
    sampleMaxSeq = clampInt(head?.max_seq, 0, Number.MAX_SAFE_INTEGER, 0);
    headsOk = 1;

    if (sampleMaxSeq > 0) {
      const cursor = Math.max(0, sampleMaxSeq - FEED_WINDOW_PER_SHARD);
      const tailURL = new URL(`${relay}/v1/feed`);
      tailURL.searchParams.set("topic", sampleTopic);
      tailURL.searchParams.set("shard", String(sampleShard));
      tailURL.searchParams.set("cursor", String(cursor));
      tailURL.searchParams.set("limit", String(FEED_WINDOW_PER_SHARD));
      const tail = await fetchJson(tailURL.toString());
      feedOk = 1;
      const entries = Array.isArray(tail?.entries) ? tail.entries : [];
      for (const e of entries) {
        const ts = parseTimestampMs(e?.timestamp);
        if (ts < cutoffMs) continue;
        signals24hSample += 1;
        if (typeof e?.sender === "string" && e.sender.length > 0) {
          agents24hSample.add(e.sender.toLowerCase());
        }
      }
    }
  } catch (_) {
    // Fall through with sample as "--".
  }

  const signals24h = signals24hSample > 0 ? signals24hSample * shardCount : signals24hSample;
  const activeAgents24h =
    agents24hSample.size > 0 ? agents24hSample.size * shardCount : agents24hSample.size;
  const topicSignalsTotalEst = sampleMaxSeq > 0 ? sampleMaxSeq * shardCount : sampleMaxSeq;

  const shardPairs = shardCount;
  const coverageRatio = shardPairs > 0 ? headsOk / shardPairs : 0;
  let status = "degraded";
  if (healthOk) status = "healthy";
  if (!healthOk) status = "down";

  const budgetRow =
    budgetResult.status === "fulfilled" && budgetResult.value && typeof budgetResult.value === "object"
      ? budgetResult.value
      : null;
  const budgetRemainingUSD =
    budgetRow && Number.isFinite(Number(budgetRow.remaining_usd))
      ? Number(budgetRow.remaining_usd)
      : null;

  return jsonResponse({
    status,
    relay,
    generated_at: new Date(nowMs).toISOString(),
    scope: {
      topics,
      shard_count: shardCount,
      shard_pairs: shardPairs,
      sample_topic: sampleTopic,
      sample_shard: sampleShard,
      sample_window: FEED_WINDOW_PER_SHARD,
    },
    kpi: {
      active_agents_24h: activeAgents24h,
      signals_24h: signals24h,
      topic_signals_total_est: topicSignalsTotalEst,
      budget_remaining_usd: budgetRemainingUSD,
      shard_coverage: {
        ok: headsOk,
        total: shardPairs,
        ratio: Number(coverageRatio.toFixed(3)),
      },
      sample_coverage: {
        feed_windows_ok: feedOk,
        feed_windows_total: sampleMaxSeq > 0 ? 1 : 0,
      },
    },
    note:
      "Cost-hardened KPI: derived from health + bootstrap plus a single-shard sample (rotates daily). Values are estimates and may under/over count.",
  });
}

export async function onRequest(context) {
  if (context.request.method !== "GET") {
    return new Response("method not allowed", { status: 405 });
  }

  const cache = caches.default;
  const cacheKey = new Request(context.request.url, { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) {
    return cached;
  }

  const fresh = await buildKPIResponse();
  if (fresh.status === 200) {
    context.waitUntil(cache.put(cacheKey, fresh.clone()));
  }
  return fresh;
}
