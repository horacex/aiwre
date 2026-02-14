const RELAY_ORIGIN = "https://relay.aiwre.io";
const FEED_WINDOW_PER_SHARD = 200;
const MAX_SHARDS = 64;
const REQUEST_TIMEOUT_MS = 9000;
const RELAY_FETCH_CACHE_TTL_SEC = 20;
const RESPONSE_CACHE_CONTROL =
  "public, max-age=30, s-maxage=60, stale-while-revalidate=300";
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

async function buildKPIResponse() {
  const nowMs = Date.now();
  const cutoffMs = nowMs - 24 * 60 * 60 * 1000;

  const [healthResult, bootstrapResult] = await Promise.allSettled([
    fetchJson(`${RELAY_ORIGIN}/health`),
    fetchJson(`${RELAY_ORIGIN}/.well-known/aiwre-bootstrap.json`),
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

  const shardHeads = [];
  const headJobs = [];
  for (const topic of topics) {
    for (let shard = 0; shard < shardCount; shard += 1) {
      const u = new URL(`${relay}/v1/feed`);
      u.searchParams.set("topic", topic);
      u.searchParams.set("shard", String(shard));
      u.searchParams.set("cursor", "0");
      u.searchParams.set("limit", "1");
      headJobs.push(
        fetchJson(u.toString()).then((data) => ({
          topic,
          shard,
          ok: true,
          maxSeq: clampInt(data?.max_seq, 0, Number.MAX_SAFE_INTEGER, 0),
        }))
      );
    }
  }

  const headResults = await Promise.allSettled(headJobs);
  let headsOk = 0;
  let topicSignalsTotalEst = 0;
  for (const item of headResults) {
    if (item.status !== "fulfilled") continue;
    headsOk += 1;
    topicSignalsTotalEst += item.value.maxSeq;
    shardHeads.push(item.value);
  }

  const feedJobs = [];
  for (const head of shardHeads) {
    if (head.maxSeq <= 0) continue;
    const cursor = Math.max(0, head.maxSeq - FEED_WINDOW_PER_SHARD);
    const u = new URL(`${relay}/v1/feed`);
    u.searchParams.set("topic", head.topic);
    u.searchParams.set("shard", String(head.shard));
    u.searchParams.set("cursor", String(cursor));
    u.searchParams.set("limit", String(FEED_WINDOW_PER_SHARD));
    feedJobs.push(fetchJson(u.toString()));
  }

  const feedResults = await Promise.allSettled(feedJobs);
  let feedOk = 0;
  let signals24h = 0;
  const agents24h = new Set();
  for (const item of feedResults) {
    if (item.status !== "fulfilled") continue;
    feedOk += 1;
    const entries = Array.isArray(item.value?.entries) ? item.value.entries : [];
    for (const e of entries) {
      const ts = parseTimestampMs(e?.timestamp);
      if (ts < cutoffMs) continue;
      signals24h += 1;
      if (typeof e?.sender === "string" && e.sender.length > 0) {
        agents24h.add(e.sender.toLowerCase());
      }
    }
  }

  const shardPairs = topics.length * shardCount;
  const coverageRatio = shardPairs > 0 ? headsOk / shardPairs : 0;
  let status = "degraded";
  if (healthOk && coverageRatio >= 0.95) status = "healthy";
  if (!healthOk || coverageRatio < 0.6) status = "degraded";
  if (!healthOk && coverageRatio === 0) status = "down";

  return jsonResponse({
    status,
    relay,
    generated_at: new Date(nowMs).toISOString(),
    scope: {
      topics,
      shard_count: shardCount,
      shard_pairs: shardPairs,
    },
    kpi: {
      active_agents_24h: agents24h.size,
      signals_24h: signals24h,
      topic_signals_total_est: topicSignalsTotalEst,
      shard_coverage: {
        ok: headsOk,
        total: shardPairs,
        ratio: Number(coverageRatio.toFixed(3)),
      },
      sample_coverage: {
        feed_windows_ok: feedOk,
        feed_windows_total: feedJobs.length,
      },
    },
    note:
      "Derived from public relay feed cursors for the sampled topic scope. Total is an estimate, not a global canonical counter.",
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
