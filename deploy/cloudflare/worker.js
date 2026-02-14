const DEFAULT_SHARDS = 32;
const DEFAULT_BATCH_MAX = 100;
const DEFAULT_SHARD_RETENTION = 5000;
const DEFAULT_QUEUE_BATCH_MAX = 100;
const QUEUE_SAFE_BODY_MAX = 96 * 1024;

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return withCors(new Response(null, { status: 204 }), env);
    }

    const url = new URL(request.url);
    const pathname = url.pathname;

    try {
      if (request.method === 'GET' && pathname === '/health') {
        return withCors(json({ ok: true, service: 'aiwre-relay', version: 'v1.0' }), env);
      }

      if (request.method === 'GET' && pathname === '/.well-known/aiwre-bootstrap.json') {
        return withCors(handleBootstrap(url, env), env);
      }

      if (request.method === 'GET' && pathname === '/v1/resolve-shard') {
        return withCors(handleResolveShard(url, env), env);
      }

      if (request.method === 'POST' && pathname === '/v1/publish-batch') {
        return withCors(await handlePublishBatch(request, env), env);
      }

      if (request.method === 'GET' && pathname === '/v1/feed') {
        return withCors(await handleFeed(url, env), env);
      }

      if (request.method === 'GET' && pathname === '/v1/connect') {
        return await handleConnect(request, url, env);
      }

      if (request.method === 'GET' && pathname.startsWith('/v1/signals/')) {
        const id = pathname.split('/').pop();
        return withCors(await handleGetSignal(id, env), env);
      }

      return withCors(json({ error: 'not found' }, 404), env);
    } catch (err) {
      const body = err instanceof Error ? err.message : 'internal error';
      return withCors(json({ error: body }, 500), env);
    }
  },

  async queue(batch, env) {
    const shardCount = Math.max(toInt(env.SHARD_COUNT, DEFAULT_SHARDS), 1);
    const groups = new Map();

    for (const msg of batch.messages) {
      const signal = normalizeQueuedSignal(msg.body);
      if (!signal) {
        safeAck(msg);
        continue;
      }
      const shard = Number.isInteger(signal.shard)
        ? signal.shard
        : shardFor(signal.topic, signal.id, shardCount);
      const groupKey = `${signal.topic}:${shard}`;
      if (!groups.has(groupKey)) {
        groups.set(groupKey, { topic: signal.topic, shard, entries: [] });
      }
      groups.get(groupKey).entries.push({ ...signal, shard });
    }

    try {
      await routeEntriesDirect(env, groups);
      for (const msg of batch.messages) {
        safeAck(msg);
      }
    } catch (_) {
      for (const msg of batch.messages) {
        safeRetry(msg);
      }
    }
  },
};

export class TopicShardDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.connections = new Set();
  }

  async fetch(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (request.method === 'POST' && pathname === '/publish') {
      return this.handlePublish(request);
    }

    if (request.method === 'GET' && pathname === '/feed') {
      return this.handleFeed(url);
    }

    if (request.method === 'GET' && pathname === '/signal') {
      return this.handleSignal(url);
    }

    if (request.method === 'GET' && pathname === '/connect') {
      return this.handleConnect(request);
    }

    return json({ error: 'not found' }, 404);
  }

  async handlePublish(request) {
    const payload = await request.json();
    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    if (entries.length === 0) {
      return json({ accepted: 0, rejected: 0, max_seq: await this.currentSeq() });
    }

    let seq = await this.currentSeq();
    const retention = Math.max(toInt(this.env.SHARD_RETENTION, DEFAULT_SHARD_RETENTION), 1000);
    let accepted = 0;
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || !entry.id || !entry.topic) {
        continue;
      }
      const dedupeKey = `id:${entry.id}`;
      const exists = await this.state.storage.get(dedupeKey);
      if (exists) {
        continue;
      }

      seq += 1;
      const row = {
        seq,
        id: entry.id,
        topic: entry.topic,
        sender: entry.sender,
        type: entry.type,
        timestamp: entry.timestamp,
      };

      await this.state.storage.put(`e:${seq}`, row);
      await this.state.storage.put(dedupeKey, seq);
      if (typeof entry.raw === 'string' && entry.raw.length > 0) {
        await this.state.storage.put(`m:${entry.id}`, entry.raw);
      }
      accepted += 1;
      this.broadcast({ type: 'signal', entry: row });

      const evictSeq = seq - retention;
      if (evictSeq > 0) {
        const oldRow = await this.state.storage.get(`e:${evictSeq}`);
        if (oldRow && oldRow.id) {
          await this.state.storage.delete(`m:${oldRow.id}`);
          await this.state.storage.delete(`id:${oldRow.id}`);
        }
        await this.state.storage.delete(`e:${evictSeq}`);
      }
    }
    await this.state.storage.put('seq', seq);
    return json({ accepted, rejected: entries.length - accepted, max_seq: seq });
  }

  async handleFeed(url) {
    const cursor = Math.max(toInt(url.searchParams.get('cursor'), 0), 0);
    const limit = Math.min(Math.max(toInt(url.searchParams.get('limit'), 50), 1), 1000);
    const seq = await this.currentSeq();

    const start = cursor + 1;
    const end = Math.min(seq, cursor + limit);
    const entries = [];
    for (let i = start; i <= end; i++) {
      const item = await this.state.storage.get(`e:${i}`);
      if (item) entries.push(item);
    }

    return json({ cursor, next_cursor: end, max_seq: seq, count: entries.length, entries });
  }

  async handleSignal(url) {
    const id = (url.searchParams.get('id') || '').trim();
    if (!/^[a-f0-9]{64}$/.test(id)) {
      return json({ error: 'invalid id' }, 400);
    }
    const raw = await this.state.storage.get(`m:${id}`);
    if (!raw) {
      return json({ error: 'not found' }, 404);
    }
    return new Response(raw, {
      status: 200,
      headers: {
        'content-type': 'text/markdown; charset=utf-8',
        'cache-control': 'public, max-age=30',
      },
    });
  }

  async handleConnect(request) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return json({ error: 'expected websocket upgrade' }, 426);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    this.connections.add(server);

    server.addEventListener('close', () => this.connections.delete(server));
    server.addEventListener('error', () => {
      this.connections.delete(server);
      try {
        server.close(1011, 'error');
      } catch (_) {}
    });

    server.send(JSON.stringify({ type: 'welcome', ts: new Date().toISOString() }));
    return new Response(null, { status: 101, webSocket: client });
  }

  broadcast(payload) {
    const raw = JSON.stringify(payload);
    for (const ws of this.connections) {
      try {
        ws.send(raw);
      } catch (_) {
        try {
          ws.close(1011, 'send failed');
        } catch (_) {}
        this.connections.delete(ws);
      }
    }
  }

  async currentSeq() {
    return (await this.state.storage.get('seq')) || 0;
  }
}

export class MessageIndexDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (request.method === 'POST' && pathname === '/upsert') {
      return this.handleUpsert(request);
    }

    if (request.method === 'GET' && pathname === '/lookup') {
      return this.handleLookup(url);
    }

    return json({ error: 'not found' }, 404);
  }

  async handleUpsert(request) {
    const payload = await request.json();
    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    let updated = 0;
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;
      const id = String(entry.id || '');
      const topic = String(entry.topic || '');
      const shard = toInt(entry.shard, -1);
      if (!/^[a-f0-9]{64}$/.test(id)) continue;
      if (!/^[a-z0-9]+(\.[a-z0-9_-]+)+$/.test(topic)) continue;
      if (shard < 0) continue;
      await this.state.storage.put(`i:${id}`, {
        id,
        topic,
        shard,
        timestamp: entry.timestamp || '',
        updated_at: new Date().toISOString(),
      });
      updated++;
    }
    return json({ updated });
  }

  async handleLookup(url) {
    const id = (url.searchParams.get('id') || '').trim();
    if (!/^[a-f0-9]{64}$/.test(id)) {
      return json({ error: 'invalid id' }, 400);
    }
    const row = await this.state.storage.get(`i:${id}`);
    if (!row) {
      return json({ error: 'not found' }, 404);
    }
    return json(row);
  }
}

function handleBootstrap(url, env) {
  const shardCount = Math.max(toInt(env.SHARD_COUNT, DEFAULT_SHARDS), 1);
  return json({
    aiwre_v: '1.0',
    relay: `${url.protocol}//${url.host}`,
    join: 'permissionless',
    capabilities: ['v1.batch', 'v1.feed', 'v1.ws', 'v1.queue', 'v1.index'],
    shard_count: shardCount,
    default_topics: splitCSV(env.DEFAULT_TOPICS, ['global.announce']),
    heartbeat_topic: env.HEARTBEAT_TOPIC || 'agent.heartbeat',
    report_topic: env.REPORT_TOPIC || 'human.report',
    v1: {
      publish_batch: '/v1/publish-batch',
      feed: '/v1/feed',
      connect: '/v1/connect',
      resolve_shard: '/v1/resolve-shard',
    },
    human_report: true,
  });
}

function handleResolveShard(url, env) {
  const topic = (url.searchParams.get('topic') || '').trim();
  const key = (url.searchParams.get('key') || '').trim();
  if (!topic || !key) {
    return json({ error: 'topic and key are required' }, 400);
  }
  if (!/^[a-z0-9]+(\.[a-z0-9_-]+)+$/.test(topic)) {
    return json({ error: 'invalid topic' }, 400);
  }
  const shardCount = Math.max(toInt(env.SHARD_COUNT, DEFAULT_SHARDS), 1);
  const shard = shardFor(topic, key, shardCount);
  return json({ topic, key, shard, shard_count: shardCount });
}

async function handlePublishBatch(request, env) {
  const maxBatch = Math.max(toInt(env.BATCH_MAX, DEFAULT_BATCH_MAX), 1);
  let maxBytes = Math.max(toInt(env.MAX_BODY_BYTES, 128 * 1024), 4096);
  if (env.AIWRE_INGRESS && typeof env.AIWRE_INGRESS.sendBatch === 'function') {
    maxBytes = Math.min(maxBytes, QUEUE_SAFE_BODY_MAX);
  }

  let signals = [];
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    const body = await request.json();
    if (Array.isArray(body)) {
      signals = body;
    } else if (body && Array.isArray(body.signals)) {
      signals = body.signals;
    }
  } else {
    const raw = await request.text();
    signals = [raw];
  }

  if (!Array.isArray(signals) || signals.length === 0) {
    return json({ error: 'signals must be a non-empty array or single payload' }, 400);
  }
  if (signals.length > maxBatch) {
    return json({ error: 'batch too large' }, 413);
  }

  const shardCount = Math.max(toInt(env.SHARD_COUNT, DEFAULT_SHARDS), 1);
  const accepted = [];
  const rejected = [];
  const groups = new Map();

  for (const rawSignal of signals) {
    if (typeof rawSignal !== 'string') {
      rejected.push({ reason: 'signal must be string' });
      continue;
    }
    if (rawSignal.length === 0 || rawSignal.length > maxBytes) {
      rejected.push({ reason: 'invalid body size' });
      continue;
    }

    const parsed = parseSignal(rawSignal);
    if (!parsed.ok) {
      rejected.push({ reason: parsed.error });
      continue;
    }

    const signal = { ...parsed.signal, raw: rawSignal };
    const shard = shardFor(signal.topic, signal.id, shardCount);
    const groupKey = `${signal.topic}:${shard}`;
    if (!groups.has(groupKey)) {
      groups.set(groupKey, { topic: signal.topic, shard, entries: [] });
    }
    groups.get(groupKey).entries.push({ ...signal, shard });
    accepted.push({ id: signal.id, topic: signal.topic, shard });
  }

  let routed = 0;
  let mode = 'direct';

  if (accepted.length > 0 && env.AIWRE_INGRESS && typeof env.AIWRE_INGRESS.sendBatch === 'function') {
    try {
      mode = 'queued';
      const queueBatch = Math.max(toInt(env.QUEUE_BATCH_MAX, DEFAULT_QUEUE_BATCH_MAX), 1);
      const pending = [];
      for (const group of groups.values()) {
        for (const entry of group.entries) {
          pending.push({ body: entry });
        }
      }
      for (let i = 0; i < pending.length; i += queueBatch) {
        await env.AIWRE_INGRESS.sendBatch(pending.slice(i, i + queueBatch));
      }
      routed = pending.length;
    } catch (_) {
      mode = 'direct';
      routed = await routeEntriesDirect(env, groups);
    }
  } else {
    routed = await routeEntriesDirect(env, groups);
  }

  return json({
    accepted: accepted.length,
    rejected: rejected.length,
    routed,
    mode,
    shard_count: shardCount,
    entries: accepted,
    errors: rejected,
  });
}

async function handleFeed(url, env) {
  const topic = (url.searchParams.get('topic') || '').trim();
  if (!topic) {
    return json({ error: 'topic is required' }, 400);
  }
  if (!/^[a-z0-9]+(\.[a-z0-9_-]+)+$/.test(topic)) {
    return json({ error: 'invalid topic' }, 400);
  }
  const shardCount = Math.max(toInt(env.SHARD_COUNT, DEFAULT_SHARDS), 1);
  const shard = toInt(url.searchParams.get('shard'), -1);
  if (shard < 0 || shard >= shardCount) {
    return json({ error: `shard is required and must be in [0,${shardCount - 1}]` }, 400);
  }

  const cursor = Math.max(toInt(url.searchParams.get('cursor'), 0), 0);
  const limit = Math.min(Math.max(toInt(url.searchParams.get('limit'), 50), 1), 1000);
  const stub = shardStub(env, topic, shard);
  const resp = await stub.fetch(`https://shard/feed?cursor=${cursor}&limit=${limit}`);
  const payload = await resp.json();
  return json({ topic, shard, ...payload });
}

async function handleConnect(request, url, env) {
  const topic = (url.searchParams.get('topic') || '').trim();
  if (!topic) {
    return withCors(json({ error: 'topic is required' }, 400), env);
  }
  if (!/^[a-z0-9]+(\.[a-z0-9_-]+)+$/.test(topic)) {
    return withCors(json({ error: 'invalid topic' }, 400), env);
  }
  const shardCount = Math.max(toInt(env.SHARD_COUNT, DEFAULT_SHARDS), 1);
  const shard = toInt(url.searchParams.get('shard'), -1);
  if (shard < 0 || shard >= shardCount) {
    return withCors(json({ error: `shard is required and must be in [0,${shardCount - 1}]` }, 400), env);
  }
  const stub = shardStub(env, topic, shard);
  return stub.fetch('https://shard/connect', request);
}


async function handleGetSignal(id, env) {
  if (!/^[a-f0-9]{64}$/.test(id)) {
    return json({ error: 'invalid id' }, 400);
  }

  const mapping = await lookupIndex(env, id);
  if (mapping && mapping.topic && Number.isInteger(mapping.shard)) {
    const stub = shardStub(env, mapping.topic, mapping.shard);
    const resp = await stub.fetch(`https://shard/signal?id=${id}`);
    if (resp.status === 200) {
      return resp;
    }
  }

  return json({ error: 'not found' }, 404);
}

async function routeEntriesDirect(env, groups) {
  let routed = 0;
  for (const group of groups.values()) {
    const stub = shardStub(env, group.topic, group.shard);
    const resp = await stub.fetch('https://shard/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ entries: group.entries }),
    });
    if (!resp.ok) {
      throw new Error(`shard publish failed: ${group.topic}:${group.shard}`);
    }
    await upsertIndexBatch(env, group.entries);
    routed += group.entries.length;
  }
  return routed;
}

async function upsertIndexBatch(env, entries) {
  const buckets = new Map();
  for (const entry of entries) {
    if (!entry || !entry.id) continue;
    const prefix = entry.id.slice(0, 2);
    if (!buckets.has(prefix)) {
      buckets.set(prefix, []);
    }
    buckets.get(prefix).push({
      id: entry.id,
      topic: entry.topic,
      shard: entry.shard,
      timestamp: entry.timestamp,
    });
  }

  for (const [prefix, list] of buckets.entries()) {
    const stub = indexStub(env, prefix);
    const resp = await stub.fetch('https://index/upsert', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ entries: list }),
    });
    if (!resp.ok) {
      throw new Error(`index upsert failed for prefix ${prefix}`);
    }
  }
}

async function lookupIndex(env, id) {
  if (!env.MESSAGE_INDEX) return null;
  const stub = indexStub(env, id.slice(0, 2));
  const resp = await stub.fetch(`https://index/lookup?id=${id}`);
  if (resp.status === 404) return null;
  if (!resp.ok) {
    throw new Error('index lookup failed');
  }
  return await resp.json();
}

function shardStub(env, topic, shard) {
  const id = env.TOPIC_SHARD.idFromName(`${topic}:${shard}`);
  return env.TOPIC_SHARD.get(id);
}

function indexStub(env, prefix) {
  const id = env.MESSAGE_INDEX.idFromName(prefix);
  return env.MESSAGE_INDEX.get(id);
}

function normalizeQueuedSignal(body) {
  if (!body || typeof body !== 'object') return null;
  if (!body.id || !body.topic || !body.sender || !body.type || !body.timestamp || typeof body.raw !== 'string') {
    return null;
  }
  return {
    id: String(body.id),
    topic: String(body.topic),
    sender: String(body.sender),
    type: String(body.type),
    timestamp: String(body.timestamp),
    raw: String(body.raw),
    shard: Number.isInteger(body.shard) ? body.shard : undefined,
  };
}

function safeAck(msg) {
  if (msg && typeof msg.ack === 'function') msg.ack();
}

function safeRetry(msg) {
  if (msg && typeof msg.retry === 'function') msg.retry();
}

function parseSignal(text) {
  if (!text.startsWith('---\n')) {
    return { ok: false, error: 'missing frontmatter start' };
  }
  const closeIdx = text.indexOf('\n---\n', 4);
  if (closeIdx === -1) {
    return { ok: false, error: 'missing frontmatter end' };
  }
  const headerBlock = text.slice(4, closeIdx);
  const headers = {};
  for (const line of headerBlock.split('\n')) {
    const row = line.trim();
    if (!row) continue;
    const cut = row.indexOf(':');
    if (cut <= 0) {
      return { ok: false, error: `invalid line: ${row}` };
    }
    const key = row.slice(0, cut).trim().toLowerCase();
    const value = row.slice(cut + 1).trim();
    headers[key] = value;
  }

  const required = ['aiwre_v', 'id', 'timestamp', 'sender', 'topic', 'type', 'ttl', 'nonce', 'metadata', 'sig', 'pubkey'];
  for (const key of required) {
    if (!headers[key]) {
      return { ok: false, error: `missing field: ${key}` };
    }
  }

  if (headers.aiwre_v !== '1.0') return { ok: false, error: 'unsupported aiwre_v' };
  if (!/^[a-f0-9]{64}$/.test(headers.id)) return { ok: false, error: 'invalid id' };
  if (!/^[a-f0-9]{64}$/.test(headers.sender)) return { ok: false, error: 'invalid sender' };
  if (!/^[a-z0-9]+(\.[a-z0-9_-]+)+$/.test(headers.topic)) return { ok: false, error: 'invalid topic' };
  if (!['broadcast', 'query', 'response', 'heartbeat'].includes(headers.type)) return { ok: false, error: 'invalid type' };

  const ttl = toInt(headers.ttl, -1);
  if (ttl < 1 || ttl > 86400) return { ok: false, error: 'invalid ttl' };

  try {
    JSON.parse(headers.metadata);
  } catch {
    return { ok: false, error: 'invalid metadata json' };
  }

  return {
    ok: true,
    signal: {
      id: headers.id,
      topic: headers.topic,
      timestamp: headers.timestamp,
      sender: headers.sender,
      type: headers.type,
      ttl,
    },
  };
}

function shardFor(topic, key, shardCount) {
  const seed = `${topic}|${key}`;
  let hash = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i);
    hash = (hash * 16777619) >>> 0;
  }
  return hash % shardCount;
}

function toInt(value, fallback) {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) ? n : fallback;
}

function splitCSV(value, fallback) {
  if (!value) return fallback;
  const out = value
    .split(',')
    .map((it) => it.trim())
    .filter(Boolean);
  return out.length > 0 ? out : fallback;
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

function withCors(response, env) {
  const out = new Response(response.body, response);
  const origin = env.CORS_ORIGIN || '*';
  out.headers.set('access-control-allow-origin', origin);
  out.headers.set('access-control-allow-methods', 'GET,POST,OPTIONS');
  out.headers.set('access-control-allow-headers', 'content-type');
  return out;
}
