// @ts-nocheck
// apiGateway — public data plane. Cache-first; keys verified by SHA-256; durable quotas; AI handlers.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token, X-Playground-Key, X-Client-Source',
  'Access-Control-Max-Age': '600',
};

const KEY_PREFIXES = ['mr_riduy_ai_', 'sk_live_'];

function json(status: number, body: unknown, extra: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra },
  });
}

async function sha256hex(s: string) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function rid() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return 'req_' + Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

const cache: any = { catalog: null, catalogAt: 0, keys: new Map(), sessions: new Map(), devs: new Map(), rl: new Map() };
const KEY_TTL = 5000;
const CAT_TTL = 30000;
const SESS_TTL = 10000;
const DEV_TTL = 30000;

function memRate(keyId: string, minuteLimit: number, dayLimit: number) {
  const now = Date.now();
  const m = Math.floor(now / 60000);
  const d = Math.floor(now / 86400000);
  let st = cache.rl.get(keyId);
  if (!st) { st = { m, mc: 0, d, dc: 0 }; cache.rl.set(keyId, st); }
  if (st.m !== m) { st.m = m; st.mc = 0; }
  if (st.d !== d) { st.d = d; st.dc = 0; }
  st.mc += 1; st.dc += 1;
  if (cache.rl.size > 4000) cache.rl.clear();
  return {
    minuteExceeded: st.mc > minuteLimit,
    dayExceeded: st.dc > dayLimit,
    minuteRemaining: Math.max(0, minuteLimit - st.mc),
    dayRemaining: Math.max(0, dayLimit - st.dc),
  };
}

async function dbRate(base44: any, keyId: string, minuteLimit: number, dayLimit: number) {
  const now = Date.now();
  const mStart = Math.floor(now / 60000) * 60000;
  const dStart = Math.floor(now / 86400000) * 86400000;
  const scope = 'k:' + keyId;
  const mIso = new Date(mStart).toISOString();
  const dIso = new Date(dStart).toISOString();
  const found = await base44.asServiceRole.entities.ApiRateLimitCounter.filter({ scope_key: scope }, { limit: 1 });
  const rec = found.items[0];
  let mc: number; let dc: number;
  if (!rec) {
    mc = 1; dc = 1;
    await base44.asServiceRole.entities.ApiRateLimitCounter.create({
      scope_key: scope, api_key_id: keyId, window_type: 'minute', window_start: mIso, count: 1,
      minute_start: mIso, minute_count: 1, day_start: dIso, day_count: 1,
    });
  } else {
    const sameM = !!(rec.minute_start && new Date(rec.minute_start).getTime() === mStart);
    const sameD = !!(rec.day_start && new Date(rec.day_start).getTime() === dStart);
    mc = (sameM ? Number(rec.minute_count || 0) : 0) + 1;
    dc = (sameD ? Number(rec.day_count || 0) : 0) + 1;
    await base44.asServiceRole.entities.ApiRateLimitCounter.update(rec.id, {
      window_start: mIso, count: mc, minute_start: mIso, minute_count: mc, day_start: dIso, day_count: dc,
    });
  }
  return {
    minuteExceeded: mc > minuteLimit,
    dayExceeded: dc > dayLimit,
    minuteRemaining: Math.max(0, minuteLimit - mc),
    dayRemaining: Math.max(0, dayLimit - dc),
  };
}

async function loadCatalog(base44: any) {
  if (cache.catalog && Date.now() - cache.catalogAt < CAT_TTL) return cache.catalog;
  const apis = await base44.asServiceRole.entities.ApiService.list({ limit: 500 });
  const eps = await base44.asServiceRole.entities.ApiEndpoint.list({ limit: 1000 });
  cache.catalog = { apis: apis.items || [], endpoints: eps.items || [] };
  cache.catalogAt = Date.now();
  return cache.catalog;
}

function str(v: any) { return typeof v === 'string' ? v.trim() : ''; }

// ---------- AI helpers (platform Core integration, no external provider key) ----------
async function llm(base44: any, prompt: string) {
  const r = await base44.asServiceRole.integrations.Core.InvokeLLM({ prompt });
  if (typeof r === 'string') return r;
  if (r && typeof r === 'object') return (r as any).text || (r as any).result || JSON.stringify(r);
  return String(r);
}

function parseJsonish(text: string) {
  const t = String(text).trim().replace(/^```(?:json)?/i, '').replace(/```$/, '').trim();
  try { return JSON.parse(t); } catch (_) { /* fall through */ }
  const m = t.match(/\{[\s\S]*\}/);
  if (m) { try { return JSON.parse(m[0]); } catch (_) { /* ignore */ } }
  return null;
}

const AI_MAX_INPUT = 12000;

function aiInput(payload: any) {
  const text = str(payload.text) || str(payload.message) || str(payload.prompt) || str(payload.input);
  if (!text) return { error: json(400, { ok: false, status: 400, data: { error: 'missing_parameter', message: '"text" is required.' } }) };
  if (text.length > AI_MAX_INPUT) {
    return { error: json(400, { ok: false, status: 400, data: { error: 'invalid_parameter', message: 'text exceeds ' + AI_MAX_INPUT + ' characters.' } }) };
  }
  return { text };
}

// ---------- handler registry ----------
const HANDLERS: Record<string, (ctx: any) => Promise<any>> = {
  'system.time': async () => {
    const now = new Date();
    return { status: 200, body: { utc_iso: now.toISOString(), unix_seconds: Math.floor(now.getTime() / 1000), unix_ms: now.getTime(), timezone: 'UTC' } };
  },

  'system.health': async () => {
    const t0 = performance.now();
    const apis = await base44.entities.ApiService.list({ limit: 500 });
    const latency = Math.max(1, Math.round(performance.now() - t0));
    const cat = cache.catalog || {};
    return {
      status: 200,
      body: {
        status: 'operational',
        database_latency_ms: latency,
        database_ok: (apis.items || []).length >= 0,
        apis_total: (cat.apis || []).length || (apis.items || []).length,
        endpoints_total: (cat.endpoints || []).length,
        timestamp: new Date().toISOString(),
        region: 'managed',
      },
    };
  },

  'crypto.sha256': async ({ body, params }) => {
    const text = str(body.text) || str(params.text);
    if (!text) return { status: 400, body: { error: 'missing_parameter', message: '"text" (non-empty string) is required.' } };
    const hex = await sha256hex(text);
    return { status: 200, body: { algorithm: 'SHA-256', hex, input_bytes: new TextEncoder().encode(text).length } };
  },

  'crypto.random': async ({ body, params }) => {
    const rawBytes = body.bytes !== undefined ? body.bytes : params.bytes;
    const bytes = rawBytes === undefined ? 32 : Number(rawBytes);
    const encoding = str(body.encoding) || str(params.encoding) || 'hex';
    if (!Number.isInteger(bytes) || bytes < 1 || bytes > 256) {
      return { status: 400, body: { error: 'invalid_parameter', message: '"bytes" must be an integer from 1 to 256.' } };
    }
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    let value: string;
    if (encoding === 'base64') {
      value = btoa(Array.from(buf).map((b) => String.fromCharCode(b)).join(''));
    } else {
      value = Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
    }
    return { status: 200, body: { encoding: encoding === 'base64' ? 'base64' : 'hex', bytes, value } };
  },

  'text.slugify': async ({ body, params }) => {
    const text = str(body.text) || str(params.text);
    if (!text) return { status: 400, body: { error: 'missing_parameter', message: '"text" (non-empty string) is required.' } };
    const slug = text.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return { status: 200, body: { slug, input_length: text.length } };
  },

  'text.stats': async ({ body, params }) => {
    const text = str(body.text) || str(params.text);
    if (!text) return { status: 400, body: { error: 'missing_parameter', message: '"text" (non-empty string) is required.' } };
    const words = text.split(/\s+/).filter(Boolean);
    const sentences = text.split(/[.!?]+/).filter((s) => s.trim().length > 0);
    return {
      status: 200,
      body: {
        input_length: text.length,
        characters: text.length,
        characters_no_spaces: text.replace(/\s/g, '').length,
        words: words.length,
        unique_words: new Set(words.map((w) => w.toLowerCase())).size,
        sentences: sentences.length,
        lines: text.split(/\r?\n/).length,
      },
    };
  },

  'echo.request': async ({ body, params, headers, api_key }) => ({
    status: 200,
    body: {
      method: (headers['x-http-method'] || 'POST').toUpperCase(),
      api_key_prefix: api_key ? api_key.prefix : null,
      query: Object.fromEntries(params.entries()),
      body,
      received_at: new Date().toISOString(),
    },
  }),

  'json.validate': async ({ body, params }) => {
    const raw = body.json !== undefined ? body.json : params.json;
    if (raw === undefined || raw === null || raw === '') {
      return { status: 400, body: { error: 'missing_parameter', message: '"json" (string) is required.' } };
    }
    try {
      const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
      return { status: 200, body: { valid: true, type: Array.isArray(parsed) ? 'array' : typeof parsed, parsed } };
    } catch (e) {
      return { status: 200, body: { valid: false, error: String((e as Error).message || e) } };
    }
  },

  'platform.usage': async ({ base44: b, api_key }) => {
    const logs = await b.asServiceRole.entities.ApiRequestLog.filter({ api_key_id: api_key.id }, { sort: '-created_date', limit: 500 });
    const rows = logs.items || [];
    const ok = rows.filter((r: any) => r.success).length;
    const avg = rows.length ? Math.round(rows.reduce((a: number, r: any) => a + Number(r.response_time_ms || 0), 0) / rows.length) : 0;
    return {
      status: 200,
      body: {
        api_key_prefix: api_key.prefix + (api_key.last4 || ''),
        requests: rows.length,
        success: ok,
        failed: rows.length - ok,
        avg_response_time_ms: avg,
        window: 'last 500 calls',
      },
    };
  },

  'data.apis.list': async () => {
    const cat = await loadCatalog(base44);
    const published = (cat.apis || []).filter((a: any) => a.status === 'active' && a.is_public !== false);
    return {
      status: 200,
      body: {
        count: published.length,
        apis: published.map((a: any) => ({
          name: a.name, slug: a.slug, description: a.description, version: a.version,
          category: a.category_slug, base_path: a.base_path,
          endpoints: (cat.endpoints || []).filter((e: any) => e.api_slug === a.slug && e.is_active !== false).length,
        })),
      },
    };
  },

  'data.endpoints.list': async ({ body, params }) => {
    const slug = str(body.api_slug) || str(params.api_slug);
    const cat = await loadCatalog(base44);
    const eps = (cat.endpoints || []).filter((e: any) => (!slug || e.api_slug === slug) && e.is_active !== false);
    return {
      status: 200,
      body: {
        api_slug: slug || null,
        count: eps.length,
        endpoints: eps.map((e: any) => ({ name: e.name, slug: e.slug, method: e.method, path: e.path, summary: e.summary })),
      },
    };
  },

  // ---- AI endpoints: executed by the platform model runtime ----
  'ai.chat': async ({ base44: b, body }) => {
    const message = str(body.message) || str(body.text) || str(body.prompt);
    if (!message) return { status: 400, body: { error: 'missing_parameter', message: '"message" is required.' } };
    if (message.length > AI_MAX_INPUT) return { status: 400, body: { error: 'invalid_parameter', message: 'message too long' } };
    const system = str(body.system);
    const prompt = system
      ? 'System instruction: ' + system + '\n\nUser: ' + message + '\n\nAnswer the user directly.'
      : message;
    const reply = await llm(b, prompt + '\n\nRespond in the same language as the user.');
    return { status: 200, body: { reply: String(reply).trim(), model: 'base44-core', input_length: message.length } };
  },

  'ai.summarize': async ({ base44: b, body }) => {
    const g = aiInput(body);
    if (g.error) return g.error;
    const maxWords = Math.max(10, Math.min(400, Number(body.max_words) || 80));
    const out = await llm(b, 'Summarize the following text in at most ' + maxWords + ' words. Return only the summary, no preamble.\n\nTEXT:\n' + g.text);
    return { status: 200, body: { summary: String(out).trim(), max_words: maxWords, input_length: g.text.length } };
  },

  'ai.sentiment': async ({ base44: b, body }) => {
    const g = aiInput(body);
    if (g.error) return g.error;
    const out = await llm(b, 'Classify the sentiment of the text. Reply ONLY with JSON: {"sentiment":"positive|negative|neutral","confidence":0-1,"reasons":["..."]}\n\nTEXT:\n' + g.text);
    const parsed = parseJsonish(out) || {};
    return {
      status: 200,
      body: {
        sentiment: parsed.sentiment || 'neutral',
        confidence: Number(parsed.confidence) || 0,
        reasons: Array.isArray(parsed.reasons) ? parsed.reasons.slice(0, 5) : [],
        input_length: g.text.length,
      },
    };
  },

  'ai.translate': async ({ base44: b, body }) => {
    const g = aiInput(body);
    if (g.error) return g.error;
    const target = str(body.target_language) || str(body.to) || 'English';
    const source = str(body.source_language) || str(body.from);
    const out = await llm(b, 'Translate the following text into ' + target + (source ? ' from ' + source : '') + '. Return only the translation.\n\nTEXT:\n' + g.text);
    return { status: 200, body: { translation: String(out).trim(), target_language: target, source_language: source || 'auto' } };
  },

  'ai.classify': async ({ base44: b, body }) => {
    const g = aiInput(body);
    if (g.error) return g.error;
    const cats = Array.isArray(body.categories) ? body.categories.filter((c: any) => typeof c === 'string').slice(0, 30) : [];
    if (!cats.length) return { status: 400, body: { error: 'missing_parameter', message: '"categories" (array of strings) is required.' } };
    const out = await llm(b, 'Choose exactly one of these categories: ' + cats.join(', ') + '.\nReply ONLY with JSON: {"category":"<one of the given categories>","confidence":0-1}\n\nTEXT:\n' + g.text);
    const parsed = parseJsonish(out) || {};
    const picked = cats.includes(parsed.category) ? parsed.category : null;
    return { status: 200, body: { category: picked, confidence: Number(parsed.confidence) || 0, allowed: cats, matched: !!picked } };
  },

  'ai.keywords': async ({ base44: b, body }) => {
    const g = aiInput(body);
    if (g.error) return g.error;
    const limit = Math.max(1, Math.min(30, Number(body.limit) || 8));
    const out = await llm(b, 'Extract the ' + limit + ' most important keywords or key phrases. Reply ONLY with JSON: {"keywords":["..."]}\n\nTEXT:\n' + g.text);
    const parsed = parseJsonish(out) || {};
    const kws = Array.isArray(parsed.keywords) ? parsed.keywords.filter((k: any) => typeof k === 'string').slice(0, limit) : [];
    return { status: 200, body: { keywords: kws, limit, input_length: g.text.length } };
  },
};

Deno.serve(async (req) => {
  const t0 = performance.now();
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const requestId = rid();
  const base44 = createClientFromRequest(req);
  const headers: Record<string, string> = {};
  for (const [k, v] of req.headers.entries()) headers[k.toLowerCase()] = v;

  let apiKey: any = null;
  let developer: any = null;
  let body: any = {};
  let params = new URL(req.url).searchParams;

  const elapsed = () => Math.round(performance.now() - t0);

  async function logRow(entry: any) {
    try {
      await base44.asServiceRole.entities.ApiRequestLog.create({
        developer_id: developer ? developer.id : null,
        developer_email: developer ? developer.email : null,
        api_key_id: apiKey ? apiKey.id : null,
        api_key_prefix: apiKey ? apiKey.prefix + (apiKey.last4 || '') : null,
        api_id: entry.api_id || null,
        api_slug: entry.api_slug || null,
        endpoint_id: entry.endpoint_id || null,
        endpoint_path: entry.endpoint_path || null,
        method: entry.method || 'POST',
        status_code: entry.status_code,
        response_time_ms: entry.response_time_ms || elapsed(),
        success: !!entry.success,
        error_code: entry.error_code || null,
        ip_address: headers['x-real-ip'] || headers['x-forwarded-for'] || null,
        user_agent: headers['user-agent'] || null,
        request_id: requestId,
        source: headers['x-client-source'] === 'playground' ? 'playground' : 'api',
      });
    } catch (_) { /* auditing must never break the response */ }
  }

  function finish(status: number, payload: any, errorCode?: string, meta?: any) {
    const needsDataShim = payload && payload.error && !payload.data && status === 400;
    const out: any = {
      ok: status < 400,
      status,
      request_id: requestId,
      api: meta && meta.api_slug ? meta.api_slug : null,
      endpoint: meta && meta.endpoint_slug ? meta.endpoint_slug : null,
      http_method: req.method,
      response_time_ms: elapsed(),
      data: needsDataShim ? payload : (payload && payload.body !== undefined ? payload.body : payload),
    };
    if (status >= 400 && !needsDataShim) out.error = { code: errorCode || 'error', message: (payload && payload.message) || (payload && payload.error) || 'Request failed.' };
    if (meta && meta.rate_limit) out.meta = { rate_limit: meta.rate_limit };
    logRow({
      api_id: meta && meta.api_id, api_slug: meta && meta.api_slug,
      endpoint_id: meta && meta.endpoint_id, endpoint_path: meta && meta.endpoint_path,
      method: meta && meta.method ? meta.method : req.method,
      status_code: status, success: status < 400, error_code: errorCode,
    });
    return json(status, out);
  }

  try {
    let rawKey = str(headers['x-api-key']);
    if (!rawKey && headers['authorization']) rawKey = str(headers['authorization'].replace(/^Bearer\s+/i, ''));

    // body parsing
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      try {
        const text = await req.text();
        if (text && text.length > 200000) return finish(413, { error: 'payload_too_large', message: 'Request body exceeds 200KB.' }, 'payload_too_large');
        if (text) { try { body = JSON.parse(text); } catch (_) { return finish(400, { error: 'invalid_json', message: 'Request body must be valid JSON.' }, 'invalid_json'); } }
      } catch (_) { body = {}; }
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) body = {};

    // ---------- authentication ----------
    if (rawKey) {
      if (!KEY_PREFIXES.some((p) => rawKey.startsWith(p))) {
        return finish(401, { error: 'invalid_api_key', message: 'Malformed API key.' }, 'invalid_api_key');
      }
      const hash = await sha256hex(rawKey);
      const cached = cache.keys.get(hash);
      if (cached && Date.now() - cached.at < KEY_TTL) {
        apiKey = cached.record;
      } else {
        const found = await base44.asServiceRole.entities.ApiKey.filter({ key_hash: hash }, { limit: 1 });
        apiKey = found.items[0] || null;
        if (apiKey) cache.keys.set(hash, { record: apiKey, at: Date.now() });
      }
      if (!apiKey) return finish(401, { error: 'invalid_api_key', message: 'API key is not recognised.' }, 'invalid_api_key');
      if (apiKey.status === 'revoked') return finish(403, { error: 'key_revoked', message: 'This API key is revoked and cannot be used.' }, 'key_revoked');
      if (apiKey.expires_at && new Date(apiKey.expires_at).getTime() < Date.now()) {
        return finish(403, { error: 'key_expired', message: 'This API key has expired.' }, 'key_expired');
      }
    } else if (headers['x-developer-token'] && headers['x-playground-key']) {
      const th = await sha256hex(str(headers['x-developer-token']));
      let sess = cache.sessions.get(th);
      if (!sess || Date.now() - sess.at > SESS_TTL) {
        const s = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: th }, { limit: 1 });
        sess = { record: s.items[0] || null, at: Date.now() };
        cache.sessions.set(th, sess);
      }
      const s = sess.record;
      if (!s || s.revoked || new Date(s.expires_at).getTime() < Date.now()) {
        return finish(401, { error: 'invalid_session', message: 'Developer session is invalid or expired.' }, 'invalid_session');
      }
      const k = await base44.asServiceRole.entities.ApiKey.filter({ id: str(headers['x-playground-key']) }, { limit: 1 });
      apiKey = k.items[0] || null;
      if (!apiKey || apiKey.developer_id !== s.developer_id) {
        return finish(403, { error: 'forbidden', message: 'That API key does not belong to your account.' }, 'forbidden');
      }
      if (apiKey.status === 'revoked') return finish(403, { error: 'key_revoked', message: 'This API key is revoked and cannot be used.' }, 'key_revoked');
    } else {
      return finish(401, { error: 'missing_api_key', message: 'Send your key in the X-Api-Key header.' }, 'missing_api_key');
    }

    // developer state
    const devCacheKey = apiKey.developer_id;
    let dev = cache.devs.get(devCacheKey);
    if (!dev || Date.now() - dev.at > DEV_TTL) {
      const d = await base44.asServiceRole.entities.DeveloperProfile.filter({ id: apiKey.developer_id }, { limit: 1 });
      dev = { record: d.items[0] || null, at: Date.now() };
      cache.devs.set(devCacheKey, dev);
    }
    developer = dev.record;
    if (!developer) return finish(403, { error: 'forbidden', message: 'Developer account not found.' }, 'forbidden');
    if (developer.status !== 'active') return finish(403, { error: 'account_suspended', message: 'This account is suspended.' }, 'account_suspended');

    // ---------- resolve target ----------
    const cat = await loadCatalog(base44);
    let api = null; let endpoint = null;
    const apiSlug = str(body.api) || str(params.get('api'));
    const epSlug = str(body.endpoint) || str(params.get('endpoint'));
    const pathRef = str(body.path) || str(params.get('path'));

    if (apiSlug) {
      api = (cat.apis || []).find((a: any) => a.slug === apiSlug) || null;
      if (!api) return finish(404, { error: 'api_not_found', message: 'No API with slug "' + apiSlug + '".' }, 'api_not_found');
      if (epSlug) {
        endpoint = (cat.endpoints || []).find((e: any) => e.api_slug === apiSlug && e.slug === epSlug) || null;
      } else if (pathRef) {
        endpoint = (cat.endpoints || []).find((e: any) => e.api_slug === apiSlug && e.path === pathRef) || null;
      }
      if (!endpoint) {
        return finish(404, { error: 'endpoint_not_found', message: 'No endpoint "' + (epSlug || pathRef || '(none)') + '" under API "' + apiSlug + '".' }, 'endpoint_not_found');
      }
    } else if (pathRef) {
      api = (cat.apis || []).find((a: any) => pathRef === a.base_path || pathRef.startsWith(String(a.base_path || '') + '/')) || null;
      if (!api) return finish(404, { error: 'api_not_found', message: 'No API matches path "' + pathRef + '".' }, 'api_not_found');
      endpoint = (cat.endpoints || []).find((e: any) => e.api_slug === api.slug && e.path === pathRef) || null;
      if (!endpoint) return finish(404, { error: 'endpoint_not_found', message: 'No endpoint at path "' + pathRef + '".' }, 'endpoint_not_found');
    } else {
      return finish(400, { error: 'missing_target', message: 'Provide "api" and "endpoint" (or "path").' }, 'missing_target');
    }

    if (api.status !== 'active') return finish(403, { error: 'api_inactive', message: 'This API is not currently published.' }, 'api_inactive', { api_slug: api.slug, endpoint_slug: endpoint.slug, api_id: api.id, endpoint_id: endpoint.id, endpoint_path: endpoint.path, method: endpoint.method });
    if (endpoint.is_active === false) return finish(403, { error: 'endpoint_inactive', message: 'This endpoint is disabled.' }, 'endpoint_inactive');

    // method: POST is the gateway envelope verb; otherwise the endpoint verb must match
    const method = String(endpoint.method || 'POST').toUpperCase();
    if (req.method !== 'POST' && req.method !== method) {
      return finish(405, { error: 'method_not_allowed', message: 'This endpoint accepts ' + method + '.' }, 'method_not_allowed',
        { api_slug: api.slug, endpoint_slug: endpoint.slug, api_id: api.id, endpoint_id: endpoint.id, endpoint_path: endpoint.path, method });
    }

    // per-key API allowlist
    const allowed = Array.isArray(apiKey.api_slugs) ? apiKey.api_slugs : [];
    if (allowed.length && !allowed.includes(api.slug)) {
      return finish(403, { error: 'api_not_permitted', message: 'This key is not permitted to call the ' + api.slug + ' API.' }, 'api_not_permitted',
        { api_slug: api.slug, endpoint_slug: endpoint.slug, api_id: api.id, endpoint_id: endpoint.id, endpoint_path: endpoint.path, method });
    }

    // ---------- rate limiting ----------
    const minuteLimit = Number(endpoint.rate_limit_override || apiKey.rate_limit_per_minute || api.default_rate_limit_per_minute || 60);
    const dayLimit = Number(apiKey.daily_quota || api.default_daily_quota || 10000);
    const metaBase = { api_slug: api.slug, endpoint_slug: endpoint.slug, api_id: api.id, endpoint_id: endpoint.id, endpoint_path: endpoint.path, method };

    let rl = memRate(apiKey.id, minuteLimit, dayLimit);
    if (rl.minuteExceeded || rl.dayExceeded) {
      return finish(429, { error: 'rate_limit_exceeded', message: 'Rate limit reached. Retry after the window resets.' }, 'rate_limit_exceeded',
        { ...metaBase, rate_limit: { limit_per_minute: minuteLimit, remaining: rl.minuteRemaining, quota_per_day: dayLimit, window: rl.minuteExceeded ? 'minute' : 'day' } },
      );
    }
    try {
      rl = await dbRate(base44, apiKey.id, minuteLimit, dayLimit);
    } catch (_) { /* durable counter unavailable: fall back to the in-memory window */ }
    if (rl.minuteExceeded || rl.dayExceeded) {
      return finish(429, { error: 'rate_limit_exceeded', message: 'Rate limit reached. Retry after the window resets.' }, 'rate_limit_exceeded',
        { ...metaBase, rate_limit: { limit_per_minute: minuteLimit, remaining: rl.minuteRemaining, quota_per_day: dayLimit, window: rl.minuteExceeded ? 'minute' : 'day' } },
      );
    }

    // ---------- dispatch ----------
    const handler = HANDLERS[endpoint.handler_key];
    if (!handler) {
      return finish(501, { error: 'unknown_handler', message: 'No handler is registered for handler_key "' + (endpoint.handler_key || '') + '".' }, 'unknown_handler', metaBase);
    }

    const RESERVED = new Set(['api', 'endpoint', 'path', 'body', 'params']);
    const flat: any = {};
    for (const [k, v] of Object.entries(body)) if (!RESERVED.has(k)) flat[k] = v;
    const payload = {
      ...flat,
      ...(body.body && typeof body.body === 'object' && !Array.isArray(body.body) ? body.body : {}),
      ...(body.params && typeof body.params === 'object' ? body.params : {}),
    };

    let result: any;
    try {
      result = await handler({ base44, body: payload, params, headers, api_key: apiKey, developer, api, endpoint });
    } catch (e) {
      const msg = String((e as Error).message || e);
      const capacity = /rate limit|allows \d+ requests|quota/i.test(msg);
      return finish(capacity ? 503 : 502, { error: capacity ? 'platform_capacity' : 'handler_error', message: msg.slice(0, 300) },
        capacity ? 'platform_capacity' : 'handler_error', metaBase);
    }

    const status = Number(result && result.status) || 200;
    const rlMeta = {
      limit_per_minute: minuteLimit,
      remaining: rl.minuteRemaining,
      quota_per_day: dayLimit,
      day_remaining: rl.dayRemaining,
    };
    const outBody: any = {
      ok: status < 400,
      status,
      request_id: requestId,
      api: api.slug,
      endpoint: endpoint.slug,
      http_method: req.method,
      response_time_ms: elapsed(),
      data: result && result.body !== undefined ? result.body : result,
      meta: { rate_limit: status < 400 ? rlMeta : { ...rlMeta, retry_after_seconds: 60 } },
    };
    logRow({
      api_id: api.id, api_slug: api.slug, endpoint_id: endpoint.id, endpoint_path: endpoint.path,
      method, status_code: status, success: status < 400,
      error_code: status < 400 ? null : (result && result.body && result.body.error) || 'error',
    });
    return json(status, outBody);
  } catch (e) {
    const msg = String((e as Error).message || e);
    const capacity = /rate limit|allows \d+ requests|quota/i.test(msg);
    return finish(capacity ? 503 : 500, { error: capacity ? 'platform_capacity' : 'internal_error', message: msg.slice(0, 300) },
      capacity ? 'platform_capacity' : 'internal_error');
  }
});
