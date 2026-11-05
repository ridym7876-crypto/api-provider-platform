// @ts-nocheck
// apiGateway — THE PUBLIC DATA PLANE.
//
// External developers call this one URL with their secret API key:
//   POST https://<host>/functions/apiGateway
//   X-Api-Key: sk_live_xxxxxxxx
//   { "api": "system", "endpoint": "time", "params": {...}, "body": {...} }
// or route by path:
//   GET  https://<host>/functions/apiGateway?path=/v1/system/time
//
// PERFORMANCE NOTE: the Base44 runtime caps entity operations at ~70 per 60s per caller,
// so this gateway is cache-first. Keys (5s TTL), sessions (10s TTL) and the API/endpoint
// catalog (30s TTL) are memoised per isolate, and rate-limit windows are counted in memory.
// That leaves exactly ONE entity write per request: the audit log row.
// Trade-off: key revocation propagates within ~5s, catalog edits within ~30s, and rate-limit
// counters are per isolate (documented in the report as a Phase 2 durability item).
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token, X-Playground-Key, X-Client-Source',
  'Access-Control-Expose-Headers': 'X-Request-Id, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After',
  'Access-Control-Max-Age': '600',
};
const MAX_BODY_BYTES = 100 * 1024;
const KEY_TTL = 5000;
const SESSION_TTL = 10000;
const CATALOG_TTL = 30000;

const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
async function sha256hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toHex(new Uint8Array(digest));
}
const slugify = (value) => String(value || '').toLowerCase().trim()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

// ---------------------------------------------------------------- isolate caches
const keyCache = new Map();      // key_hash -> { at, record }
const keyByIdCache = new Map();  // key id  -> { at, record }
const devCache = new Map();      // developer id -> { at, record }
const sessionCache = new Map();  // token_hash -> { at, record }
const rateState = new Map();     // key id -> { minuteStart, minuteCount, dayStart, dayCount }
let catalogCache = { at: 0, apis: [], endpoints: [] };

function cacheGet(map, key, ttl) {
  const hit = map.get(key);
  if (hit && Date.now() - hit.at < ttl) return hit.record;
  return null;
}
function cacheSet(map, key, record) {
  if (map.size > 800) map.clear();
  map.set(key, { at: Date.now(), record });
}

async function loadCatalog(base44, force) {
  if (!force && Date.now() - catalogCache.at < CATALOG_TTL) return catalogCache;
  const apis = await base44.asServiceRole.entities.ApiService.list({ limit: 500 });
  const endpoints = await base44.asServiceRole.entities.ApiEndpoint.list({ limit: 1000 });
  catalogCache = { at: Date.now(), apis: apis.items, endpoints: endpoints.items };
  return catalogCache;
}

// In-memory sliding-window limiter (per isolate).
function checkRate(keyId, minuteLimit, dayLimit) {
  const now = Date.now();
  const minuteStart = Math.floor(now / 60000) * 60000;
  const dayStart = Math.floor(now / 86400000) * 86400000;
  if (rateState.size > 2000) rateState.clear();
  let state = rateState.get(keyId);
  if (!state) {
    state = { minuteStart, minuteCount: 0, dayStart, dayCount: 0 };
    rateState.set(keyId, state);
  }
  if (state.minuteStart !== minuteStart) { state.minuteStart = minuteStart; state.minuteCount = 0; }
  if (state.dayStart !== dayStart) { state.dayStart = dayStart; state.dayCount = 0; }
  state.minuteCount += 1;
  state.dayCount += 1;
  return {
    minuteExceeded: state.minuteCount > minuteLimit,
    dayExceeded: state.dayCount > dayLimit,
    minuteRemaining: Math.max(0, minuteLimit - state.minuteCount),
    dayRemaining: Math.max(0, dayLimit - state.dayCount),
  };
}

// ---------------------------------------------------------------- native handlers
const HANDLERS = {
  'system.health': async ({ base44, catalog }) => {
    const started = performance.now();
    await base44.asServiceRole.entities.ApiService.list({ limit: 1 });
    const latency = performance.now() - started;
    return {
      status: 200,
      body: {
        status: 'operational',
        service: 'api-provider-platform',
        database_latency_ms: Math.round(latency * 100) / 100,
        apis_total: catalog.apis.length,
        apis_active: catalog.apis.filter((a) => a.status === 'active').length,
        endpoints_total: catalog.endpoints.length,
        checked_at: new Date().toISOString(),
      },
    };
  },

  'system.time': async () => {
    const now = new Date();
    return {
      status: 200,
      body: {
        utc_iso: now.toISOString(),
        unix_seconds: Math.floor(now.getTime() / 1000),
        unix_ms: now.getTime(),
        timezone: 'UTC',
        weekday: now.toUTCString().split(',')[0],
      },
    };
  },

  'crypto.sha256': async ({ body, params }) => {
    const text = body.text !== undefined ? body.text : params.text;
    if (typeof text !== 'string' || text.length === 0) {
      return { status: 400, body: { error: 'missing_parameter', message: '"text" (non-empty string) is required.' } };
    }
    if (text.length > 50000) {
      return { status: 413, body: { error: 'payload_too_large', message: 'text is limited to 50000 characters.' } };
    }
    return { status: 200, body: { algorithm: 'SHA-256', input_length: text.length, hex: await sha256hex(text) } };
  },

  'crypto.random': async ({ body, params }) => {
    const rawBytes = body.bytes !== undefined ? body.bytes : params.bytes;
    const bytes = rawBytes === undefined ? 32 : Number(rawBytes);
    if (!Number.isInteger(bytes) || bytes < 1 || bytes > 256) {
      return { status: 400, body: { error: 'invalid_parameter', message: '"bytes" must be an integer between 1 and 256.' } };
    }
    const encoding = String(body.encoding || params.encoding || 'hex').toLowerCase();
    if (!['hex', 'base64'].includes(encoding)) {
      return { status: 400, body: { error: 'invalid_parameter', message: '"encoding" must be hex or base64.' } };
    }
    const buffer = crypto.getRandomValues(new Uint8Array(bytes));
    let value;
    if (encoding === 'hex') {
      value = toHex(buffer);
    } else {
      let binary = '';
      for (const b of buffer) binary += String.fromCharCode(b);
      value = btoa(binary);
    }
    return { status: 200, body: { encoding, bytes, value } };
  },

  'text.slugify': async ({ body, params }) => {
    const text = body.text !== undefined ? body.text : params.text;
    if (typeof text !== 'string' || text.trim() === '') {
      return { status: 400, body: { error: 'missing_parameter', message: '"text" (non-empty string) is required.' } };
    }
    const slug = slugify(text).slice(0, 120);
    return { status: 200, body: { input: text, slug, length: slug.length } };
  },

  'text.stats': async ({ body, params }) => {
    const text = body.text !== undefined ? body.text : params.text;
    if (typeof text !== 'string' || text === '') {
      return { status: 400, body: { error: 'missing_parameter', message: '"text" (non-empty string) is required.' } };
    }
    const words = text.trim() === '' ? [] : text.trim().split(/\s+/);
    const unique = new Set(words.map((w) => w.toLowerCase().replace(/[^a-z0-9]/gi, '')).filter(Boolean));
    return {
      status: 200,
      body: {
        characters: text.length,
        characters_no_spaces: text.replace(/\s/g, '').length,
        words: words.length,
        unique_words: unique.size,
        lines: text.split(/\r\n|\r|\n/).length,
        sentences: (text.match(/[.!?]+(\s|$)/g) || []).length || (words.length ? 1 : 0),
      },
    };
  },

  'json.validate': async ({ body, params }) => {
    let candidate = body.json !== undefined ? body.json : params.json;
    if (candidate === undefined) {
      return { status: 400, body: { error: 'missing_parameter', message: '"json" (string) is required.' } };
    }
    if (typeof candidate !== 'string') candidate = JSON.stringify(candidate);
    try {
      const parsed = JSON.parse(candidate);
      return {
        status: 200,
        body: {
          valid: true,
          type: Array.isArray(parsed) ? 'array' : typeof parsed,
          key_count: parsed && typeof parsed === 'object' ? Object.keys(parsed).length : 0,
          parsed,
        },
      };
    } catch (e) {
      return { status: 200, body: { valid: false, error: String(e && e.message ? e.message : e) } };
    }
  },

  'platform.usage': async ({ base44, api_key }) => {
    const logs = await base44.asServiceRole.entities.ApiRequestLog.filter(
      { api_key_id: api_key.id }, { sort: '-created_date', limit: 500 },
    );
    const total = logs.items.length;
    const success = logs.items.filter((l) => l.success).length;
    const times = logs.items.map((l) => Number(l.response_time_ms) || 0).sort((a, b) => a - b);
    const avg = total ? Math.round((times.reduce((s, t) => s + t, 0) / total) * 100) / 100 : 0;
    const p95 = total ? times[Math.min(total - 1, Math.floor(total * 0.95))] : 0;
    // Persist the derived totals onto the key record (one write, only when this endpoint is used).
    try {
      await base44.asServiceRole.entities.ApiKey.update(api_key.id, {
        request_count: total,
        success_count: success,
        error_count: total - success,
        last_used_at: logs.items[0] ? logs.items[0].created_date : api_key.last_used_at,
      });
    } catch (_) { /* best effort */ }
    return {
      status: 200,
      body: {
        api_key_prefix: api_key.prefix,
        key_name: api_key.name,
        window: 'most recent 500 requests',
        total_requests: total,
        successful: success,
        failed: total - success,
        success_rate_percent: total ? Math.round((success / total) * 10000) / 100 : 0,
        avg_response_time_ms: avg,
        p95_response_time_ms: p95,
      },
    };
  },

  'data.apis.list': async ({ catalog }) => {
    const list = catalog.apis
      .filter((a) => a.status === 'active' && a.is_public !== false)
      .map((a) => ({
        name: a.name,
        slug: a.slug,
        description: a.description,
        category: a.category_slug,
        version: a.version,
        base_path: a.base_path,
      }));
    return { status: 200, body: { count: list.length, apis: list } };
  },

  'data.endpoints.list': async ({ catalog, body, params }) => {
    const apiSlug = String(body.api_slug || params.api_slug || '');
    const list = catalog.endpoints
      .filter((e) => e.is_active !== false && (!apiSlug || e.api_slug === apiSlug))
      .map((e) => ({ api: e.api_slug, name: e.name, slug: e.slug, method: e.method, path: e.path, summary: e.summary }));
    return { status: 200, body: { count: list.length, endpoints: list } };
  },

  'echo.request': async ({ body, params, headers, api_key, request }) => {
    const notable = {};
    for (const h of ['content-type', 'user-agent', 'accept-language']) {
      if (headers.get(h)) notable[h] = headers.get(h);
    }
    return {
      status: 200,
      body: {
        authenticated: true,
        api_key_prefix: api_key.prefix,
        http_method: request.method,
        params,
        body,
        notable_headers: notable,
        received_at: new Date().toISOString(),
      },
    };
  },
};

function reply(status, payload, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extraHeaders },
  });
}

function isCapacityError(e) {
  const m = String(e && e.message ? e.message : e);
  return /rate limit|allows \d+ requests per|quota/i.test(m);
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const startedAt = performance.now();
  const base44 = createClientFromRequest(req);
  const requestId = `req_${toHex(crypto.getRandomValues(new Uint8Array(8)))}`;
  const ipAddress = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim();
  const userAgent = (req.headers.get('user-agent') || '').slice(0, 200);
  const clientSource = req.headers.get('x-client-source') === 'playground' ? 'playground' : 'api';
  const url = new URL(req.url);

  let apiKeyRecord = null;
  let developerRecord = null;
  let resolvedApi = null;
  let resolvedEndpoint = null;
  let body = {};

  const writeLog = async (status, errorCode) => {
    try {
      await base44.asServiceRole.entities.ApiRequestLog.create({
        developer_id: developerRecord ? developerRecord.id : null,
        developer_email: developerRecord ? developerRecord.email : null,
        api_key_id: apiKeyRecord ? apiKeyRecord.id : null,
        api_key_prefix: apiKeyRecord ? `${apiKeyRecord.prefix}${apiKeyRecord.last4 || ''}` : null,
        api_id: resolvedApi ? resolvedApi.id : null,
        api_slug: resolvedApi ? resolvedApi.slug : (body.api || null),
        endpoint_id: resolvedEndpoint ? resolvedEndpoint.id : null,
        endpoint_path: resolvedEndpoint ? resolvedEndpoint.path : (body.path || null),
        method: req.method,
        status_code: status,
        response_time_ms: Math.round((performance.now() - startedAt) * 100) / 100,
        success: status >= 200 && status < 400,
        error_code: errorCode,
        ip_address: ipAddress,
        user_agent: userAgent,
        request_id: requestId,
        source: clientSource,
      });
    } catch (_) { /* audit logging is best effort; never fail the caller */ }
  };

  const finish = async (status, payload, headers = {}, errorCode = null) => {
    await writeLog(status, errorCode);
    return reply(status, payload, { ...headers, 'X-Request-Id': requestId });
  };

  try {
    // ---- parse input
    const rawText = req.method === 'GET' || req.method === 'DELETE' ? '' : await req.text();
    if (rawText) {
      if (rawText.length > MAX_BODY_BYTES) {
        return finish(413, { ok: false, error: { code: 'payload_too_large', message: 'Request body exceeds 100KB.' }, request_id: requestId }, {}, 'payload_too_large');
      }
      try {
        body = JSON.parse(rawText);
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          return finish(400, { ok: false, error: { code: 'invalid_body', message: 'JSON body must be an object.' }, request_id: requestId }, {}, 'invalid_body');
        }
      } catch (_) {
        return finish(400, { ok: false, error: { code: 'invalid_json', message: 'Request body is not valid JSON.' }, request_id: requestId }, {}, 'invalid_json');
      }
    }

    const params = {};
    for (const [k, v] of url.searchParams.entries()) params[k] = v;

    // ---- 1. authenticate
    const rawKey = (req.headers.get('x-api-key')
      || (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')).trim();
    const sessionHeader = (req.headers.get('x-developer-token') || '').trim();
    const delegatedKeyId = (req.headers.get('x-playground-key') || '').trim();

    if (rawKey) {
      if (!rawKey.startsWith('sk_live_')) {
        return finish(401, { ok: false, error: { code: 'invalid_api_key', message: 'API key format is not recognised.' }, request_id: requestId }, {}, 'invalid_api_key');
      }
      const hash = await sha256hex(rawKey);
      apiKeyRecord = cacheGet(keyCache, hash, KEY_TTL);
      if (!apiKeyRecord) {
        const keyFound = await base44.asServiceRole.entities.ApiKey.filter({ key_hash: hash }, { limit: 1 });
        apiKeyRecord = keyFound.items[0] || null;
        if (apiKeyRecord) cacheSet(keyCache, hash, apiKeyRecord);
      }
      if (!apiKeyRecord) {
        return finish(401, { ok: false, error: { code: 'invalid_api_key', message: 'API key is invalid or has been revoked.' }, request_id: requestId }, {}, 'invalid_api_key');
      }
    } else if (sessionHeader && delegatedKeyId) {
      const sHash = await sha256hex(sessionHeader);
      let session = cacheGet(sessionCache, sHash, SESSION_TTL);
      if (!session) {
        const sessFound = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: sHash }, { limit: 1 });
        session = sessFound.items[0] || null;
        if (session) cacheSet(sessionCache, sHash, session);
      }
      if (!session || session.revoked || new Date(session.expires_at).getTime() < Date.now()) {
        return finish(401, { ok: false, error: { code: 'invalid_session', message: 'Developer session token is invalid or expired.' }, request_id: requestId }, {}, 'invalid_session');
      }
      apiKeyRecord = cacheGet(keyByIdCache, delegatedKeyId, KEY_TTL);
      if (!apiKeyRecord) {
        const keyFound = await base44.asServiceRole.entities.ApiKey.filter({ id: delegatedKeyId }, { limit: 1 });
        apiKeyRecord = keyFound.items[0] || null;
        if (apiKeyRecord) cacheSet(keyByIdCache, delegatedKeyId, apiKeyRecord);
      }
      if (!apiKeyRecord || apiKeyRecord.developer_id !== session.developer_id) {
        return finish(403, { ok: false, error: { code: 'forbidden', message: 'That API key does not belong to your account.' }, request_id: requestId }, {}, 'forbidden');
      }
    } else {
      return finish(401, {
        ok: false,
        error: { code: 'missing_api_key', message: 'Provide your secret key in the X-Api-Key header.' },
        request_id: requestId,
      }, {}, 'missing_api_key');
    }

    if (apiKeyRecord.status !== 'active') {
      return finish(403, { ok: false, error: { code: 'key_revoked', message: 'This API key has been revoked.' }, request_id: requestId }, {}, 'key_revoked');
    }
    if (apiKeyRecord.expires_at && new Date(apiKeyRecord.expires_at).getTime() < Date.now()) {
      return finish(403, { ok: false, error: { code: 'key_expired', message: 'This API key has expired.' }, request_id: requestId }, {}, 'key_expired');
    }

    // ---- 2. developer state
    developerRecord = cacheGet(devCache, apiKeyRecord.developer_id, CATALOG_TTL);
    if (!developerRecord) {
      const devFound = await base44.asServiceRole.entities.DeveloperProfile.filter({ id: apiKeyRecord.developer_id }, { limit: 1 });
      developerRecord = devFound.items[0] || null;
      if (developerRecord) cacheSet(devCache, apiKeyRecord.developer_id, developerRecord);
    }
    if (!developerRecord) {
      return finish(403, { ok: false, error: { code: 'developer_not_found', message: 'The owning developer account no longer exists.' }, request_id: requestId }, {}, 'developer_not_found');
    }
    if (developerRecord.status !== 'active') {
      return finish(403, { ok: false, error: { code: 'account_suspended', message: 'This developer account is suspended.' }, request_id: requestId }, {}, 'account_suspended');
    }

    // ---- 3. resolve api + endpoint from the cached catalog
    const catalog = await loadCatalog(base44, false);
    const apiRef = String(body.api || params.api || '').trim();
    const endpointRef = String(body.endpoint || params.endpoint || '').trim();
    const pathRef = String(body.path || params.path || '').trim();

    if (apiRef) {
      resolvedApi = catalog.apis.find((a) => a.slug === apiRef) || null;
    } else if (pathRef) {
      resolvedApi = catalog.apis
        .filter((a) => a.base_path && (pathRef === a.base_path || pathRef.startsWith(`${a.base_path}/`)))
        .sort((a, b) => (b.base_path || '').length - (a.base_path || '').length)[0] || null;
    }

    if (!resolvedApi) {
      return finish(404, {
        ok: false,
        error: { code: 'api_not_found', message: 'Unknown API. Send {"api":"<slug>","endpoint":"<slug>"} or ?path=/your/path.' },
        request_id: requestId,
      }, {}, 'api_not_found');
    }
    if (resolvedApi.status !== 'active') {
      return finish(403, { ok: false, error: { code: 'api_inactive', message: `API "${resolvedApi.slug}" is not currently active.` }, request_id: requestId }, {}, 'api_inactive');
    }

    const keyAllowlist = Array.isArray(apiKeyRecord.api_slugs) ? apiKeyRecord.api_slugs : [];
    if (keyAllowlist.length > 0 && !keyAllowlist.includes(resolvedApi.slug)) {
      return finish(403, {
        ok: false,
        error: { code: 'api_not_permitted', message: `This API key is not scoped to "${resolvedApi.slug}".` },
        request_id: requestId,
      }, {}, 'api_not_permitted');
    }

    resolvedEndpoint = endpointRef
      ? catalog.endpoints.find((e) => e.api_slug === resolvedApi.slug && e.slug === endpointRef) || null
      : catalog.endpoints.find((e) => e.api_slug === resolvedApi.slug && e.path === pathRef) || null;

    if (!resolvedEndpoint) {
      return finish(404, { ok: false, error: { code: 'endpoint_not_found', message: 'Unknown endpoint for this API.' }, request_id: requestId }, {}, 'endpoint_not_found');
    }
    if (resolvedEndpoint.is_active === false) {
      return finish(403, { ok: false, error: { code: 'endpoint_inactive', message: 'This endpoint is disabled.' }, request_id: requestId }, {}, 'endpoint_inactive');
    }
    if (req.method !== resolvedEndpoint.method && req.method !== 'POST') {
      return finish(405, {
        ok: false,
        error: { code: 'method_not_allowed', message: `This endpoint accepts ${resolvedEndpoint.method}.` },
        request_id: requestId,
      }, { Allow: resolvedEndpoint.method }, 'method_not_allowed');
    }

    // ---- 4. rate limiting
    const minuteLimit = Number(
      resolvedEndpoint.rate_limit_override
        || apiKeyRecord.rate_limit_per_minute
        || resolvedApi.default_rate_limit_per_minute
        || developerRecord.rate_limit_per_minute
        || 60,
    );
    const dayLimit = Number(apiKeyRecord.daily_quota || resolvedApi.default_daily_quota || developerRecord.daily_quota || 10000);
    const rl = checkRate(apiKeyRecord.id, minuteLimit, dayLimit);

    if (rl.minuteExceeded) {
      return finish(429, {
        ok: false,
        error: { code: 'rate_limit_exceeded', message: `Rate limit of ${minuteLimit} requests/minute exceeded. Retry shortly.` },
        request_id: requestId,
        rate_limit: { limit: minuteLimit, remaining: 0, window: 'minute' },
      }, { 'Retry-After': '60', 'X-RateLimit-Limit': String(minuteLimit), 'X-RateLimit-Remaining': '0' }, 'rate_limit_exceeded');
    }
    if (rl.dayExceeded) {
      return finish(429, {
        ok: false,
        error: { code: 'daily_quota_exceeded', message: `Daily quota of ${dayLimit} requests exceeded.` },
        request_id: requestId,
        rate_limit: { limit: dayLimit, remaining: 0, window: 'day' },
      }, { 'X-RateLimit-Limit': String(dayLimit), 'X-RateLimit-Remaining': '0' }, 'daily_quota_exceeded');
    }

    // ---- 5. dispatch
    const handlerKey = resolvedEndpoint.handler_key || '';
    const handler = HANDLERS[handlerKey];
    let result;
    if (!handler) {
      result = {
        status: 501,
        body: {
          error: 'handler_not_implemented',
          message: handlerKey
            ? `No native handler is registered for "${handlerKey}" yet.`
            : 'This endpoint has no handler_key assigned.',
          hint: 'Register the handler in the apiGateway HANDLERS map (Phase 2 native API work).',
        },
      };
    } else {
      try {
        result = await handler({
          base44, body, params, headers: req.headers,
          api_key: apiKeyRecord, developer: developerRecord, request: req, catalog,
        });
      } catch (e) {
        result = isCapacityError(e)
          ? { status: 503, body: { error: 'platform_capacity', message: 'Upstream capacity limit reached. Retry shortly.' } }
          : { status: 500, body: { error: 'handler_error', message: String(e && e.message ? e.message : e) } };
      }
    }

    const isSuccess = result.status >= 200 && result.status < 400;
    return finish(result.status, {
      ok: isSuccess,
      status: result.status,
      request_id: requestId,
      api: resolvedApi.slug,
      endpoint: resolvedEndpoint.slug,
      http_method: req.method,
      response_time_ms: Math.round((performance.now() - startedAt) * 100) / 100,
      data: result.body,
      meta: {
        rate_limit: { limit: minuteLimit, remaining: rl.minuteRemaining, window: 'minute' },
        daily_quota: { limit: dayLimit, remaining: rl.dayRemaining, window: 'day' },
      },
    }, {
      'X-RateLimit-Limit': String(minuteLimit),
      'X-RateLimit-Remaining': String(rl.minuteRemaining),
    }, isSuccess ? null : ((result.body && result.body.error) || 'handler_error'));
  } catch (e) {
    const capacity = isCapacityError(e);
    return finish(capacity ? 503 : 500, {
      ok: false,
      error: {
        code: capacity ? 'platform_capacity' : 'gateway_error',
        message: capacity
          ? 'Upstream capacity limit reached. Retry shortly.'
          : String(e && e.message ? e.message : e),
      },
      request_id: requestId,
    }, capacity ? { 'Retry-After': '20' } : {}, capacity ? 'platform_capacity' : 'gateway_error');
  }
});
