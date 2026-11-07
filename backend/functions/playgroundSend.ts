// @ts-nocheck
// playgroundSend — runs a REAL request through the public apiGateway on behalf of a
// signed-in developer, using one of their own active keys. Nothing is simulated.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token',
};

const enc = new TextEncoder();
const hexOf = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hexOf(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const json = (status, body) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json', ...CORS },
});
const fail = (status, code, message) => json(status, { ok: false, error: { code, message } });
const str = (v) => (typeof v === 'string' ? v.trim() : '');
const isCapacity = (msg) => /allows \d+ requests per|rate limit exceeded/i.test(msg);

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  const base44 = createClientFromRequest(req);
  let payload = {};
  try { payload = await req.json(); } catch (_) { return fail(400, 'invalid_json', 'Request body must be valid JSON.'); }

  try {
    const token = str(req.headers.get('x-developer-token')) || str(req.headers.get('authorization')).replace(/^Bearer\s+/i, '');
    if (!token) return fail(401, 'missing_token', 'X-Developer-Token header is required.');

    const sessions = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: await sha(token) }, { limit: 1 });
    const session = sessions.items[0];
    if (!session) return fail(401, 'invalid_token', 'Session token is invalid.');
    if (session.revoked) return fail(401, 'token_revoked', 'Session token has been revoked.');
    if (new Date(session.expires_at).getTime() < Date.now()) return fail(401, 'token_expired', 'Session token has expired.');

    const profiles = await base44.asServiceRole.entities.DeveloperProfile.filter({ email: session.developer_email }, { limit: 1 });
    const developer = profiles.items[0];
    if (!developer) return fail(401, 'profile_missing', 'Developer profile not found.');
    if (developer.status !== 'active') return fail(403, 'account_suspended', 'This account is suspended.');

    const keyId = str(payload.key_id);
    if (!keyId) return fail(400, 'missing_parameter', '"key_id" is required.');
    const keys = await base44.asServiceRole.entities.ApiKey.filter({ id: keyId }, { limit: 1 });
    const key = keys.items[0];
    if (!key || key.developer_id !== developer.id) return fail(403, 'forbidden', 'That API key does not belong to your account.');
    if (key.status !== 'active') return fail(403, 'key_revoked', 'This API key is revoked and cannot be used.');

    const apiSlug = str(payload.api_slug);
    const endpointSlug = str(payload.endpoint_slug);
    const requestBody = payload.body && typeof payload.body === 'object' ? payload.body : {};

    const target = {
      api: apiSlug,
      endpoint: endpointSlug,
      body: requestBody,
    };
    if (isObj(payload.headers)) target.params = payload.headers;

    const started = Date.now();
    let res, text;
    try {
      res = await fetch(new URL(req.url).origin + '/functions/apiGateway', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Developer-Token': token,
          'X-Playground-Key': keyId,
          'X-Client-Source': 'playground',
        },
        body: JSON.stringify(target),
      });
      text = await res.text();
    } catch (e) {
      return fail(502, 'gateway_unreachable', 'Could not reach the gateway: ' + String(e && e.message || e));
    }

    let gatewayBody = {};
    try { gatewayBody = text ? JSON.parse(text) : {}; } catch (_) { gatewayBody = { raw: text }; }

    return json(200, {
      ok: true,
      data: {
        simulated: false,
        executed_by: 'functions/apiGateway',
        request: { api: apiSlug, endpoint: endpointSlug, body: requestBody, api_key_id: keyId },
        response: { status_code: res.status, body: gatewayBody },
        round_trip_ms: Date.now() - started,
      },
    });
  } catch (e) {
    const msg = String(e && e.message || e);
    if (isCapacity(msg)) return fail(503, 'platform_capacity', 'The platform is briefly at capacity. Retry in a few seconds.');
    return fail(500, 'internal_error', msg.slice(0, 300));
  }
});

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }
