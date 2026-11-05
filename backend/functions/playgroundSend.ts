// @ts-nocheck
// playgroundSend — executes a REAL request through the public apiGateway on behalf of a
// logged-in developer, using one of their own active keys (authenticated delegation).
// It does not simulate responses: the returned status/body/timing come from the gateway.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token, X-Playground-Key',
  'Access-Control-Max-Age': '600',
};

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
function err(status, code, message) {
  return json(status, { ok: false, error: { code, message } });
}
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
async function sha256hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toHex(new Uint8Array(digest));
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const raw = (req.headers.get('x-developer-token')
      || (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')).trim();
    if (!raw) return err(401, 'missing_token', 'X-Developer-Token header is required.');

    const sessFound = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: await sha256hex(raw) }, { limit: 1 });
    const session = sessFound.items[0];
    if (!session) return err(401, 'invalid_token', 'Session token is invalid.');
    if (session.revoked) return err(401, 'token_revoked', 'Session token has been revoked.');
    if (new Date(session.expires_at).getTime() < Date.now()) return err(401, 'token_expired', 'Session token has expired.');

    const devFound = await base44.asServiceRole.entities.DeveloperProfile.filter({ email: session.developer_email }, { limit: 1 });
    const developer = devFound.items[0];
    if (!developer) return err(401, 'profile_missing', 'Developer profile not found.');
    if (developer.status !== 'active') return err(403, 'account_suspended', 'This account is suspended.');

    const input = await req.json().catch(() => ({}));
    const keyId = String(input.key_id || '');
    if (!keyId) return err(400, 'missing_key_id', 'key_id is required.');

    const keyFound = await base44.asServiceRole.entities.ApiKey.filter({ id: keyId }, { limit: 1 });
    const key = keyFound.items[0];
    if (!key) return err(404, 'key_not_found', 'API key not found.');
    if (key.developer_id !== developer.id) return err(403, 'forbidden', 'You do not own this API key.');
    if (key.status !== 'active') return err(409, 'key_revoked', 'This API key is revoked and cannot be used.');

    const apiSlug = String(input.api_slug || '');
    const endpointSlug = String(input.endpoint_slug || '');
    if (!apiSlug || !endpointSlug) return err(400, 'missing_target', 'api_slug and endpoint_slug are required.');

    const epFound = await base44.asServiceRole.entities.ApiEndpoint.filter({ api_slug: apiSlug, slug: endpointSlug }, { limit: 1 });
    const endpoint = epFound.items[0];
    if (!endpoint) return err(404, 'endpoint_not_found', 'That endpoint does not exist.');

    const params = input.params && typeof input.params === 'object' ? input.params : {};
    const body = input.body && typeof input.body === 'object' ? input.body : {};
    const extraHeaders = input.headers && typeof input.headers === 'object' ? input.headers : {};

    const gatewayUrl = `${new URL(req.url).origin}/functions/apiGateway`;
    const started = performance.now();
    let gwResponse;
    try {
      gwResponse = await fetch(gatewayUrl, {
        method: endpoint.method === 'GET' ? 'GET' : 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Developer-Token': raw,
          'X-Playground-Key': key.id,
          'X-Client-Source': 'playground',
        },
        body: endpoint.method === 'GET' ? undefined : JSON.stringify({ api: apiSlug, endpoint: endpointSlug, params, body }),
      });
    } catch (e) {
      return err(502, 'gateway_unreachable', `Could not reach the gateway: ${String(e && e.message ? e.message : e)}`);
    }

    const text = await gwResponse.text();
    let parsed = null;
    try { parsed = JSON.parse(text); } catch (_) { parsed = { raw: text.slice(0, 2000) }; }
    const elapsed = Math.round((performance.now() - started) * 100) / 100;

    const responseHeaders = {};
    for (const [k, v] of gwResponse.headers.entries()) {
      if (/^(x-ratelimit|x-request-id|retry-after|content-type)/i.test(k)) responseHeaders[k] = v;
    }

    return json(200, {
      ok: true,
      data: {
        executed_through: 'functions/apiGateway',
        simulated: false,
        method: endpoint.method,
        path: endpoint.path,
        sent: { params, body, extra_headers_ignored: Object.keys(extraHeaders) },
        response: {
          status_code: gwResponse.status,
          headers: responseHeaders,
          body: parsed,
        },
        round_trip_ms: elapsed,
      },
    });
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
