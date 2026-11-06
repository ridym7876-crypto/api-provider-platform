// @ts-nocheck
// playgroundSend — runs a REAL request through the public apiGateway for a signed-in developer,
// using one of their own active keys (authenticated delegation). Nothing is simulated.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token',
  'Access-Control-Max-Age': '600',
};

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}
function err(status: number, code: string, message: string) {
  return json(status, { ok: false, error: { code, message } });
}
async function sha256hex(s: string) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function isCapacity(msg: string) {
  return /rate limit|allows \d+ requests|quota/i.test(msg);
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);

  try {
    const rawToken = (req.headers.get('x-developer-token') || (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')).trim();
    if (!rawToken) return err(401, 'missing_token', 'Sign in to use the playground.');

    const sessions = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: await sha256hex(rawToken) }, { limit: 1 });
    const session = sessions.items[0];
    if (!session) return err(401, 'invalid_token', 'Session token is invalid.');
    if (session.revoked) return err(401, 'token_revoked', 'Session token has been revoked.');
    if (new Date(session.expires_at).getTime() < Date.now()) return err(401, 'token_expired', 'Session token has expired.');

    let input: any = {};
    try { input = await req.json(); } catch (_) { input = {}; }

    const keyId = String(input.key_id || '');
    const apiSlug = String(input.api_slug || '');
    const endpointSlug = String(input.endpoint_slug || input.endpoint || '');
    if (!keyId) return err(400, 'missing_parameter', 'key_id is required.');
    if (!apiSlug || !endpointSlug) return err(400, 'missing_parameter', 'api_slug and endpoint_slug are required.');

    const keys = await base44.asServiceRole.entities.ApiKey.filter({ id: keyId }, { limit: 1 });
    const key = keys.items[0];
    if (!key) return err(404, 'key_not_found', 'No such API key.');
    if (key.developer_id !== session.developer_id) return err(403, 'forbidden', 'That API key does not belong to your account.');
    if (key.status !== 'active') return err(403, 'key_revoked', 'This API key is revoked. Rotate it to get a working secret.');

    const payloadObj = input.body && typeof input.body === 'object' && !Array.isArray(input.body) ? input.body : {};
    const gatewayPayload: any = { api: apiSlug, endpoint: endpointSlug, body: payloadObj };
    if (input.params && typeof input.params === 'object') gatewayPayload.params = input.params;
    if (input.path) gatewayPayload.path = String(input.path);

    const origin = new URL(req.url).origin;
    const started = Date.now();
    const res = await fetch(origin + '/functions/apiGateway', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Developer-Token': rawToken,
        'X-Playground-Key': keyId,
        'X-Client-Source': 'playground',
      },
      body: JSON.stringify(gatewayPayload),
    });
    const roundTrip = Date.now() - started;
    let gw: any = {};
    try { gw = await res.json(); } catch (_) { gw = {}; }

    if (!res.ok && isCapacity(String((gw && gw.error && gw.error.message) || ''))) {
      return err(503, 'platform_capacity', 'The platform is momentarily at its request ceiling. Retry in a few seconds.');
    }

    return json(200, {
      ok: true,
      data: {
        request: { api: apiSlug, endpoint: endpointSlug, body: payloadObj },
        response: {
          status_code: res.status,
          success: res.status < 400,
          headers: { 'content-type': 'application/json' },
          body: gw,
        },
        round_trip_ms: roundTrip,
        source: 'playground',
      },
    });
  } catch (e) {
    const msg = String((e as Error).message || e);
    if (isCapacity(msg)) return err(503, 'platform_capacity', 'The platform is momentarily at its request ceiling. Retry in a few seconds.');
    return err(500, 'internal_error', msg.slice(0, 300));
  }
});
