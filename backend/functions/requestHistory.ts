// @ts-nocheck
// requestHistory — paginated request log for the calling developer only.
// Ownership is enforced on every query; no cross-developer leakage is possible.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token',
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
    const limit = Math.max(1, Math.min(Number(input.limit) || 50, 200));
    const query = { developer_id: developer.id };
    if (input.api_slug) query.api_slug = String(input.api_slug);
    if (input.key_id) query.api_key_id = String(input.key_id);
    if (typeof input.success === 'boolean') query.success = input.success;
    if (input.status_code !== undefined && input.status_code !== null) query.status_code = Number(input.status_code);
    if (input.source) query.source = String(input.source);

    const page = await base44.asServiceRole.entities.ApiRequestLog.filter(
      query,
      { sort: '-created_date', limit, cursor: input.cursor || undefined },
    );

    const rangeDays = Number(input.range_days) || 0;
    const cutoff = rangeDays > 0 ? Date.now() - rangeDays * 86400000 : 0;
    const items = cutoff
      ? page.items.filter((l) => new Date(l.created_date).getTime() >= cutoff)
      : page.items;

    return json(200, {
      ok: true,
      data: {
        requests: items.map((l) => ({
          id: l.id,
          timestamp: l.created_date,
          request_id: l.request_id,
          api_slug: l.api_slug,
          endpoint_path: l.endpoint_path,
          method: l.method,
          status_code: l.status_code,
          response_time_ms: l.response_time_ms,
          success: l.success,
          error_code: l.error_code || null,
          api_key_id: l.api_key_id,
          api_key_prefix: l.api_key_prefix,
          source: l.source,
          user_agent: l.user_agent,
          ip_address: l.ip_address,
        })),
        count: items.length,
        has_more: page.has_more === true,
        next_cursor: page.next_cursor || null,
        filters: query,
      },
    });
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
