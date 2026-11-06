// @ts-nocheck
// keyManage — API key lifecycle. Branded "MR RIDUY AI" keys. SHA-256 hashes only; secret shown once.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token',
  'Access-Control-Max-Age': '600',
};

const KEY_PREFIX = 'mr_riduy_ai_';

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
function newSecret() {
  const b = new Uint8Array(24);
  crypto.getRandomValues(b);
  return KEY_PREFIX + Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}
function masked(record: any) {
  return {
    id: record.id,
    name: record.name,
    prefix: record.prefix,
    last4: record.last4,
    masked_key: KEY_PREFIX + '*'.repeat(20) + (record.last4 || ''),
    label: 'MR RIDUY AI API',
    status: record.status,
    scopes: record.scopes || [],
    api_slugs: record.api_slugs || [],
    rate_limit_per_minute: record.rate_limit_per_minute,
    daily_quota: record.daily_quota,
    request_count: record.request_count || 0,
    success_count: record.success_count || 0,
    error_count: record.error_count || 0,
    last_used_at: record.last_used_at || null,
    expires_at: record.expires_at || null,
    revoked_at: record.revoked_at || null,
    created_date: record.created_date,
  };
}

async function auth(req: Request, base44: any) {
  const raw = (req.headers.get('x-developer-token') || (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')).trim();
  if (!raw) return { error: err(401, 'missing_token', 'X-Developer-Token header is required.') };
  const found = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: await sha256hex(raw) }, { limit: 1 });
  const s = found.items[0];
  if (!s) return { error: err(401, 'invalid_token', 'Session token is invalid.') };
  if (s.revoked) return { error: err(401, 'token_revoked', 'Session token has been revoked.') };
  if (new Date(s.expires_at).getTime() < Date.now()) return { error: err(401, 'token_expired', 'Session token has expired.') };
  const pf = await base44.asServiceRole.entities.DeveloperProfile.filter({ email: s.developer_email }, { limit: 1 });
  const dev = pf.items[0];
  if (!dev) return { error: err(401, 'profile_missing', 'Developer profile not found.') };
  if (dev.status !== 'active') return { error: err(403, 'account_suspended', 'This account is suspended.') };
  return { dev, session: s };
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  const a = await auth(req, base44);
  if (a.error) return a.error;
  const dev = a.dev;

  let input: any = {};
  try { input = await req.json(); } catch (_) { input = {}; }
  const action = String(input.action || 'list');

  try {
    if (action === 'list') {
      const page = await base44.asServiceRole.entities.ApiKey.filter({ developer_id: dev.id }, { sort: '-created_date', limit: 100 });
      const keys = (page.items || []).map(masked);
      return json(200, { ok: true, data: { keys, count: keys.length, label: 'MR RIDUY AI API' } });
    }

    if (action === 'create') {
      const name = String(input.name || 'Default key').slice(0, 80);
      const apiSlugs = Array.isArray(input.api_slugs) ? input.api_slugs.filter((x: any) => typeof x === 'string') : [];
      const scopes = Array.isArray(input.scopes) && input.scopes.length ? input.scopes.filter((x: any) => typeof x === 'string') : ['read'];
      const active = await base44.asServiceRole.entities.ApiKey.filter({ developer_id: dev.id, status: 'active' }, { limit: 100 });
      if ((active.items || []).length >= 20) return err(400, 'key_limit_reached', 'You can hold at most 20 active keys.');

      const secret = newSecret();
      const record = await base44.asServiceRole.entities.ApiKey.create({
        developer_id: dev.id,
        developer_email: dev.email,
        name,
        prefix: KEY_PREFIX,
        key_hash: await sha256hex(secret),
        last4: secret.slice(-4),
        status: 'active',
        scopes,
        api_slugs: apiSlugs,
        rate_limit_per_minute: Math.max(1, Math.min(Number(input.rate_limit_per_minute) || dev.rate_limit_per_minute || 60, dev.rate_limit_per_minute || 60)),
        daily_quota: Math.max(1, Math.min(Number(input.daily_quota) || dev.daily_quota || 10000, dev.daily_quota || 10000)),
        request_count: 0, success_count: 0, error_count: 0,
      });
      return json(201, {
        ok: true,
        data: {
          api_key: secret,
          label: 'MR RIDUY AI API',
          warning: 'Store this key now. It is shown only once and cannot be retrieved again.',
          key: masked(record),
          rotated_from: null,
        },
      });
    }

    if (action === 'revoke' || action === 'regenerate') {
      const id = String(input.key_id || input.id || '');
      if (!id) return err(400, 'missing_parameter', 'key_id is required.');
      const found = await base44.asServiceRole.entities.ApiKey.filter({ id }, { limit: 1 });
      const existing = found.items[0];
      if (!existing) return err(404, 'key_not_found', 'No such API key.');
      if (existing.developer_id !== dev.id) return err(403, 'forbidden', 'That API key does not belong to your account.');

      if (action === 'revoke') {
        if (existing.status === 'revoked') {
          return json(200, { ok: true, data: { key: masked(existing) } });
        }
        const updated = await base44.asServiceRole.entities.ApiKey.update(existing.id, { status: 'revoked', revoked_at: new Date().toISOString() });
        return json(200, { ok: true, data: { key: masked(updated) } });
      }

      await base44.asServiceRole.entities.ApiKey.update(existing.id, { status: 'revoked', revoked_at: new Date().toISOString() });
      const secret = newSecret();
      const record = await base44.asServiceRole.entities.ApiKey.create({
        developer_id: dev.id,
        developer_email: dev.email,
        name: existing.name,
        prefix: KEY_PREFIX,
        key_hash: await sha256hex(secret),
        last4: secret.slice(-4),
        status: 'active',
        scopes: existing.scopes || ['read'],
        api_slugs: existing.api_slugs || [],
        rate_limit_per_minute: existing.rate_limit_per_minute,
        daily_quota: existing.daily_quota,
        request_count: 0, success_count: 0, error_count: 0,
      });
      return json(201, {
        ok: true,
        data: {
          api_key: secret,
          label: 'MR RIDUY AI API',
          warning: 'The previous key was revoked. Store this new key now; it is shown only once.',
          key: masked(record),
          rotated_from: existing.id,
        },
      });
    }

    return err(400, 'unknown_action', 'action must be list, create, revoke or regenerate.');
  } catch (e) {
    return err(500, 'internal_error', String((e as Error).message || e).slice(0, 300));
  }
});
