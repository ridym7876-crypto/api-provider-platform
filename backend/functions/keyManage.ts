// @ts-nocheck
// keyManage — API key lifecycle: create, list, revoke, regenerate.
// Secrets are stored only as SHA-256 hashes. The full key is returned exactly once,
// at creation/regeneration time, and is never retrievable afterwards.
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

function masked(key) {
  return {
    id: key.id,
    name: key.name,
    prefix: key.prefix,
    last4: key.last4,
    masked_key: `${key.prefix}${'*'.repeat(20)}${key.last4 || ''}`,
    status: key.status,
    scopes: key.scopes || [],
    api_slugs: key.api_slugs || [],
    rate_limit_per_minute: key.rate_limit_per_minute,
    daily_quota: key.daily_quota,
    request_count: key.request_count || 0,
    success_count: key.success_count || 0,
    error_count: key.error_count || 0,
    last_used_at: key.last_used_at || null,
    expires_at: key.expires_at || null,
    revoked_at: key.revoked_at || null,
    created_date: key.created_date,
  };
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const raw = req.headers.get('x-developer-token')
      || (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!raw) return err(401, 'missing_token', 'X-Developer-Token header is required.');

    const found = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: await sha256hex(raw) }, { limit: 1 });
    const session = found.items[0];
    if (!session) return err(401, 'invalid_token', 'Session token is invalid.');
    if (session.revoked) return err(401, 'token_revoked', 'Session token has been revoked.');
    if (new Date(session.expires_at).getTime() < Date.now()) return err(401, 'token_expired', 'Session token has expired.');

    const profileFound = await base44.asServiceRole.entities.DeveloperProfile.filter({ email: session.developer_email }, { limit: 1 });
    const developer = profileFound.items[0];
    if (!developer) return err(401, 'profile_missing', 'Developer profile no longer exists.');
    if (developer.status !== 'active') return err(403, 'account_suspended', 'This account is suspended.');

    const input = await req.json().catch(() => ({}));
    const action = String(input.action || 'list');

    if (action === 'list') {
      const keys = await base44.asServiceRole.entities.ApiKey.filter(
        { developer_id: developer.id }, { sort: '-created_date', limit: 200 },
      );
      return json(200, { ok: true, data: { keys: keys.items.map(masked), count: keys.items.length } });
    }

    if (action === 'create' || action === 'regenerate') {
      let name = String(input.name || '').trim().slice(0, 80);
      let scopes = Array.isArray(input.scopes) ? input.scopes.map(String).slice(0, 20) : ['read'];
      let apiSlugs = Array.isArray(input.api_slugs) ? input.api_slugs.map(String).slice(0, 50) : [];
      let rateLimit = Number(input.rate_limit_per_minute) || developer.rate_limit_per_minute || 60;
      let dailyQuota = Number(input.daily_quota) || developer.daily_quota || 10000;
      let rotatedFrom = null;

      if (action === 'regenerate') {
        const targetId = String(input.key_id || '');
        if (!targetId) return err(400, 'missing_key_id', 'key_id is required for regenerate.');
        const targetFound = await base44.asServiceRole.entities.ApiKey.filter({ id: targetId }, { limit: 1 });
        const target = targetFound.items[0];
        if (!target) return err(404, 'key_not_found', 'API key not found.');
        if (target.developer_id !== developer.id) return err(403, 'forbidden', 'You do not own this API key.');
        await base44.asServiceRole.entities.ApiKey.update(target.id, {
          status: 'revoked', revoked_at: new Date().toISOString(),
        });
        rotatedFrom = target.id;
        name = name || target.name || 'Regenerated key';
        scopes = scopes && scopes.length ? scopes : (target.scopes || ['read']);
        apiSlugs = apiSlugs && apiSlugs.length ? apiSlugs : (target.api_slugs || []);
        rateLimit = Number(input.rate_limit_per_minute) || target.rate_limit_per_minute || rateLimit;
        dailyQuota = Number(input.daily_quota) || target.daily_quota || dailyQuota;
      }

      if (!name) name = 'Default key';

      // Enforce a sane ceiling on per-key limits so nobody self-issues unlimited access.
      rateLimit = Math.max(1, Math.min(rateLimit, developer.rate_limit_per_minute || 60));
      dailyQuota = Math.max(1, Math.min(dailyQuota, developer.daily_quota || 10000));

      const activeKeys = await base44.asServiceRole.entities.ApiKey.filter(
        { developer_id: developer.id, status: 'active' }, { limit: 100 },
      );
      if (activeKeys.items.length >= 20) {
        return err(429, 'key_limit_reached', 'Maximum of 20 active API keys per account. Revoke a key first.');
      }

      const secret = toHex(crypto.getRandomValues(new Uint8Array(24)));
      const fullKey = `sk_live_${secret}`;
      const keyRecord = await base44.asServiceRole.entities.ApiKey.create({
        developer_id: developer.id,
        developer_email: developer.email,
        name,
        prefix: 'sk_live_',
        key_hash: await sha256hex(fullKey),
        last4: secret.slice(-4),
        status: 'active',
        scopes,
        api_slugs: apiSlugs,
        rate_limit_per_minute: rateLimit,
        daily_quota: dailyQuota,
        request_count: 0,
        success_count: 0,
        error_count: 0,
        expires_at: input.expires_at ? String(input.expires_at) : null,
        rotated_from: rotatedFrom,
      });

      return json(201, {
        ok: true,
        data: {
          api_key: fullKey,
          warning: 'Store this key now. It is shown only once and cannot be retrieved again.',
          key: masked(keyRecord),
          rotated_from: rotatedFrom,
        },
      });
    }

    if (action === 'revoke') {
      const targetId = String(input.key_id || '');
      if (!targetId) return err(400, 'missing_key_id', 'key_id is required.');
      const targetFound = await base44.asServiceRole.entities.ApiKey.filter({ id: targetId }, { limit: 1 });
      const target = targetFound.items[0];
      if (!target) return err(404, 'key_not_found', 'API key not found.');
      if (target.developer_id !== developer.id) return err(403, 'forbidden', 'You do not own this API key.');
      if (target.status === 'revoked') return err(409, 'already_revoked', 'This key is already revoked.');
      const updated = await base44.asServiceRole.entities.ApiKey.update(target.id, {
        status: 'revoked', revoked_at: new Date().toISOString(),
      });
      return json(200, { ok: true, data: { key: masked(updated) } });
    }

    return err(400, 'unknown_action', `Unknown action: ${action}`);
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
