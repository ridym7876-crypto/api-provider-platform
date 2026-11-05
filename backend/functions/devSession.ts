// @ts-nocheck
// devSession — developer profile read, logout, profile update, password change.
// Auth: X-Developer-Token header (session token issued by devLogin / devRegister).
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
const fromHex = (hex) => new Uint8Array(hex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));

async function sha256hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toHex(new Uint8Array(digest));
}
async function hashPassword(password, saltHex, iterations) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromHex(saltHex), iterations, hash: 'SHA-256' },
    keyMaterial,
    256,
  );
  return toHex(new Uint8Array(bits));
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function publicProfile(p) {
  return {
    id: p.id,
    email: p.email,
    full_name: p.full_name,
    company: p.company,
    website: p.website,
    plan: p.plan,
    role: p.role,
    status: p.status,
    rate_limit_per_minute: p.rate_limit_per_minute,
    daily_quota: p.daily_quota,
    last_login_at: p.last_login_at,
    created_date: p.created_date,
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
    if (new Date(session.expires_at).getTime() < Date.now()) return err(401, 'token_expired', 'Session token has expired. Please log in again.');

    const profileFound = await base44.asServiceRole.entities.DeveloperProfile.filter({ email: session.developer_email }, { limit: 1 });
    const profile = profileFound.items[0];
    if (!profile) return err(401, 'profile_missing', 'Developer profile no longer exists.');
    if (profile.status !== 'active') return err(403, 'account_suspended', 'This account is suspended.');

    await base44.asServiceRole.entities.DeveloperSession.update(session.id, { last_used_at: new Date().toISOString() });

    const input = await req.json().catch(() => ({}));
    const action = String(input.action || 'me');

    if (action === 'me') {
      const keys = await base44.asServiceRole.entities.ApiKey.filter({ developer_id: profile.id }, { limit: 100 });
      const activeKeys = keys.items.filter((k) => k.status === 'active').length;
      const recent = await base44.asServiceRole.entities.ApiRequestLog.filter(
        { developer_id: profile.id }, { sort: '-created_date', limit: 500 },
      );
      const dayStart = new Date();
      dayStart.setUTCHours(0, 0, 0, 0);
      const todayLogs = recent.items.filter((l) => new Date(l.created_date).getTime() >= dayStart.getTime());
      return json(200, {
        ok: true,
        data: {
          developer: publicProfile(profile),
          session: { expires_at: session.expires_at, token_prefix: session.token_prefix },
          overview: {
            total_keys: keys.items.length,
            active_keys: activeKeys,
            requests_last_500: recent.items.length,
            requests_today_scanned: todayLogs.length,
            success_today_scanned: todayLogs.filter((l) => l.success).length,
            failed_today_scanned: todayLogs.filter((l) => !l.success).length,
          },
        },
      });
    }

    if (action === 'logout') {
      await base44.asServiceRole.entities.DeveloperSession.update(session.id, { revoked: true });
      return json(200, { ok: true, data: { message: 'Session revoked.' } });
    }

    if (action === 'update_profile') {
      const patch = {};
      if (typeof input.full_name === 'string') patch.full_name = input.full_name.trim().slice(0, 120);
      if (typeof input.company === 'string') patch.company = input.company.trim().slice(0, 120);
      if (typeof input.website === 'string') patch.website = input.website.trim().slice(0, 200);
      if (Object.keys(patch).length === 0) return err(400, 'nothing_to_update', 'Provide full_name, company or website.');
      const updated = await base44.asServiceRole.entities.DeveloperProfile.update(profile.id, patch);
      return json(200, { ok: true, data: { developer: publicProfile(updated) } });
    }

    if (action === 'change_password') {
      const current = String(input.current_password || '');
      const next = String(input.new_password || '');
      if (next.length < 8) return err(400, 'weak_password', 'New password must be at least 8 characters.');
      const parts = String(profile.password_hash || '').split('$');
      if (parts.length !== 5) return err(400, 'no_password_set', 'This account has no password credential.');
      const computed = await hashPassword(current, parts[3], parseInt(parts[2], 10));
      if (!safeEqual(computed, parts[4])) return err(403, 'invalid_current_password', 'Current password is incorrect.');
      const saltHex = toHex(crypto.getRandomValues(new Uint8Array(16)));
      const iterations = 100000;
      const newHash = `pbkdf2$sha256$${iterations}$${saltHex}$${await hashPassword(next, saltHex, iterations)}`;
      await base44.asServiceRole.entities.DeveloperProfile.update(profile.id, { password_hash: newHash });
      // Revoke every other session for this developer.
      const sessions = await base44.asServiceRole.entities.DeveloperSession.filter({ developer_email: profile.email }, { limit: 100 });
      for (const s of sessions.items) {
        if (s.id !== session.id && !s.revoked) {
          await base44.asServiceRole.entities.DeveloperSession.update(s.id, { revoked: true });
        }
      }
      return json(200, { ok: true, data: { message: 'Password updated. Other sessions were revoked.' } });
    }

    return err(400, 'unknown_action', `Unknown action: ${action}`);
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
