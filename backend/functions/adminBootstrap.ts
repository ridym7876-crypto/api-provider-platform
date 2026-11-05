// @ts-nocheck
// adminBootstrap — one-time creation of the first platform administrator.
// Refuses permanently once any admin profile exists.
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

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const existingAdmins = await base44.asServiceRole.entities.DeveloperProfile.filter({ role: 'admin' }, { limit: 1 });
    if (existingAdmins.items.length > 0) {
      return err(403, 'admin_exists', 'An administrator already exists. This endpoint is disabled.');
    }

    const input = await req.json().catch(() => ({}));
    const email = String(input.email || '').trim().toLowerCase();
    const password = String(input.password || '');
    const fullName = String(input.full_name || 'Platform Administrator').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return err(400, 'invalid_email', 'A valid email address is required.');
    if (password.length < 10) return err(400, 'weak_password', 'Admin password must be at least 10 characters.');

    const saltHex = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const iterations = 100000;
    const profile = await base44.asServiceRole.entities.DeveloperProfile.create({
      email,
      full_name: fullName,
      plan: 'enterprise',
      role: 'admin',
      status: 'active',
      password_hash: `pbkdf2$sha256$${iterations}$${saltHex}$${await hashPassword(password, saltHex, iterations)}`,
      rate_limit_per_minute: 600,
      daily_quota: 1000000,
      last_login_at: new Date().toISOString(),
    });

    const rawToken = `dst_${toHex(crypto.getRandomValues(new Uint8Array(24)))}`;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await base44.asServiceRole.entities.DeveloperSession.create({
      developer_id: profile.id,
      developer_email: email,
      token_hash: await sha256hex(rawToken),
      token_prefix: rawToken.slice(0, 12),
      expires_at: expiresAt,
      last_used_at: new Date().toISOString(),
      revoked: false,
    });

    return json(201, {
      ok: true,
      data: {
        token: rawToken,
        token_expires_at: expiresAt,
        developer: { id: profile.id, email: profile.email, role: profile.role, plan: profile.plan },
      },
    });
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
