// @ts-nocheck
// devRegister — create a DeveloperProfile with PBKDF2-hashed password and issue a session token.
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
const PBKDF2_ITERATIONS = 100000;

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const input = await req.json().catch(() => ({}));
    const email = String(input.email || '').trim().toLowerCase();
    const password = String(input.password || '');
    const fullName = String(input.full_name || '').trim();
    const company = String(input.company || '').trim();
    const website = String(input.website || '').trim();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return err(400, 'invalid_email', 'A valid email address is required.');
    if (password.length < 8) return err(400, 'weak_password', 'Password must be at least 8 characters.');
    if (password.length > 200) return err(400, 'invalid_password', 'Password is too long.');

    const existing = await base44.asServiceRole.entities.DeveloperProfile.filter({ email }, { limit: 1 });
    if (existing.items.length > 0) return err(409, 'email_in_use', 'An account already exists for this email.');

    const saltHex = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const passwordHash = `pbkdf2$sha256$${PBKDF2_ITERATIONS}$${saltHex}$${await hashPassword(password, saltHex, PBKDF2_ITERATIONS)}`;

    const profile = await base44.asServiceRole.entities.DeveloperProfile.create({
      email,
      full_name: fullName || email.split('@')[0],
      company,
      website,
      plan: 'free',
      role: 'developer',
      status: 'active',
      password_hash: passwordHash,
      rate_limit_per_minute: 60,
      daily_quota: 10000,
      last_login_at: new Date().toISOString(),
    });

    // Issue a session token. The raw token is returned exactly once; only its hash is stored.
    const rawToken = `dst_${toHex(crypto.getRandomValues(new Uint8Array(24)))}`;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await base44.asServiceRole.entities.DeveloperSession.create({
      developer_id: profile.id,
      developer_email: email,
      token_hash: await sha256hex(rawToken),
      token_prefix: rawToken.slice(0, 12),
      expires_at: expiresAt,
      last_used_at: new Date().toISOString(),
      ip_address: (req.headers.get('x-forwarded-for') || '').split(',')[0].trim(),
      user_agent: (req.headers.get('user-agent') || '').slice(0, 200),
      revoked: false,
    });

    return json(201, {
      ok: true,
      data: {
        token: rawToken,
        token_expires_at: expiresAt,
        developer: {
          id: profile.id,
          email: profile.email,
          full_name: profile.full_name,
          company: profile.company,
          plan: profile.plan,
          role: profile.role,
          status: profile.status,
          rate_limit_per_minute: profile.rate_limit_per_minute,
          daily_quota: profile.daily_quota,
        },
      },
    });
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
