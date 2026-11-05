// @ts-nocheck
// devLogin — verify PBKDF2 password, rate-limit failed attempts, issue session token.
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

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const input = await req.json().catch(() => ({}));
    const email = String(input.email || '').trim().toLowerCase();
    const password = String(input.password || '');
    if (!email || !password) return err(400, 'missing_credentials', 'Email and password are required.');

    const ipAddress = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';

    // Brute-force protection: max 10 failed attempts per email+IP per 15 minutes.
    const windowKey = `login:${email}:${ipAddress}:${Math.floor(Date.now() / 900000)}`;
    const attempts = await base44.asServiceRole.entities.ApiRateLimitCounter.filter({ scope_key: windowKey }, { limit: 1 });
    const currentAttempts = attempts.items[0] ? Number(attempts.items[0].count || 0) : 0;
    if (currentAttempts >= 10) {
      return err(429, 'too_many_attempts', 'Too many failed login attempts. Try again in 15 minutes.');
    }

    const found = await base44.asServiceRole.entities.DeveloperProfile.filter({ email }, { limit: 1 });
    const profile = found.items[0];

    let passwordOk = false;
    if (profile && typeof profile.password_hash === 'string') {
      const parts = profile.password_hash.split('$');
      if (parts.length === 5 && parts[0] === 'pbkdf2' && parts[1] === 'sha256') {
        const iterations = parseInt(parts[2], 10);
        const computed = await hashPassword(password, parts[3], iterations);
        passwordOk = safeEqual(computed, parts[4]);
      }
    }

    if (!profile || !passwordOk) {
      if (attempts.items[0]) {
        await base44.asServiceRole.entities.ApiRateLimitCounter.update(attempts.items[0].id, { count: currentAttempts + 1 });
      } else {
        await base44.asServiceRole.entities.ApiRateLimitCounter.create({
          scope_key: windowKey, window_type: 'minute', window_start: new Date().toISOString(), count: 1,
        });
      }
      return err(401, 'invalid_credentials', 'Invalid email or password.');
    }
    if (profile.status !== 'active') {
      return err(403, 'account_suspended', 'This account is suspended. Contact the platform administrator.');
    }

    const rawToken = `dst_${toHex(crypto.getRandomValues(new Uint8Array(24)))}`;
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await base44.asServiceRole.entities.DeveloperSession.create({
      developer_id: profile.id,
      developer_email: profile.email,
      token_hash: await sha256hex(rawToken),
      token_prefix: rawToken.slice(0, 12),
      expires_at: expiresAt,
      last_used_at: new Date().toISOString(),
      ip_address: ipAddress,
      user_agent: (req.headers.get('user-agent') || '').slice(0, 200),
      revoked: false,
    });
    await base44.asServiceRole.entities.DeveloperProfile.update(profile.id, { last_login_at: new Date().toISOString() });

    return json(200, {
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
