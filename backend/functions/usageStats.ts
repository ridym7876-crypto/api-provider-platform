// @ts-nocheck
// usageStats — real usage analytics for the calling developer, computed from ApiRequestLog.
// Ownership is enforced: only the developer's own logs are ever scanned.
import { createClientFromRequest } from 'npm:@base44/sdk@0.8.54';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Api-Key, X-Developer-Token',
  'Access-Control-Max-Age': '600',
};
const SCAN_CAP = 5000;

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
    const rangeDays = Math.max(1, Math.min(Number(input.range_days) || 30, 365));
    const fromIso = new Date(Date.now() - rangeDays * 86400000).toISOString();

    const baseQuery = { developer_id: developer.id };
    if (input.api_slug) baseQuery.api_slug = String(input.api_slug);
    if (input.key_id) baseQuery.api_key_id = String(input.key_id);

    // Page through the developer's own logs, capped for safety.
    const logs = [];
    let truncated = false;
    let cursor = undefined;
    for (;;) {
      const page = await base44.asServiceRole.entities.ApiRequestLog.filter(
        baseQuery, { sort: '-created_date', limit: 500, cursor },
      );
      for (const item of page.items) logs.push(item);
      if (logs.length >= SCAN_CAP) { truncated = page.has_more === true; break; }
      if (!page.has_more) break;
      cursor = page.next_cursor;
      if (!cursor) break;
    }

    const inRange = logs.filter((l) => new Date(l.created_date).getTime() >= new Date(fromIso).getTime());

    const byEndpoint = {};
    const byKey = {};
    const byDay = {};
    const byStatus = {};
    const times = [];
    let success = 0;

    for (const log of inRange) {
      const ok = !!log.success;
      if (ok) success++;
      times.push(Number(log.response_time_ms) || 0);

      const epKey = `${log.method || 'GET'} ${log.endpoint_path || 'unknown'}`;
      if (!byEndpoint[epKey]) byEndpoint[epKey] = { endpoint: epKey, api_slug: log.api_slug || null, requests: 0, success: 0, failed: 0, total_ms: 0 };
      byEndpoint[epKey].requests++;
      byEndpoint[epKey][ok ? 'success' : 'failed']++;
      byEndpoint[epKey].total_ms += Number(log.response_time_ms) || 0;

      const kKey = log.api_key_id || 'unknown';
      if (!byKey[kKey]) byKey[kKey] = { key_id: kKey, label: log.api_key_prefix || 'unknown', requests: 0, success: 0, failed: 0, total_ms: 0 };
      byKey[kKey].requests++;
      byKey[kKey][ok ? 'success' : 'failed']++;
      byKey[kKey].total_ms += Number(log.response_time_ms) || 0;

      const day = String(log.created_date).slice(0, 10);
      if (!byDay[day]) byDay[day] = { date: day, requests: 0, success: 0, failed: 0, total_ms: 0 };
      byDay[day].requests++;
      byDay[day][ok ? 'success' : 'failed']++;
      byDay[day].total_ms += Number(log.response_time_ms) || 0;

      const st = String(log.status_code || 0);
      byStatus[st] = (byStatus[st] || 0) + 1;
    }

    times.sort((a, b) => a - b);
    const total = inRange.length;
    const avg = total ? Math.round((times.reduce((s, t) => s + t, 0) / total) * 100) / 100 : 0;
    const pick = (q) => (total ? times[Math.min(total - 1, Math.floor(total * q))] : 0);

    const finishAgg = (obj) => Object.values(obj).map((v) => ({
      ...v,
      success_rate_percent: v.requests ? Math.round((v.success / v.requests) * 10000) / 100 : 0,
      avg_response_time_ms: v.requests ? Math.round((v.total_ms / v.requests) * 100) / 100 : 0,
      total_ms: undefined,
    })).sort((a, b) => b.requests - a.requests);

    return json(200, {
      ok: true,
      data: {
        range: { days: rangeDays, from: fromIso, to: new Date().toISOString() },
        scan: { scanned_records: logs.length, in_range: total, cap: SCAN_CAP, truncated },
        totals: {
          requests: total,
          successful: success,
          failed: total - success,
          success_rate_percent: total ? Math.round((success / total) * 10000) / 100 : 0,
          avg_response_time_ms: avg,
          min_response_time_ms: total ? times[0] : 0,
          p50_response_time_ms: pick(0.5),
          p95_response_time_ms: pick(0.95),
          max_response_time_ms: total ? times[total - 1] : 0,
        },
        by_endpoint: finishAgg(byEndpoint),
        by_key: finishAgg(byKey),
        by_status: Object.entries(byStatus).map(([status_code, count]) => ({ status_code: Number(status_code), count })).sort((a, b) => b.count - a.count),
        by_day: Object.values(byDay).map((d) => ({
          date: d.date,
          requests: d.requests,
          success: d.success,
          failed: d.failed,
          avg_response_time_ms: d.requests ? Math.round((d.total_ms / d.requests) * 100) / 100 : 0,
        })).sort((a, b) => (a.date < b.date ? -1 : 1)),
      },
    });
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
