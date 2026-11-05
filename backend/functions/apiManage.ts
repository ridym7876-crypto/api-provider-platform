// @ts-nocheck
// apiManage — API product CRUD, activation, deletion. Writes: admin only.
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
const slugify = (value) => String(value || '').toLowerCase().trim()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);

async function auth(req, base44) {
  const raw = req.headers.get('x-developer-token')
    || (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!raw) return { error: err(401, 'missing_token', 'X-Developer-Token header is required.') };
  const found = await base44.asServiceRole.entities.DeveloperSession.filter({ token_hash: await sha256hex(raw) }, { limit: 1 });
  const session = found.items[0];
  if (!session) return { error: err(401, 'invalid_token', 'Session token is invalid.') };
  if (session.revoked) return { error: err(401, 'token_revoked', 'Session token has been revoked.') };
  if (new Date(session.expires_at).getTime() < Date.now()) return { error: err(401, 'token_expired', 'Session token has expired.') };
  const pf = await base44.asServiceRole.entities.DeveloperProfile.filter({ email: session.developer_email }, { limit: 1 });
  const developer = pf.items[0];
  if (!developer) return { error: err(401, 'profile_missing', 'Developer profile not found.') };
  if (developer.status !== 'active') return { error: err(403, 'account_suspended', 'This account is suspended.') };
  return { developer, session };
}

async function loadApi(base44, ref) {
  if (!ref) return null;
  const byId = await base44.asServiceRole.entities.ApiService.filter({ id: ref }, { limit: 1 });
  if (byId.items[0]) return byId.items[0];
  const bySlug = await base44.asServiceRole.entities.ApiService.filter({ slug: ref }, { limit: 1 });
  return bySlug.items[0] || null;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const a = await auth(req, base44);
    if (a.error) return a.error;
    const { developer } = a;
    const isAdmin = developer.role === 'admin';

    const input = await req.json().catch(() => ({}));
    const action = String(input.action || 'list');

    if (action === 'list') {
      const apis = await base44.asServiceRole.entities.ApiService.list({ sort: 'sort_order', limit: 500 });
      const endpoints = await base44.asServiceRole.entities.ApiEndpoint.list({ limit: 1000 });
      const epCount = {};
      for (const ep of endpoints.items) epCount[ep.api_slug] = (epCount[ep.api_slug] || 0) + 1;
      const visible = isAdmin ? apis.items : apis.items.filter((x) => x.status === 'active' && x.is_public !== false);
      return json(200, {
        ok: true,
        data: {
          apis: visible.map((x) => ({ ...x, endpoint_count: epCount[x.slug] || 0 })),
          count: visible.length,
        },
      });
    }

    if (action === 'get') {
      const api = await loadApi(base44, input.slug || input.id || input.api);
      if (!api) return err(404, 'api_not_found', 'API not found.');
      if (!isAdmin && (api.status !== 'active' || api.is_public === false)) {
        return err(404, 'api_not_found', 'API not found.');
      }
      const eps = await base44.asServiceRole.entities.ApiEndpoint.filter({ api_slug: api.slug }, { sort: 'sort_order', limit: 200 });
      return json(200, { ok: true, data: { api, endpoints: eps.items } });
    }

    if (!isAdmin) return err(403, 'forbidden', 'Administrator role required for this action.');

    if (action === 'create') {
      const name = String(input.name || '').trim().slice(0, 100);
      if (!name) return err(400, 'missing_name', 'API name is required.');
      const slug = input.slug ? slugify(input.slug) : slugify(name);
      if (!slug) return err(400, 'invalid_slug', 'API slug could not be derived.');
      const dupe = await base44.asServiceRole.entities.ApiService.filter({ slug }, { limit: 1 });
      if (dupe.items.length > 0) return err(409, 'slug_in_use', `API slug "${slug}" already exists.`);
      const created = await base44.asServiceRole.entities.ApiService.create({
        name,
        slug,
        description: String(input.description || '').slice(0, 500),
        long_description: String(input.long_description || '').slice(0, 5000),
        category_slug: String(input.category_slug || '').slice(0, 60),
        version: String(input.version || 'v1').slice(0, 20),
        base_path: String(input.base_path || `/${slug}`).slice(0, 120),
        status: ['active', 'inactive', 'draft'].includes(input.status) ? input.status : 'draft',
        auth_required: input.auth_required === undefined ? true : !!input.auth_required,
        handler_namespace: String(input.handler_namespace || slug).slice(0, 60),
        default_rate_limit_per_minute: Number(input.default_rate_limit_per_minute) || 60,
        default_daily_quota: Number(input.default_daily_quota) || 10000,
        tags: Array.isArray(input.tags) ? input.tags.map(String).slice(0, 10) : [],
        docs_markdown: String(input.docs_markdown || '').slice(0, 20000),
        contact_email: String(input.contact_email || '').slice(0, 120),
        is_public: input.is_public === undefined ? true : !!input.is_public,
        sort_order: Number(input.sort_order) || 0,
      });
      return json(201, { ok: true, data: { api: created } });
    }

    if (action === 'update') {
      const api = await loadApi(base44, input.slug || input.id || input.api);
      if (!api) return err(404, 'api_not_found', 'API not found.');
      const patch = {};
      const strFields = ['name', 'description', 'long_description', 'category_slug', 'version', 'base_path', 'handler_namespace', 'docs_markdown', 'contact_email'];
      for (const f of strFields) {
        if (typeof input[f] === 'string') patch[f] = input[f].slice(0, f === 'docs_markdown' ? 20000 : 5000);
      }
      if (input.auth_required !== undefined) patch.auth_required = !!input.auth_required;
      if (input.is_public !== undefined) patch.is_public = !!input.is_public;
      if (input.default_rate_limit_per_minute !== undefined) patch.default_rate_limit_per_minute = Math.max(1, Number(input.default_rate_limit_per_minute) || 60);
      if (input.default_daily_quota !== undefined) patch.default_daily_quota = Math.max(1, Number(input.default_daily_quota) || 10000);
      if (input.sort_order !== undefined) patch.sort_order = Number(input.sort_order) || 0;
      if (Array.isArray(input.tags)) patch.tags = input.tags.map(String).slice(0, 10);
      if (typeof input.status === 'string' && ['active', 'inactive', 'draft'].includes(input.status)) patch.status = input.status;
      if (Object.keys(patch).length === 0) return err(400, 'nothing_to_update', 'No valid fields supplied.');
      const updated = await base44.asServiceRole.entities.ApiService.update(api.id, patch);
      return json(200, { ok: true, data: { api: updated } });
    }

    if (action === 'set_status') {
      const api = await loadApi(base44, input.slug || input.id || input.api);
      if (!api) return err(404, 'api_not_found', 'API not found.');
      const status = String(input.status || '');
      if (!['active', 'inactive', 'draft'].includes(status)) return err(400, 'invalid_status', 'status must be active, inactive or draft.');
      const updated = await base44.asServiceRole.entities.ApiService.update(api.id, { status });
      return json(200, { ok: true, data: { api: updated } });
    }

    if (action === 'delete') {
      const api = await loadApi(base44, input.slug || input.id || input.api);
      if (!api) return err(404, 'api_not_found', 'API not found.');
      const eps = await base44.asServiceRole.entities.ApiEndpoint.filter({ api_slug: api.slug }, { limit: 500 });
      for (const ep of eps.items) {
        await base44.asServiceRole.entities.ApiEndpoint.delete(ep.id);
      }
      await base44.asServiceRole.entities.ApiService.delete(api.id);
      return json(200, { ok: true, data: { deleted: api.slug, endpoints_deleted: eps.items.length } });
    }

    return err(400, 'unknown_action', `Unknown action: ${action}`);
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
