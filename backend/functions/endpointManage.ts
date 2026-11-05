// @ts-nocheck
// endpointManage — endpoint CRUD for an API product. Writes: admin only.
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
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

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
      const apiSlug = String(input.api_slug || '');
      if (!apiSlug) return err(400, 'missing_api_slug', 'api_slug is required.');
      const eps = await base44.asServiceRole.entities.ApiEndpoint.filter({ api_slug: apiSlug }, { sort: 'sort_order', limit: 300 });
      const visible = isAdmin ? eps.items : eps.items.filter((x) => x.is_active !== false);
      return json(200, { ok: true, data: { endpoints: visible, count: visible.length } });
    }

    if (!isAdmin) return err(403, 'forbidden', 'Administrator role required for this action.');

    if (action === 'create') {
      const apiSlug = String(input.api_slug || '');
      if (!apiSlug) return err(400, 'missing_api_slug', 'api_slug is required.');
      const apiFound = await base44.asServiceRole.entities.ApiService.filter({ slug: apiSlug }, { limit: 1 });
      const api = apiFound.items[0];
      if (!api) return err(404, 'api_not_found', 'Parent API not found.');
      const method = String(input.method || 'GET').toUpperCase();
      if (!METHODS.includes(method)) return err(400, 'invalid_method', `method must be one of ${METHODS.join(', ')}.`);
      let path = String(input.path || '').trim();
      if (!path.startsWith('/')) return err(400, 'invalid_path', 'path must start with "/".');
      const slug = input.slug ? slugify(input.slug) : slugify(`${method}-${path.replace(/\//g, '-')}`);
      const dupe = await base44.asServiceRole.entities.ApiEndpoint.filter({ api_slug: apiSlug, slug }, { limit: 1 });
      if (dupe.items.length > 0) return err(409, 'slug_in_use', `Endpoint slug "${slug}" already exists in this API.`);
      const created = await base44.asServiceRole.entities.ApiEndpoint.create({
        api_id: api.id,
        api_slug: apiSlug,
        name: String(input.name || `${method} ${path}`).slice(0, 120),
        slug,
        method,
        path: path.slice(0, 200),
        summary: String(input.summary || '').slice(0, 300),
        description: String(input.description || '').slice(0, 5000),
        parameters: Array.isArray(input.parameters) ? input.parameters.slice(0, 50) : [],
        request_headers: Array.isArray(input.request_headers) ? input.request_headers.slice(0, 20) : [],
        request_body_schema: input.request_body_schema && typeof input.request_body_schema === 'object' ? input.request_body_schema : {},
        request_body_example: input.request_body_example && typeof input.request_body_example === 'object' ? input.request_body_example : {},
        response_examples: Array.isArray(input.response_examples) ? input.response_examples.slice(0, 20) : [],
        auth_required: input.auth_required === undefined ? true : !!input.auth_required,
        handler_key: String(input.handler_key || '').slice(0, 80),
        rate_limit_override: Number(input.rate_limit_override) || 0,
        is_active: input.is_active === undefined ? true : !!input.is_active,
        sort_order: Number(input.sort_order) || 0,
      });
      return json(201, { ok: true, data: { endpoint: created } });
    }

    if (action === 'update') {
      const targetId = String(input.id || input.endpoint_id || '');
      if (!targetId) return err(400, 'missing_id', 'id is required.');
      const found = await base44.asServiceRole.entities.ApiEndpoint.filter({ id: targetId }, { limit: 1 });
      const endpoint = found.items[0];
      if (!endpoint) return err(404, 'endpoint_not_found', 'Endpoint not found.');
      const patch = {};
      if (typeof input.name === 'string') patch.name = input.name.slice(0, 120);
      if (typeof input.summary === 'string') patch.summary = input.summary.slice(0, 300);
      if (typeof input.description === 'string') patch.description = input.description.slice(0, 5000);
      if (typeof input.method === 'string') {
        const method = input.method.toUpperCase();
        if (!METHODS.includes(method)) return err(400, 'invalid_method', `method must be one of ${METHODS.join(', ')}.`);
        patch.method = method;
      }
      if (typeof input.path === 'string') {
        if (!input.path.startsWith('/')) return err(400, 'invalid_path', 'path must start with "/".');
        patch.path = input.path.slice(0, 200);
      }
      if (Array.isArray(input.parameters)) patch.parameters = input.parameters.slice(0, 50);
      if (Array.isArray(input.request_headers)) patch.request_headers = input.request_headers.slice(0, 20);
      if (input.request_body_schema && typeof input.request_body_schema === 'object') patch.request_body_schema = input.request_body_schema;
      if (input.request_body_example && typeof input.request_body_example === 'object') patch.request_body_example = input.request_body_example;
      if (Array.isArray(input.response_examples)) patch.response_examples = input.response_examples.slice(0, 20);
      if (input.auth_required !== undefined) patch.auth_required = !!input.auth_required;
      if (typeof input.handler_key === 'string') patch.handler_key = input.handler_key.slice(0, 80);
      if (input.rate_limit_override !== undefined) patch.rate_limit_override = Number(input.rate_limit_override) || 0;
      if (input.is_active !== undefined) patch.is_active = !!input.is_active;
      if (input.sort_order !== undefined) patch.sort_order = Number(input.sort_order) || 0;
      if (Object.keys(patch).length === 0) return err(400, 'nothing_to_update', 'No valid fields supplied.');
      const updated = await base44.asServiceRole.entities.ApiEndpoint.update(endpoint.id, patch);
      return json(200, { ok: true, data: { endpoint: updated } });
    }

    if (action === 'delete') {
      const targetId = String(input.id || input.endpoint_id || '');
      if (!targetId) return err(400, 'missing_id', 'id is required.');
      const found = await base44.asServiceRole.entities.ApiEndpoint.filter({ id: targetId }, { limit: 1 });
      const endpoint = found.items[0];
      if (!endpoint) return err(404, 'endpoint_not_found', 'Endpoint not found.');
      await base44.asServiceRole.entities.ApiEndpoint.delete(endpoint.id);
      return json(200, { ok: true, data: { deleted: endpoint.id } });
    }

    return err(400, 'unknown_action', `Unknown action: ${action}`);
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
