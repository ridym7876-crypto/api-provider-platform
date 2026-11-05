// @ts-nocheck
// categoryManage — API category CRUD. Reads: any developer. Writes: admin only.
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

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const a = await auth(req, base44);
    if (a.error) return a.error;
    const { developer } = a;

    const input = await req.json().catch(() => ({}));
    const action = String(input.action || 'list');

    if (action === 'list') {
      const cats = await base44.asServiceRole.entities.ApiCategory.list({ sort: 'sort_order', limit: 200 });
      const apis = await base44.asServiceRole.entities.ApiService.list({ limit: 500 });
      const counts = {};
      for (const api of apis.items) {
        counts[api.category_slug] = (counts[api.category_slug] || 0) + 1;
      }
      return json(200, {
        ok: true,
        data: {
          categories: cats.items.map((c) => ({ ...c, api_count: counts[c.slug] || 0 })),
          count: cats.items.length,
        },
      });
    }

    if (developer.role !== 'admin') return err(403, 'forbidden', 'Administrator role required.');

    if (action === 'create') {
      const name = String(input.name || '').trim().slice(0, 80);
      if (!name) return err(400, 'missing_name', 'Category name is required.');
      const slug = input.slug ? slugify(input.slug) : slugify(name);
      if (!slug) return err(400, 'invalid_slug', 'Category slug could not be derived.');
      const dupe = await base44.asServiceRole.entities.ApiCategory.filter({ slug }, { limit: 1 });
      if (dupe.items.length > 0) return err(409, 'slug_in_use', `Category slug "${slug}" already exists.`);
      const created = await base44.asServiceRole.entities.ApiCategory.create({
        name,
        slug,
        description: String(input.description || '').slice(0, 500),
        icon: String(input.icon || '').slice(0, 40),
        color: String(input.color || '').slice(0, 20),
        sort_order: Number(input.sort_order) || 0,
        is_active: input.is_active === undefined ? true : !!input.is_active,
      });
      return json(201, { ok: true, data: { category: created } });
    }

    if (action === 'update') {
      const targetId = String(input.id || input.category_id || '');
      if (!targetId) return err(400, 'missing_id', 'id is required.');
      const found = await base44.asServiceRole.entities.ApiCategory.filter({ id: targetId }, { limit: 1 });
      const existing = found.items[0];
      if (!existing) return err(404, 'category_not_found', 'Category not found.');
      const patch = {};
      if (typeof input.name === 'string' && input.name.trim()) patch.name = input.name.trim().slice(0, 80);
      if (typeof input.description === 'string') patch.description = input.description.slice(0, 500);
      if (typeof input.icon === 'string') patch.icon = input.icon.slice(0, 40);
      if (typeof input.color === 'string') patch.color = input.color.slice(0, 20);
      if (input.sort_order !== undefined) patch.sort_order = Number(input.sort_order) || 0;
      if (input.is_active !== undefined) patch.is_active = !!input.is_active;
      if (typeof input.slug === 'string' && input.slug.trim()) {
        const nextSlug = slugify(input.slug);
        if (nextSlug !== existing.slug) {
          const dupe = await base44.asServiceRole.entities.ApiCategory.filter({ slug: nextSlug }, { limit: 1 });
          if (dupe.items.length > 0) return err(409, 'slug_in_use', `Category slug "${nextSlug}" already exists.`);
          patch.slug = nextSlug;
        }
      }
      if (Object.keys(patch).length === 0) return err(400, 'nothing_to_update', 'No valid fields supplied.');
      const updated = await base44.asServiceRole.entities.ApiCategory.update(existing.id, patch);
      if (patch.slug) {
        const linked = await base44.asServiceRole.entities.ApiService.filter({ category_slug: existing.slug }, { limit: 500 });
        for (const api of linked.items) {
          await base44.asServiceRole.entities.ApiService.update(api.id, { category_slug: patch.slug });
        }
      }
      return json(200, { ok: true, data: { category: updated } });
    }

    if (action === 'delete') {
      const targetId = String(input.id || input.category_id || '');
      if (!targetId) return err(400, 'missing_id', 'id is required.');
      const found = await base44.asServiceRole.entities.ApiCategory.filter({ id: targetId }, { limit: 1 });
      const existing = found.items[0];
      if (!existing) return err(404, 'category_not_found', 'Category not found.');
      const inUse = await base44.asServiceRole.entities.ApiService.filter({ category_slug: existing.slug }, { limit: 1 });
      if (inUse.items.length > 0) {
        return err(409, 'category_in_use', 'This category still has APIs assigned. Move or delete them first.');
      }
      await base44.asServiceRole.entities.ApiCategory.delete(existing.id);
      return json(200, { ok: true, data: { deleted: existing.id } });
    }

    return err(400, 'unknown_action', `Unknown action: ${action}`);
  } catch (e) {
    return err(500, 'internal_error', String(e && e.message ? e.message : e));
  }
});
