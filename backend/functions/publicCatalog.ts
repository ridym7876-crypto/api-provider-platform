// @ts-nocheck
// publicCatalog — unauthenticated developer-portal catalog: categories + active public APIs.
// Emits documentation-safe fields only. No secrets, no private records.
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

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const cats = await base44.asServiceRole.entities.ApiCategory.list({ sort: 'sort_order', limit: 200 });
    const apis = await base44.asServiceRole.entities.ApiService.list({ sort: 'sort_order', limit: 500 });
    const endpoints = await base44.asServiceRole.entities.ApiEndpoint.list({ limit: 1000 });

    const activeApis = apis.items.filter((a) => a.status === 'active' && a.is_public !== false);
    const activeSlugs = new Set(activeApis.map((a) => a.slug));

    const epByApi = {};
    for (const ep of endpoints.items) {
      if (ep.is_active === false) continue;
      if (!activeSlugs.has(ep.api_slug)) continue;
      (epByApi[ep.api_slug] = epByApi[ep.api_slug] || []).push({
        name: ep.name,
        slug: ep.slug,
        method: ep.method,
        path: ep.path,
        summary: ep.summary,
        auth_required: ep.auth_required !== false,
      });
    }

    return json(200, {
      ok: true,
      data: {
        categories: cats.items
          .filter((c) => c.is_active !== false)
          .map((c) => ({
            name: c.name,
            slug: c.slug,
            description: c.description,
            icon: c.icon,
            color: c.color,
          })),
        apis: activeApis.map((a) => ({
          name: a.name,
          slug: a.slug,
          description: a.description,
          category_slug: a.category_slug,
          version: a.version,
          base_path: a.base_path,
          auth_required: a.auth_required !== false,
          tags: a.tags || [],
          endpoint_count: (epByApi[a.slug] || []).length,
          endpoints: epByApi[a.slug] || [],
        })),
        totals: {
          categories: cats.items.length,
          apis: activeApis.length,
          endpoints: Object.values(epByApi).reduce((sum, list) => sum + list.length, 0),
        },
      },
    });
  } catch (e) {
    return json(500, { ok: false, error: { code: 'internal_error', message: String(e && e.message ? e.message : e) } });
  }
});
