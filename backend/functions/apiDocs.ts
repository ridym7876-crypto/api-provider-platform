// @ts-nocheck
// apiDocs — public documentation for one API: structured spec, parameters, headers,
// request/response examples, auth instructions, curl samples and rendered Markdown.
// Contains no secrets: only documentation-safe metadata.
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

const AVAILABLE_HANDLERS = [
  'system.health', 'system.time', 'crypto.sha256', 'crypto.random', 'text.slugify',
  'text.stats', 'json.validate', 'platform.usage', 'data.apis.list', 'data.endpoints.list', 'echo.request',
];

function paramTable(params) {
  if (!Array.isArray(params) || params.length === 0) return '_No parameters._';
  const rows = params.map((p) => `| \`${p.name || ''}\` | ${p.in || 'body'} | ${p.type || 'string'} | ${p.required ? 'yes' : 'no'} | ${(p.description || '').replace(/\|/g, '\\|')} |`);
  return ['| Name | In | Type | Required | Description |', '| --- | --- | --- | --- | --- |', ...rows].join('\n');
}

function buildMarkdown(api, endpoints, baseUrl) {
  const lines = [];
  lines.push(`# ${api.name}`);
  lines.push('');
  lines.push(api.description || '');
  lines.push('');
  lines.push(`**Version:** ${api.version || 'v1'}  `);
  lines.push(`**Base path:** \`${api.base_path || ''}\`  `);
  lines.push(`**Status:** ${api.status}  `);
  lines.push(`**Authentication:** ${api.auth_required === false ? 'None required for this API' : 'API key required'}`);
  lines.push('');
  if (api.long_description) {
    lines.push(api.long_description);
    lines.push('');
  }
  lines.push('## Authentication');
  lines.push('');
  if (api.auth_required === false) {
    lines.push('This API does not require an API key.');
  } else {
    lines.push('Send your secret key in the `X-Api-Key` header. Keys are created from the developer dashboard.');
    lines.push('The full key is displayed only once at creation time, so store it in a secret manager.');
    lines.push('');
    lines.push('```bash');
    lines.push(`curl -X POST '${baseUrl}/functions/apiGateway' \\`);
    lines.push('  -H "X-Api-Key: $API_KEY" \\');
    lines.push('  -H "Content-Type: application/json" \\');
    lines.push(`  -d '{"api":"${api.slug}","endpoint":"<endpoint-slug>","body":{}}'`);
    lines.push('```');
  }
  lines.push('');
  for (const ep of endpoints) {
    lines.push(`## ${ep.name}`);
    lines.push('');
    lines.push(`\`${ep.method} ${ep.path}\``);
    lines.push('');
    if (ep.summary) { lines.push(ep.summary); lines.push(''); }
    if (ep.description) { lines.push(ep.description); lines.push(''); }
    lines.push('### Parameters');
    lines.push('');
    lines.push(paramTable(ep.parameters));
    lines.push('');
    if (Array.isArray(ep.request_headers) && ep.request_headers.length > 0) {
      lines.push('### Headers');
      lines.push('');
      lines.push(paramTable(ep.request_headers.map((h) => ({ ...h, in: 'header' }))));
      lines.push('');
    }
    if (ep.request_body_schema && Object.keys(ep.request_body_schema).length > 0) {
      lines.push('### Request body schema');
      lines.push('');
      lines.push('```json');
      lines.push(JSON.stringify(ep.request_body_schema, null, 2));
      lines.push('```');
      lines.push('');
    }
    if (ep.request_body_example && Object.keys(ep.request_body_example).length > 0) {
      lines.push('### Example request');
      lines.push('');
      lines.push('```bash');
      lines.push(`curl -X POST '${baseUrl}/functions/apiGateway' \\`);
      lines.push('  -H "X-Api-Key: $API_KEY" \\');
      lines.push('  -H "Content-Type: application/json" \\');
      lines.push(`  -d '${JSON.stringify({ api: api.slug, endpoint: ep.slug, body: ep.request_body_example })}'`);
      lines.push('```');
      lines.push('');
    }
    if (Array.isArray(ep.response_examples)) {
      for (const ex of ep.response_examples) {
        lines.push(`### Response ${ex.status || 200}${ex.description ? ` — ${ex.description}` : ''}`);
        lines.push('');
        lines.push('```json');
        lines.push(typeof ex.body === 'string' ? ex.body : JSON.stringify(ex.body, null, 2));
        lines.push('```');
        lines.push('');
      }
    }
    lines.push('---');
    lines.push('');
  }
  if (api.docs_markdown) {
    lines.push('## Additional notes');
    lines.push('');
    lines.push(api.docs_markdown);
  }
  return lines.join('\n');
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  const base44 = createClientFromRequest(req);
  try {
    const url = new URL(req.url);
    const input = req.method === 'GET' ? {} : await req.json().catch(() => ({}));
    const apiRef = String(input.api_slug || input.slug || url.searchParams.get('api_slug') || url.searchParams.get('slug') || '');
    if (!apiRef) return json(400, { ok: false, error: { code: 'missing_api_slug', message: 'api_slug is required.' } });

    const bySlug = await base44.asServiceRole.entities.ApiService.filter({ slug: apiRef }, { limit: 1 });
    const api = bySlug.items[0];
    if (!api || api.status !== 'active' || api.is_public === false) {
      return json(404, { ok: false, error: { code: 'api_not_found', message: 'No published API found for that slug.' } });
    }

    const eps = await base44.asServiceRole.entities.ApiEndpoint.filter({ api_slug: api.slug }, { sort: 'sort_order', limit: 300 });
    const endpoints = eps.items.filter((e) => e.is_active !== false);
    const host = url.origin;

    const authHeader = api.auth_required === false ? null : {
      name: 'X-Api-Key',
      in: 'header',
      required: true,
      description: 'Your secret API key (sk_live_...). Create one in the developer dashboard.',
    };

    return json(200, {
      ok: true,
      data: {
        api: {
          name: api.name,
          slug: api.slug,
          description: api.description,
          long_description: api.long_description,
          version: api.version,
          base_path: api.base_path,
          category_slug: api.category_slug,
          tags: api.tags || [],
          status: api.status,
          auth_required: api.auth_required !== false,
          default_rate_limit_per_minute: api.default_rate_limit_per_minute,
          default_daily_quota: api.default_daily_quota,
        },
        authentication: {
          type: api.auth_required === false ? 'none' : 'api_key',
          header: authHeader,
          gateway_url: `${host}/functions/apiGateway`,
          instructions: [
            'Create a secret key in the developer dashboard. It is shown once and stored only as a SHA-256 hash.',
            'Send it on every request in the X-Api-Key header.',
            'Never embed the key in client-side or browser code.',
          ],
        },
        endpoints: endpoints.map((ep) => ({
          name: ep.name,
          slug: ep.slug,
          method: ep.method,
          path: ep.path,
          summary: ep.summary,
          description: ep.description,
          auth_required: ep.auth_required !== false,
          parameters: ep.parameters || [],
          request_headers: ep.request_headers || [],
          request_body_schema: ep.request_body_schema || {},
          request_body_example: ep.request_body_example || {},
          response_examples: ep.response_examples || [],
          call: {
            url: `${host}/functions/apiGateway`,
            body: { api: api.slug, endpoint: ep.slug, params: {}, body: ep.request_body_example || {} },
          },
        })),
        platform: { available_handlers: AVAILABLE_HANDLERS },
        markdown: buildMarkdown(api, endpoints, host),
      },
    });
  } catch (e) {
    return json(500, { ok: false, error: { code: 'internal_error', message: String(e && e.message ? e.message : e) } });
  }
});
