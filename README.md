# MR RIDUY AI API — AI API Platform

Branded AI API platform: users sign up, generate a `mr_riduy_ai_…` key, and call AI endpoints (chat, summarise, translate, sentiment, classify, keywords) from any website, app or game.

A complete, working API provider platform: a public API gateway with hashed API keys,
server-side rate limiting, usage analytics, request history, generated documentation and a
live testing playground — plus a developer portal and an admin console.

**Live portal:** https://ridym7876-crypto.github.io/api-provider-platform/
**API gateway:** `https://superagent-b31b88fd.base44.app/functions/apiGateway`
**Backend runtime:** Base44 app functions + entities (serverless)

---

## What this is

Phase 1 delivers the **API management infrastructure**. It does not resell third-party AI
APIs; instead it publishes its own native, deterministic endpoints and gives you the full
provider-side machinery to run them: authentication, quotas, metering, docs and billing-ready
usage data.

Everything in the table below is implemented and was verified end to end against the live
deployment (see `scripts/end-to-end-test.py`).

| Requirement | Status | Where |
| --- | --- | --- |
| API management dashboard | Done | Admin console in `index.html` → `apiManage`, `endpointManage` |
| Developer dashboard (register, login, profile, overview, keys) | Done | `devRegister`, `devLogin`, `devSession` |
| API key generation (multiple, shown once, revoke, rotate, hashed) | Done | `keyManage` |
| Secure API authentication on the backend | Done | `apiGateway` |
| Usage tracking (per key, per endpoint, success/failure) | Done | `apiGateway` → `usageStats` |
| Request history (time, endpoint, status, latency, success) | Done | `requestHistory` |
| Server-side rate limiting (per minute + per day, configurable) | Done | `apiGateway` |
| API categories management | Done | `categoryManage` |
| Documentation system (params, headers, bodies, examples, auth) | Done | `apiDocs` |
| Testing playground (real requests, real responses) | Done | `playgroundSend` → `apiGateway` |

## Architecture

```
Developer browser (static portal, GitHub Pages)
        │  X-Developer-Token (session)
        ▼
  Control plane functions                     Data plane function
 ┌──────────────────────────────┐        ┌───────────────────────────────┐
 │ devRegister  devLogin        │        │  POST /functions/apiGateway   │
 │ devSession   keyManage       │        │  X-Api-Key: sk_live_…         │
 │ apiManage    endpointManage  │        │  ↓ SHA-256 lookup             │
 │ categoryManage adminBootstrap│        │  ↓ account status             │
 │ usageStats   requestHistory  │        │  ↓ route → cache-first catalog│
 │ apiDocs      publicCatalog   │        │  ↓ rate limit (mem + durable) │
 │ playgroundSend               │───────▶│  ↓ native handler             │
 └──────────────────────────────┘        │  ↓ audit log + counters       │
                                         └───────────────────────────────┘
                       Base44 entities (8 tables, RLS-scoped app database)
```

Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
Security model: [`docs/SECURITY.md`](docs/SECURITY.md)
Phase 1 report and known limits: [`docs/PHASE1-REPORT.md`](docs/PHASE1-REPORT.md)

## Entities

| Entity | Purpose |
| --- | --- |
| `DeveloperProfile` | Account, plan, role, PBKDF2 password hash, per-developer limits |
| `DeveloperSession` | Hashed session tokens with expiry and revocation |
| `ApiKey` | Hashed secret keys, scopes, allowlists, per-key limits, counters |
| `ApiRequestLog` | Immutable audit row per gateway call |
| `ApiRateLimitCounter` | Durable per-key minute/day windows |
| `ApiCategory` | Category taxonomy |
| `ApiService` | API products (slug, base path, status, docs) |
| `ApiEndpoint` | Endpoints with params, headers, schemas, examples, handler key |

JSON Schema for every table: `backend/entities/`.

## The gateway contract

```bash
curl -X POST 'https://superagent-b31b88fd.base44.app/functions/apiGateway' \
  -H 'X-Api-Key: sk_live_…' \
  -H 'Content-Type: application/json' \
  -d '{"api":"crypto","endpoint":"sha256","body":{"text":"hello world"}}'
```

Three calling styles are supported:

```bash
# 1. envelope in the body
-d '{"api":"crypto","endpoint":"sha256","body":{"text":"hi"}}'
# 2. flattened parameters
-d '{"api":"crypto","endpoint":"sha256","text":"hi"}'
# 3. path style
GET /functions/apiGateway?path=/v1/crypto/sha256&text=hi
```

Response envelope:

```json
{
  "ok": true, "status": 200, "request_id": "req_ab12…",
  "api": "crypto", "endpoint": "sha256", "http_method": "POST",
  "response_time_ms": 41.2,
  "data": { "algorithm": "SHA-256", "hex": "b94d27b9…" },
  "meta": { "rate_limit": {"limit":60,"remaining":59,"window":"minute"},
            "daily_quota": {"limit":10000,"remaining":9999,"window":"day"} }
}
```

Error codes are stable and machine readable: `missing_api_key`, `invalid_api_key`,
`key_revoked`, `key_expired`, `account_suspended`, `api_inactive`, `api_not_permitted`,
`endpoint_not_found`, `method_not_allowed`, `rate_limit_exceeded`, `daily_quota_exceeded`,
`platform_capacity`, `handler_not_implemented`.

## Published APIs

| API | Base path | Endpoints |
| --- | --- | --- |
| System | `/v1/system` | health, time |
| Crypto | `/v1/crypto` | sha256, random |
| Text | `/v1/text` | slugify, stats |
| Data | `/v1/data` | list-apis, list-endpoints |
| Developer | `/v1/developer` | usage, echo, validate-json |

Every handler computes a real result from real input. There are no hardcoded or simulated
responses anywhere in the data plane.

## Verification

```bash
# 76 assertions against the live deployment. Creates its own throwaway
# developer accounts and keys, so it is idempotent and safe to re-run.
python3 scripts/end-to-end-test.py

# Admin-only assertions (catalog CRUD, activate/deactivate) need an admin login:
export ADMIN_EMAIL=you@example.com
export ADMIN_PASSWORD='...'
python3 scripts/end-to-end-test.py
```

Without those env vars the admin block is skipped and everything else still runs.
Exit code is 0 only when every assertion passes.

## Adding your own APIs (Phase 2 hook)

1. Add a handler to the `HANDLERS` map in `backend/functions/apiGateway.ts` under a new key,
   e.g. `weather.current`.
2. Create the API + endpoint records and set `handler_key` to that key.
3. Redeploy `apiGateway`. Docs, keys, quotas, metering and the playground pick it up
   automatically — no other code changes.

## Limitations (honest list)

- The Base44 runtime caps entity operations at roughly **70 per 60 seconds per caller**. The
  gateway is cache-first to stay inside that budget, which bounds sustained throughput to
  roughly 20–70 requests/minute. Real production traffic needs a dedicated runtime or a
  raised quota. Details and the migration path are in `docs/PHASE1-REPORT.md`.
- Rate-limit counters are durable, but the fast in-memory pre-check is per serverless
  isolate, so a burst spread across isolates can overshoot slightly before the durable
  counter catches it.
- Key revocation and catalog edits propagate within the cache TTL (5s for keys, 30s for the
  catalog) rather than instantly.
- `usageStats` aggregates in the application layer over a capped scan (5,000 rows per query),
  not a database `GROUP BY`. Fine at Phase 1 scale.
- The portal is a static single-page app. It is served from GitHub Pages and talks to the
  API over CORS; there is no server-rendered marketing site.

## License

MIT — see `LICENSE`.
