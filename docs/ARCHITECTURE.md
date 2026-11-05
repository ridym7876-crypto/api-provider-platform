# Architecture

## Layers

**1. Data plane — `apiGateway`**
One public HTTPS endpoint. It is the only function external developers call.
Pipeline per request:

1. Parse and size-limit the body (100 KB ceiling) and query string.
2. Authenticate. `X-Api-Key` → SHA-256 → `ApiKey.key_hash` lookup. A secret is never
   stored, logged or echoed. Delegation path (`X-Developer-Token` + `X-Playground-Key`) is
   used only by the in-app playground and is ownership-checked against the session.
3. Account checks: key active, not expired, developer active.
4. Route: `{api, endpoint}`, flattened body, or `?path=` matched against `ApiService.base_path`.
5. Authorise: API active, endpoint active, key allowlist (`api_slugs`), HTTP method.
6. Rate limit: in-memory burst shed, then durable per-key counters (minute + day).
7. Dispatch to a native handler; unknown `handler_key` returns `501 handler_not_implemented`.
8. Write an `ApiRequestLog` row (audit + metering source of truth).
9. Return a stable envelope with `meta.rate_limit` and `meta.daily_quota`.

**2. Control plane — per-concern functions**
`devRegister`, `devLogin`, `devSession` (auth) · `keyManage` (key lifecycle) ·
`apiManage`, `endpointManage`, `categoryManage` (catalog CRUD, admin only) ·
`usageStats`, `requestHistory` (analytics) · `apiDocs`, `publicCatalog` (public read) ·
`playgroundSend` (proxies a real gateway call) · `adminBootstrap` (one-time admin creation).

**3. Presentation — `index.html`**
Static SPA. Holds only the session token. Every privileged decision happens server-side.

## Why everything runs on the backend

The browser never sees another user's data or any secret. The SPA can only:
- call public endpoints (`publicCatalog`, `apiDocs`),
- act as an authenticated developer using its own session token,
- act as an admin only if the server says `role: "admin"`.

Every check is re-evaluated server-side on every call. There is no client-side authorisation
that can be bypassed by opening devtools.

## Caching model (and why)

The Base44 runtime limits entity operations to about 70 per 60 seconds per caller, and the
gateway needs to answer requests quickly. So the gateway is cache-first, per isolate:

| Cache | TTL | Effect |
| --- | --- | --- |
| `keyCache` / `keyByIdCache` | 5 s | Revocation takes effect within ~5 s |
| `sessionCache` | 10 s | Playground delegation refresh |
| `devCache` | 30 s | Suspension takes effect within ~30 s |
| `catalogCache` | 30 s | Catalog edits reach the data plane within ~30 s |
| `memState` | per minute window | Local burst shedding |

The durable rate-limit counter is always consulted, so quota enforcement does not depend on
which isolate answers.

## Database

Eight entities. `ApiRequestLog` is append-only. `DeveloperProfile.password_hash` and
`ApiKey.key_hash` are one-way. `DeveloperSession.token_hash` is one-way.

## Extension points for Phase 2

- `HANDLERS` map: add native APIs without touching auth, quotas or metering.
- `ApiEndpoint.handler_key`: the routing contract between a catalog row and a handler.
- `ApiService.handler_namespace`: groups future handler modules (e.g. `ai`, `payments`).
- A future billing layer reads `ApiRequestLog`; no schema change is needed.
