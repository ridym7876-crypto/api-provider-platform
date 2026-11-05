# Security model

## Secrets

| Secret | Storage | Lifetime |
| --- | --- | --- |
| Developer password | PBKDF2-SHA256, 100,000 iterations, 16-byte random salt, per-user | Until changed |
| Session token (`dst_…`) | SHA-256 hash only | 7 days, revocable |
| API key (`sk_live_…`) | SHA-256 hash only | Until revoked or rotated |

Full secrets exist exactly once: in the response that creates them. They are never written
to the database, never logged, never returned by any list endpoint (`masked_key` only).

PBKDF2 is capped at 100,000 iterations by the runtime (higher counts throw), which is the
maximum available strength on this platform.

## Authorisation

- **Developers** can only read or mutate their own keys, sessions and request logs. Ownership
  is checked against the session's `developer_id` on every call, and every list query is
  filtered by it server-side.
- **Admins** (`role: "admin"`) are required for every catalog mutation: create/update/delete
  of categories, APIs and endpoints. Self-service escalation is impossible: `devRegister`
  always writes `role: "developer"`, and `adminBootstrap` refuses once any admin exists.
- **API keys** carry an optional `api_slugs` allowlist. An empty list means all published
  APIs; a non-empty list is enforced on every request.

## Transport and input

- Every endpoint validates and bounds its input: email format, password length, slug
  shaping, method enum, path prefix, integer ranges for `bytes`, 100 KB body ceiling.
- Unknown/absent values are rejected with specific 4xx codes rather than silently defaulting.
- All query-building uses server-side filtered equality on indexed-ish fields; there is no
  string interpolation into queries.

## Abuse controls

1. Login brute force: 10 failed attempts per email + IP per 15 minutes (durable counter).
2. Per-key minute limit and daily quota, configurable per key, per API and per developer.
3. Per-key allowlist scoping.
4. Invalid keys are rejected before any catalog work is done.
5. Playground calls are rate-limited exactly like production calls and are labelled
   `source: "playground"` in the audit log.

## Known gaps (deliberate, documented)

- The gateway responses and portal are CORS-open (`*`) so any developer tool can call the API.
  Authorisation is carried by the key, not by origin. Do not rely on CORS to protect data.
- No email verification or password reset flow yet (Phase 2).
- No dedicated WAF/DDoS layer in front of the function; platform-level limits apply.
- Data at rest is protected by the platform database; there is no application-level field
  encryption beyond the hashing described above.

## Reporting

Found something? Open an issue in this repository rather than testing against other
developers' accounts.
