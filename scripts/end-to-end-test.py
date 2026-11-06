#!/usr/bin/env python3
"""
Self-contained end-to-end test suite for the API Provider Platform.

Every run creates its own throwaway developer accounts and API keys, so it is
idempotent and safe to run repeatedly against the live deployment.

Usage:
    export ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=...   # optional: enables admin tests
    python3 scripts/end-to-end-test.py

Admin-only assertions are skipped when ADMIN_EMAIL / ADMIN_PASSWORD are absent.
Exit code is 0 only when every assertion passes.
"""
import json, os, sys, time, urllib.error, urllib.request

BASE = os.environ.get("API_BASE", "https://superagent-b31b88fd.base44.app/functions")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SUFFIX = int(time.time())
results = []


def request(method, fn, payload=None, headers=None, url=None):
    target = url or (BASE + "/" + fn)
    data = json.dumps(payload).encode() if (payload is not None and method != "GET") else None
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(target, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode()[:300]}
    except Exception as e:
        return 0, {"transport": str(e)}


def call(method, fn, payload=None, headers=None, url=None, pace=False):
    """Request with pacing and capacity backoff (the platform caps entity ops per minute)."""
    if pace:
        time.sleep(1.2)
    last = (0, {})
    for attempt in range(4):
        status, body = request(method, fn, payload, headers, url)
        blob = json.dumps(body)
        capacity = status == 0 or "platform_capacity" in blob or "allows 70 requests" in blob or "user worker threw" in blob
        if not capacity:
            return status, body
        last = (status, body)
        time.sleep(18)
    return last


def check(name, condition, detail=""):
    results.append((name, bool(condition)))
    print(("PASS " if condition else "FAIL ") + name + ("" if condition else "  <<< " + str(detail)[:280]))


def new_developer(label):
    email = "e2e.%s.%s@example.com" % (label, SUFFIX)
    status, body = call("POST", "devRegister", {"email": email, "password": "E2eTestPassword1", "full_name": label})
    if status != 201:
        raise SystemExit("could not register %s: %s" % (email, body))
    return body["data"]["token"], body["data"]["developer"], email


print("Base:", BASE, "\nrunning as suffix", SUFFIX, "\n")

# ---------------------------------------------------------------- public surface
status, body = call("POST", "publicCatalog", {})
check("public catalog is reachable without auth", status == 200 and body["data"]["totals"]["apis"] >= 5, (status, body))
check("catalog reports 11 endpoints", status == 200 and body["data"]["totals"]["endpoints"] >= 11, body.get("data", {}).get("totals"))
api_slugs = [a["slug"] for a in body["data"]["apis"]]
for slug in api_slugs:
    status, body = call("POST", "apiDocs", {"api_slug": slug})
    check("documentation generated for " + slug,
          status == 200 and len(body["data"]["markdown"]) > 300 and len(body["data"]["endpoints"]) > 0, (status, body.get("error")))

# ---------------------------------------------------------------- fresh identity
TOKEN_A, DEV_A, EMAIL_A = new_developer("alpha")
TOKEN_B, DEV_B, EMAIL_B = new_developer("beta")

status, body = call("POST", "keyManage", {"action": "create", "name": "primary"}, {"X-Developer-Token": TOKEN_A})
KEY_MAIN = body["data"]["api_key"]
KEY_MAIN_ID = body["data"]["key"]["id"]
check("key creation returns the secret exactly once", status == 201 and KEY_MAIN.startswith("sk_live_"), (status, body.get("error")))

status, body = call("POST", "keyManage", {"action": "list"}, {"X-Developer-Token": TOKEN_A})
listed = body["data"]["keys"][0]
check("key listing masks the secret and never exposes a hash",
      status == 200 and "key_hash" not in listed and "****" in listed["masked_key"], listed)

# ---------------------------------------------------------------- gateway happy paths
cases = [
    ("system", "time", {}, lambda d: "utc_iso" in d, "system/time"),
    ("system", "health", {}, lambda d: d["database_latency_ms"] > 0 and d["apis_total"] >= 5, "system/health real db latency"),
    ("crypto", "sha256", {"body": {"text": "hello world"}},
     lambda d: d["hex"] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "crypto/sha256 known digest"),
    ("crypto", "random", {"body": {"bytes": 8}}, lambda d: d["bytes"] == 8 and len(d["value"]) == 16, "crypto/random honours byte count"),
    ("text", "slugify", {"body": {"text": "Hello, World!  API Platform 2026"}},
     lambda d: d["slug"] == "hello-world-api-platform-2026", "text/slugify"),
    ("text", "stats", {"body": {"text": "One two. Three!\nFour five six."}}, lambda d: d["words"] == 6 and d["lines"] == 2, "text/stats"),
    ("data", "list-apis", {}, lambda d: d["count"] >= 5, "data/list-apis"),
    ("data", "list-endpoints", {}, lambda d: d["count"] >= 11, "data/list-endpoints"),
    ("developer", "echo", {"body": {"hello": "world"}}, lambda d: d["body"]["hello"] == "world", "developer/echo"),
    ("developer", "validate-json", {"body": {"json": '{"a":1}'}}, lambda d: d["valid"] is True, "developer/validate-json valid"),
    ("developer", "validate-json", {"body": {"json": "{bad"}}, lambda d: d["valid"] is False, "developer/validate-json invalid"),
    ("developer", "usage", {}, lambda d: d["total_requests"] > 0, "developer/usage"),
]
for api, endpoint, extra, predicate, label in cases:
    payload = {"api": api, "endpoint": endpoint}
    payload.update(extra)
    status, body = call("POST", "apiGateway", payload, {"X-Api-Key": KEY_MAIN}, pace=True)
    ok = status == 200 and body.get("ok") and predicate(body["data"]) and body["meta"]["rate_limit"]["limit"] > 0
    check("gateway " + label, ok, (status, json.dumps(body)[:300]))

# ---------------------------------------------------------------- routing styles
status, body = call("GET", "apiGateway", None, {"X-Api-Key": KEY_MAIN},
                    url=BASE + "/apiGateway?path=/v1/system/time", pace=True)
check("path routing (GET ?path=)", status == 200 and "utc_iso" in json.dumps(body), (status, body))

status, body = call("POST", "apiGateway", {}, {"X-Api-Key": KEY_MAIN},
                    url=BASE + "/apiGateway?path=/v1/text/slugify&text=Hello%20There", pace=True)
check("query-parameter routing", status == 200 and body["data"]["slug"] == "hello-there", (status, body))

status, body = call("POST", "apiGateway", {"api": "crypto", "endpoint": "sha256", "text": "flat"}, {"X-Api-Key": KEY_MAIN}, pace=True)
check("flattened body parameters", status == 200 and body["data"]["input_length"] == 4, (status, body))

# ---------------------------------------------------------------- failure modes
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"})
check("missing key rejected", status == 401 and body["error"]["code"] == "missing_api_key", (status, body))
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": "sk_live_deadbeef"})
check("unknown key rejected", status == 401 and body["error"]["code"] == "invalid_api_key", (status, body))
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": "nonsense"})
check("malformed key rejected", status == 401, (status, body))
status, body = call("POST", "apiGateway", {"api": "crypto", "endpoint": "sha256", "body": {}}, {"X-Api-Key": KEY_MAIN}, pace=True)
check("missing parameter rejected", status == 400 and body["data"]["error"] == "missing_parameter", (status, body))
status, body = call("POST", "apiGateway", {"api": "crypto", "endpoint": "random", "body": {"bytes": 9999}}, {"X-Api-Key": KEY_MAIN}, pace=True)
check("out-of-range parameter rejected", status == 400, (status, body))
status, body = call("POST", "apiGateway", {"api": "nope", "endpoint": "x"}, {"X-Api-Key": KEY_MAIN}, pace=True)
check("unknown API rejected", status == 404 and body["error"]["code"] == "api_not_found", (status, body))
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "nope"}, {"X-Api-Key": KEY_MAIN}, pace=True)
check("unknown endpoint rejected", status == 404 and body["error"]["code"] == "endpoint_not_found", (status, body))
status, body = call("PUT", "apiGateway", {"api": "system", "endpoint": "health"}, {"X-Api-Key": KEY_MAIN}, pace=True)
check("wrong HTTP method rejected", status == 405 and body["error"]["code"] == "method_not_allowed", (status, body))

# ---------------------------------------------------------------- isolation
status, body = call("POST", "keyManage", {"action": "list"}, {"X-Developer-Token": TOKEN_B})
check("second developer sees no foreign keys", status == 200 and body["data"]["count"] == 0, (status, body))
status, body = call("POST", "keyManage", {"action": "revoke", "key_id": KEY_MAIN_ID}, {"X-Developer-Token": TOKEN_B})
check("second developer cannot revoke a foreign key", status == 403 and body["error"]["code"] == "forbidden", (status, body))
status, body = call("POST", "playgroundSend", {"key_id": KEY_MAIN_ID, "api_slug": "system", "endpoint_slug": "time"}, {"X-Developer-Token": TOKEN_B})
check("second developer cannot use a foreign key in the playground", status == 403, (status, body))
status, body = call("POST", "requestHistory", {}, {"X-Developer-Token": TOKEN_B})
check("second developer has no foreign request history", status == 200 and body["data"]["count"] == 0, (status, body))
status, body = call("POST", "usageStats", {}, {"X-Developer-Token": TOKEN_B})
check("second developer has no foreign usage", status == 200 and body["data"]["totals"]["requests"] == 0, (status, body))
for fn, payload in [("apiManage", {"action": "create", "name": "x"}),
                    ("categoryManage", {"action": "create", "name": "x"}),
                    ("endpointManage", {"action": "create", "api_slug": "system", "method": "GET", "path": "/x"})]:
    status, body = call("POST", fn, payload, {"X-Developer-Token": TOKEN_B})
    check("non-admin blocked from " + fn, status == 403, (status, body))

# ---------------------------------------------------------------- playground + analytics
status, body = call("POST", "playgroundSend",
                    {"key_id": KEY_MAIN_ID, "api_slug": "crypto", "endpoint_slug": "sha256", "body": {"text": "abc"}},
                    {"X-Developer-Token": TOKEN_A}, pace=True)
ok = (status == 200 and body["data"]["simulated"] is False
      and body["data"]["response"]["status_code"] == 200
      and body["data"]["response"]["body"]["data"]["hex"].startswith("ba7816bf8"))
check("playground executes the real gateway", ok, (status, json.dumps(body)[:400]))

status, body = call("POST", "usageStats", {"range_days": 7}, {"X-Developer-Token": TOKEN_A})
data = body.get("data", {})
check("usage aggregates real traffic",
      status == 200 and data["totals"]["requests"] >= 10 and len(data["by_endpoint"]) >= 5
      and len(data["by_key"]) >= 1 and data["totals"]["p95_response_time_ms"] > 0, data.get("totals"))
check("usage includes a daily trend", status == 200 and len(data["by_day"]) >= 1, data.get("by_day"))
check("usage includes status-code breakdown", status == 200 and len(data["by_status"]) >= 2, data.get("by_status"))

status, body = call("POST", "requestHistory", {"limit": 5}, {"X-Developer-Token": TOKEN_A})
check("history paginates",
      status == 200 and len(body["data"]["requests"]) == 5 and body["data"]["has_more"] is True
      and body["data"]["requests"][0]["timestamp"], body.get("data", {}).get("count"))
status, body = call("POST", "requestHistory", {"success": True, "limit": 50}, {"X-Developer-Token": TOKEN_A})
check("history success filter", status == 200 and len(body["data"]["requests"]) > 0
      and all(r["success"] for r in body["data"]["requests"]), status)
status, body = call("POST", "requestHistory", {"success": False, "limit": 50}, {"X-Developer-Token": TOKEN_A})
check("history failure filter", status == 200 and len(body["data"]["requests"]) > 0
      and all(not r["success"] for r in body["data"]["requests"]), len(body.get("data", {}).get("requests", [])))
status, body = call("POST", "requestHistory", {"source": "playground", "limit": 20}, {"X-Developer-Token": TOKEN_A})
check("history records playground as a source", status == 200 and len(body["data"]["requests"]) > 0, status)

# ---------------------------------------------------------------- quotas and scoping
status, body = call("POST", "keyManage", {"action": "create", "name": "throttled", "rate_limit_per_minute": 1}, {"X-Developer-Token": TOKEN_A})
KEY_THROTTLE = body["data"]["api_key"]
first, _ = call("POST", "apiGateway", {"api": "data", "endpoint": "list-apis"}, {"X-Api-Key": KEY_THROTTLE})
second, second_body = call("POST", "apiGateway", {"api": "data", "endpoint": "list-apis"}, {"X-Api-Key": KEY_THROTTLE})
check("per-key minute limit enforced",
      first == 200 and second == 429 and second_body["error"]["code"] == "rate_limit_exceeded",
      (first, second, second_body.get("error")))

status, body = call("POST", "keyManage", {"action": "create", "name": "scoped", "api_slugs": ["text"]}, {"X-Developer-Token": TOKEN_A})
KEY_SCOPED = body["data"]["api_key"]
KEY_SCOPED_ID = body["data"]["key"]["id"]
status, body = call("POST", "apiGateway", {"api": "text", "endpoint": "slugify", "body": {"text": "Ok Fine"}}, {"X-Api-Key": KEY_SCOPED}, pace=True)
check("scoped key works on its own API", status == 200, (status, body))
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY_SCOPED}, pace=True)
check("scoped key blocked on other APIs", status == 403 and body["error"]["code"] == "api_not_permitted", (status, body))

status, body = call("POST", "keyManage", {"action": "revoke", "key_id": KEY_SCOPED_ID}, {"X-Developer-Token": TOKEN_A})
check("key revocation succeeds", status == 200 and body["data"]["key"]["status"] == "revoked", (status, body))
time.sleep(7)
status, body = call("POST", "apiGateway", {"api": "text", "endpoint": "slugify", "body": {"text": "x"}}, {"X-Api-Key": KEY_SCOPED})
check("revoked key rejected", status == 403 and body["error"]["code"] == "key_revoked", (status, body))

status, body = call("POST", "keyManage", {"action": "regenerate", "key_id": KEY_MAIN_ID}, {"X-Developer-Token": TOKEN_A})
KEY_ROTATED = body["data"]["api_key"]
check("rotation issues a new secret", status == 201 and KEY_ROTATED and KEY_ROTATED != KEY_MAIN, (status, body.get("error")))
time.sleep(7)
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY_MAIN})
check("old secret dead after rotation", status == 403, (status, body))
status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY_ROTATED}, pace=True)
check("new secret works after rotation", status == 200, (status, body))

# ---------------------------------------------------------------- admin lifecycle
if ADMIN_EMAIL and ADMIN_PASSWORD:
    status, body = call("POST", "devLogin", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    ADMIN_TOKEN = body.get("data", {}).get("token")
    check("admin login", status == 200 and ADMIN_TOKEN, (status, body.get("error")))
    if ADMIN_TOKEN:
        status, body = call("POST", "apiManage", {"action": "set_status", "slug": "system", "status": "inactive"}, {"X-Developer-Token": ADMIN_TOKEN})
        check("admin deactivates an API", status == 200 and body["data"]["api"]["status"] == "inactive", (status, body.get("error")))
        time.sleep(32)
        status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY_ROTATED})
        check("deactivated API stops serving traffic", status == 403 and body["error"]["code"] == "api_inactive", (status, body))
        status, body = call("POST", "apiManage", {"action": "get", "slug": "system"}, {"X-Developer-Token": ADMIN_TOKEN})
        check("admin reads API by slug with endpoints", status == 200 and len(body["data"]["endpoints"]) == 2, (status, body.get("error")))
        status, body = call("POST", "apiManage", {"action": "set_status", "slug": "system", "status": "active"}, {"X-Developer-Token": ADMIN_TOKEN})
        check("admin reactivates the API", status == 200, (status, body.get("error")))
        time.sleep(32)
        status, body = call("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY_ROTATED}, pace=True)
        check("reactivated API serves traffic again", status == 200, (status, body))
        status, body = call("POST", "categoryManage", {"action": "create", "name": "E2E Category " + str(SUFFIX),
                                                       "description": "created by the test suite"}, {"X-Developer-Token": ADMIN_TOKEN})
        check("admin creates a category", status == 201, (status, body.get("error")))
        new_cat_id = body.get("data", {}).get("category", {}).get("id")
        if new_cat_id:
            status, body = call("POST", "categoryManage", {"action": "delete", "id": new_cat_id}, {"X-Developer-Token": ADMIN_TOKEN})
            check("admin deletes an empty category", status == 200, (status, body.get("error")))
        status, body = call("POST", "apiManage", {"action": "create", "name": "E2E Temp API " + str(SUFFIX),
                                                  "description": "temp", "status": "draft"}, {"X-Developer-Token": ADMIN_TOKEN})
        check("admin creates an API product", status == 201, (status, body.get("error")))
        temp_slug = body.get("data", {}).get("api", {}).get("slug")
        if temp_slug:
            status, body = call("POST", "endpointManage", {"action": "create", "api_slug": temp_slug, "name": "ping",
                                                           "method": "GET", "path": "/v1/temp/ping",
                                                           "handler_key": "system.time"}, {"X-Developer-Token": ADMIN_TOKEN})
            check("admin creates an endpoint", status == 201, (status, body.get("error")))
            status, body = call("POST", "apiManage", {"action": "delete", "slug": temp_slug}, {"X-Developer-Token": ADMIN_TOKEN})
            check("admin deletes an API and cascades endpoints",
                  status == 200 and body["data"]["endpoints_deleted"] >= 1, (status, body.get("error")))
else:
    print("SKIP admin lifecycle checks (set ADMIN_EMAIL and ADMIN_PASSWORD to enable)")

# ---------------------------------------------------------------- session lifecycle
status, body = call("POST", "devLogin", {"email": EMAIL_A, "password": "E2eTestPassword1"})
temp_token = body.get("data", {}).get("token")
check("login issues a session token", status == 200 and temp_token, (status, body.get("error")))
status, body = call("POST", "devSession", {"action": "logout"}, {"X-Developer-Token": temp_token})
check("logout succeeds", status == 200, (status, body))
status, body = call("POST", "devSession", {"action": "me"}, {"X-Developer-Token": temp_token})
check("logged-out session rejected", status == 401 and body["error"]["code"] == "token_revoked", (status, body))
status, body = call("POST", "devSession", {"action": "me"}, {"X-Developer-Token": "dst_forged_token"})
check("forged session rejected", status == 401, (status, body))
status, body = call("POST", "devSession", {"action": "me"}, {"X-Developer-Token": TOKEN_A})
check("session read returns profile and overview", status == 200 and body["data"]["developer"]["email"] == EMAIL_A, (status, body.get("error")))
status, body = call("POST", "devLogin", {"email": EMAIL_A, "password": "wrong-password"})
check("wrong password rejected", status == 401, (status, body))
status, body = call("POST", "devRegister", {"email": EMAIL_A, "password": "E2eTestPassword1"})
check("duplicate registration rejected", status == 409, (status, body))
status, body = call("POST", "devRegister", {"email": "not-an-email", "password": "E2eTestPassword1"})
check("invalid email rejected on registration", status == 400, (status, body))
status, body = call("POST", "devRegister", {"email": "short.%s@example.com" % SUFFIX, "password": "short"})
check("weak password rejected on registration", status == 400, (status, body))

# ---------------------------------------------------------------- summary
passed = sum(1 for _, ok in results if ok)
print("\n==== %d/%d assertions passed ====" % (passed, len(results)))
for name, ok in results:
    if not ok:
        print("FAILED:", name)
sys.exit(0 if passed == len(results) else 1)
