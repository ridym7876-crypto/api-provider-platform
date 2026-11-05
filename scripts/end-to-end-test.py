import json, urllib.request, urllib.error, time

B = "https://superagent-b31b88fd.base44.app/functions"
ADMIN = open('/tmp/admintoken').read().strip()
DEV = open('/tmp/devtoken').read().strip()
KEY = open('/tmp/apikey').read().strip()
KEYID = open('/tmp/keyid').read().strip()
results = []

def req(method, fn, payload=None, headers=None, url=None):
    u = url or (B + "/" + fn)
    data = json.dumps(payload).encode() if payload is not None and method != "GET" else None
    h = {"Content-Type": "application/json"}
    if headers: h.update(headers)
    r = urllib.request.Request(u, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=90) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: body = json.loads(raw)
        except Exception: body = {"raw": raw.decode()[:300]}
        return e.code, body
    except Exception as e:
        return 0, {"transport": str(e)}

def call_retry(method, fn, payload=None, headers=None, url=None, tries=3):
    for i in range(tries):
        s, b = req(method, fn, payload, headers, url)
        cap = False
        if isinstance(b, dict):
            blob = json.dumps(b)
            cap = "platform_capacity" in blob or "allows 70 requests" in blob or "user worker threw" in blob
        if s in (0,) or cap:
            time.sleep(3)
            continue
        return s, b
    return s, b

def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  <<< " + str(detail)[:260]))

# ---------- A. public surface ----------
s, b = call_retry("POST", "publicCatalog", {})
check("publicCatalog no-auth", s == 200 and b["data"]["totals"]["apis"] == 5, (s, b))
check("catalog 11 endpoints", s == 200 and b["data"]["totals"]["endpoints"] == 11, (s, b))
for slug in ["system", "crypto", "text", "data", "developer"]:
    s, b = call_retry("POST", "apiDocs", {"api_slug": slug})
    check(f"apiDocs {slug} + markdown", s == 200 and len(b["data"]["markdown"]) > 300 and len(b["data"]["endpoints"]) > 0, (s, b.get("error")))

# ---------- B. gateway functional ----------
cases = [
  ("system", "time", {}, lambda d: "utc_iso" in d, "system/time"),
  ("system", "health", {}, lambda d: d["database_latency_ms"] > 0 and d["apis_total"] == 5, "system/health live db"),
  ("crypto", "sha256", {"body": {"text": "hello world"}}, lambda d: d["hex"] == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "sha256 digest"),
  ("crypto", "random", {"body": {"bytes": 8}}, lambda d: len(d["value"]) == 16, "random 8 bytes"),
  ("text", "slugify", {"body": {"text": "Hello, World!  API Platform 2026"}}, lambda d: d["slug"] == "hello-world-api-platform-2026", "slugify"),
  ("text", "stats", {"body": {"text": "One two. Three!\nFour five six."}}, lambda d: d["words"] == 6 and d["lines"] == 2, "text stats"),
  ("data", "list-apis", {}, lambda d: d["count"] == 5, "data/list-apis"),
  ("data", "list-endpoints", {}, lambda d: d["count"] == 11, "data/list-endpoints"),
  ("developer", "echo", {"body": {"hello": "world"}}, lambda d: d["body"]["hello"] == "world", "echo"),
  ("developer", "validate-json", {"body": {"json": '{"a":1}'}}, lambda d: d["valid"] is True, "json valid"),
  ("developer", "validate-json", {"body": {"json": "{bad"}}, lambda d: d["valid"] is False, "json invalid"),
  ("developer", "usage", {}, lambda d: d["total_requests"] > 0, "platform.usage"),
]
for api, ep, extra, pred, label in cases:
    payload = {"api": api, "endpoint": ep, **extra}
    s, b = call_retry("POST", "apiGateway", payload, {"X-Api-Key": KEY})
    ok = s == 200 and b.get("ok") and pred(b["data"]) and b["meta"]["rate_limit"]["limit"] > 0
    check("gateway " + label, ok, (s, json.dumps(b)[:300]))

# path routing
s, b = call_retry("GET", "apiGateway", None, {"X-Api-Key": KEY}, url=B + "/apiGateway?path=/v1/system/time")
check("path routing /v1/system/time", s == 200 and "utc_iso" in json.dumps(b), (s, json.dumps(b)[:200]))
s, b = call_retry("GET", "apiGateway", None, {"X-Api-Key": KEY}, url=B + "/apiGateway?path=/v1/text/slugify&text=Hello%20There")
check("path routing + query param", s == 200 and b["data"]["slug"] == "hello-there", (s, json.dumps(b)[:250]))

# ---------- C. gateway failures ----------
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"})
check("no key -> 401", s == 401 and b["error"]["code"] == "missing_api_key", (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": "sk_live_deadbeef"})
check("bad key -> 401", s == 401 and b["error"]["code"] == "invalid_api_key", (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": "nonsense"})
check("malformed key -> 401", s == 401, (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "crypto", "endpoint": "sha256", "body": {}}, {"X-Api-Key": KEY})
check("missing param -> 400", s == 400 and b["data"]["error"] == "missing_parameter", (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "crypto", "endpoint": "random", "body": {"bytes": 9999}}, {"X-Api-Key": KEY})
check("invalid param -> 400", s == 400, (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "nope", "endpoint": "x"}, {"X-Api-Key": KEY})
check("unknown api -> 404", s == 404 and b["error"]["code"] == "api_not_found", (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "nope"}, {"X-Api-Key": KEY})
check("unknown endpoint -> 404", s == 404 and b["error"]["code"] == "endpoint_not_found", (s, b))
s, b = call_retry("PUT", "apiGateway", {"api": "system", "endpoint": "health"}, {"X-Api-Key": KEY})
check("wrong method -> 405", s == 405 and b["error"]["code"] == "method_not_allowed", (s, b))
print("... pausing 40s to let the platform entity quota reset ...")
time.sleep(40)

# ---------- D. developer isolation ----------
email2 = f"dev2_{int(time.time())}@example.com"
s, b = call_retry("POST", "devRegister", {"email": email2, "password": "SuperSecret123"})
DEV2 = b.get("data", {}).get("token")
check("dev2 registered", s == 201 and DEV2, (s, b))
s, b = call_retry("POST", "keyManage", {"action": "list"}, {"X-Developer-Token": DEV2})
check("dev2 sees 0 keys", s == 200 and b["data"]["count"] == 0, (s, b))
s, b = call_retry("POST", "keyManage", {"action": "revoke", "key_id": KEYID}, {"X-Developer-Token": DEV2})
check("dev2 cannot revoke dev1 key", s == 403, (s, b))
s, b = call_retry("POST", "requestHistory", {}, {"X-Developer-Token": DEV2})
check("dev2 request history empty", s == 200 and b["data"]["count"] == 0, (s, b))
s, b = call_retry("POST", "usageStats", {}, {"X-Developer-Token": DEV2})
check("dev2 usage empty", s == 200 and b["data"]["totals"]["requests"] == 0, (s, b))
s, b = call_retry("POST", "playgroundSend", {"key_id": KEYID, "api_slug": "system", "endpoint_slug": "time"}, {"X-Developer-Token": DEV2})
check("dev2 cannot play with dev1 key", s == 403, (s, b))
s, b = call_retry("POST", "apiManage", {"action": "create", "name": "Hacked"}, {"X-Developer-Token": DEV2})
check("non-admin cannot create API", s == 403, (s, b))
s, b = call_retry("POST", "categoryManage", {"action": "create", "name": "Hacked"}, {"X-Developer-Token": DEV2})
check("non-admin cannot create category", s == 403, (s, b))
s, b = call_retry("POST", "endpointManage", {"action": "create", "api_slug": "system", "method": "GET", "path": "/x"}, {"X-Developer-Token": DEV2})
check("non-admin cannot create endpoint", s == 403, (s, b))

# ---------- E. playground + analytics ----------
s, b = call_retry("POST", "playgroundSend", {"key_id": KEYID, "api_slug": "crypto", "endpoint_slug": "sha256", "body": {"text": "abc"}}, {"X-Developer-Token": DEV})
ok = s == 200 and b["data"]["simulated"] is False and b["data"]["response"]["status_code"] == 200 and b["data"]["response"]["body"]["data"]["hex"].startswith("ba7816bf8")
check("playground runs real gateway", ok, (s, json.dumps(b)[:400]))
s, b = call_retry("POST", "usageStats", {"range_days": 7}, {"X-Developer-Token": DEV})
ok = s == 200 and b["data"]["totals"]["requests"] > 15 and len(b["data"]["by_endpoint"]) >= 5 and len(b["data"]["by_key"]) >= 1 and b["data"]["totals"]["p95_response_time_ms"] > 0
check("usageStats aggregates", ok, json.dumps(b.get("data", {}).get("totals")))
check("usageStats by_day trend", s == 200 and len(b["data"]["by_day"]) >= 1, b["data"].get("by_day") if s == 200 else b)
s, b = call_retry("POST", "requestHistory", {"limit": 5}, {"X-Developer-Token": DEV})
check("requestHistory paginated", s == 200 and len(b["data"]["requests"]) == 5 and b["data"]["has_more"] is True, (s, b.get("data", {}).get("count")))
s, b = call_retry("POST", "requestHistory", {"success": True, "limit": 50}, {"X-Developer-Token": DEV})
check("history success filter", s == 200 and all(r["success"] for r in b["data"]["requests"]), (s,))
s, b = call_retry("POST", "requestHistory", {"success": False, "limit": 50}, {"X-Developer-Token": DEV})
check("history failure filter", s == 200 and len(b["data"]["requests"]) > 0 and all(not r["success"] for r in b["data"]["requests"]), (s, len(b.get("data", {}).get("requests", []))))

# ---------- F. keys: rate limit, scoping, revoke, regenerate ----------
s, b = call_retry("POST", "keyManage", {"action": "create", "name": "Throttle", "rate_limit_per_minute": 1}, {"X-Developer-Token": DEV})
RLKEY = b.get("data", {}).get("api_key")
check("throttle key created", s == 201 and RLKEY, (s, b.get("error")))
s1, b1 = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": RLKEY})
s2, b2 = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": RLKEY})
check("rate limit 1/min enforced", s1 == 200 and s2 == 429 and b2["error"]["code"] == "rate_limit_exceeded", (s1, s2, b2.get("error")))

s, b = call_retry("POST", "keyManage", {"action": "create", "name": "Scoped", "api_slugs": ["text"]}, {"X-Developer-Token": DEV})
SCOPED = b.get("data", {}).get("api_key"); SCOPEDID = b.get("data", {}).get("key", {}).get("id")
s, b = call_retry("POST", "apiGateway", {"api": "text", "endpoint": "slugify", "body": {"text": "Ok Fine"}}, {"X-Api-Key": SCOPED})
check("scoped key works on its api", s == 200, (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": SCOPED})
check("scoped key blocked elsewhere", s == 403 and b["error"]["code"] == "api_not_permitted", (s, b))
s, b = call_retry("POST", "keyManage", {"action": "revoke", "key_id": SCOPEDID}, {"X-Developer-Token": DEV})
check("revoke works", s == 200 and b["data"]["key"]["status"] == "revoked", (s, b))
time.sleep(7)
s, b = call_retry("POST", "apiGateway", {"api": "text", "endpoint": "slugify", "body": {"text": "x"}}, {"X-Api-Key": SCOPED})
check("revoked key dead after cache TTL", s == 403 and b["error"]["code"] == "key_revoked", (s, b))

s, b = call_retry("POST", "keyManage", {"action": "regenerate", "key_id": KEYID}, {"X-Developer-Token": DEV})
NEWKEY = b.get("data", {}).get("api_key")
check("regenerate issues new secret", s == 201 and NEWKEY and NEWKEY != KEY, (s, b.get("error")))
time.sleep(7)
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY})
check("old key rejected after rotate", s == 403, (s, b))
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": NEWKEY})
check("new key accepted", s == 200, (s, b))
KEY = NEWKEY; open('/tmp/apikey','w').write(KEY)

# ---------- G. api lifecycle ----------
s, b = call_retry("POST", "apiManage", {"action": "set_status", "slug": "system", "status": "inactive"}, {"X-Developer-Token": ADMIN})
check("admin deactivates api", s == 200 and b["data"]["api"]["status"] == "inactive", (s, b))
time.sleep(32)
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY})
check("inactive api blocked", s == 403 and b["error"]["code"] == "api_inactive", (s, b))
s, b = call_retry("POST", "apiManage", {"action": "set_status", "slug": "system", "status": "active"}, {"X-Developer-Token": ADMIN})
time.sleep(32)
s, b = call_retry("POST", "apiGateway", {"api": "system", "endpoint": "time"}, {"X-Api-Key": KEY})
check("reactivated api live again", s == 200, (s, b))

# ---------- H. session lifecycle ----------
s, b = call_retry("POST", "devLogin", {"email": "dev1@example.com", "password": "SuperSecret123"})
TMP = b.get("data", {}).get("token")
check("login issues token", s == 200 and TMP, (s, b.get("error")))
s, b = call_retry("POST", "devSession", {"action": "logout"}, {"X-Developer-Token": TMP})
check("logout", s == 200, (s, b))
s, b = call_retry("POST", "devSession", {"action": "me"}, {"X-Developer-Token": TMP})
check("revoked session rejected", s == 401 and b["error"]["code"] == "token_revoked", (s, b))
s, b = call_retry("POST", "devSession", {"action": "me"}, {"X-Developer-Token": "dst_fake"})
check("fake session rejected", s == 401, (s, b))
s, b = call_retry("POST", "devSession", {"action": "me"}, {"X-Developer-Token": DEV})
check("devSession me returns profile+overview", s == 200 and b["data"]["developer"]["email"] == "dev1@example.com", (s, b.get("error")))
s, b = call_retry("POST", "devLogin", {"email": "dev1@example.com", "password": "wrongpass"})
check("wrong password rejected", s == 401, (s, b))

passed = sum(1 for _, ok, _ in results if ok)
print("\n==== %d/%d PASSED ====" % (passed, len(results)))
for n, ok, d in results:
    if not ok: print("FAILED:", n, "|", str(d)[:200])
