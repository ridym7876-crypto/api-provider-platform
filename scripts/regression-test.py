import json, urllib.request, urllib.error, time
B="https://superagent-b31b88fd.base44.app/functions"
ADMIN=open('/tmp/admintoken').read().strip(); DEV=open('/tmp/devtoken').read().strip(); KEY=open('/tmp/apikey').read().strip()
def req(method,fn,payload=None,headers=None,url=None):
    u=url or (B+"/"+fn); data=json.dumps(payload).encode() if payload is not None and method!="GET" else None
    h={"Content-Type":"application/json"};  h.update(headers or {})
    r=urllib.request.Request(u,data=data,headers=h,method=method)
    try:
        with urllib.request.urlopen(r,timeout=90) as resp: return resp.status,json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: return e.code,json.loads(raw)
        except: return e.code,{"raw":raw.decode()[:200]}
out=[]
def check(n,c,d=""):
    out.append((n,bool(c))); print(("PASS " if c else "FAIL ")+n+(("" if c else "  <<< "+str(d)[:250])))

s,b=req("POST","apiGateway",{"body":{}},{"X-Api-Key":KEY},url=B+"/apiGateway?path=/v1/text/slugify&text=Hello%20There")
check("query-param routing (POST + ?path=)",s==200 and b["data"]["slug"]=="hello-there",(s,b))

s,b=req("POST","keyManage",{"action":"create","name":"RL probe 2","rate_limit_per_minute":1},{"X-Developer-Token":DEV})
k=b.get("data",{}).get("api_key")
s1,b1=req("POST","apiGateway",{"api":"data","endpoint":"list-apis"},{"X-Api-Key":k})
s2,b2=req("POST","apiGateway",{"api":"data","endpoint":"list-apis"},{"X-Api-Key":k})
check("rate limit 1/min (durable)",s1==200 and s2==429 and b2["error"]["code"]=="rate_limit_exceeded",(s1,s2,b2.get("error")))

s,b=req("POST","apiManage",{"action":"set_status","slug":"system","status":"inactive"},{"X-Developer-Token":ADMIN})
check("deactivate via slug (no id error)",s==200 and b["data"]["api"]["status"]=="inactive",(s,b.get("error")))
time.sleep(33)
s,b=req("POST","apiGateway",{"api":"system","endpoint":"time"},{"X-Api-Key":KEY})
check("inactive api blocked",s==403 and b["error"]["code"]=="api_inactive",(s,b))
s,b=req("POST","apiManage",{"action":"set_status","slug":"system","status":"active"},{"X-Developer-Token":ADMIN})
check("reactivate",s==200,(s,b.get("error")))
time.sleep(33)
s,b=req("POST","apiGateway",{"api":"system","endpoint":"time"},{"X-Api-Key":KEY})
check("active again",s==200,(s,b))
print("\n%d/%d"%(sum(1 for _,c in out if c),len(out)))
