"""FHIR R4 conformance, write-path, security and performance checks.

Every check returns a Result. Status is one of pass, fail, warn, skip.
Write checks create a synthetic Patient tagged with a run id and delete it afterwards.
"""
import json
import statistics
import time
import uuid

import netprobe

LEAK_MARKERS = ("Traceback (most recent call last)", "\tat org.", "\tat java.", "at System.",
                "NullPointerException", "SQLException", "stack trace")


class Result:
    def __init__(self, cid, category, status, detail="", ms=None):
        self.id, self.category, self.status, self.detail, self.ms = cid, category, status, detail, ms

    def as_dict(self):
        d = {"id": self.id, "category": self.category, "status": self.status, "detail": self.detail}
        if self.ms is not None:
            d["ms"] = round(self.ms, 1)
        return d


def _oo(resp):
    j = resp.json()
    return isinstance(j, dict) and j.get("resourceType") == "OperationOutcome"


def _leaks(resp):
    t = resp.text
    return [m.strip() for m in LEAK_MARKERS if m in t]


def _net(resp):
    return f"network error: {resp.error}" if resp.error else f"HTTP {resp.status}"


# ---------------------------------------------------------------- conformance

def c_metadata(cl, ctx):
    r = cl.get("metadata")
    j = r.json() or {}
    ctx["capability"] = j
    if r.status != 200:
        return Result("C01-metadata", "conformance", "fail", _net(r), r.ms)
    if j.get("resourceType") != "CapabilityStatement":
        return Result("C01-metadata", "conformance", "fail", f"resourceType={j.get('resourceType')}", r.ms)
    v = str(j.get("fhirVersion", ""))
    if not v.startswith("4.0"):
        return Result("C01-metadata", "conformance", "fail", f"fhirVersion={v}, expected 4.0.x", r.ms)
    return Result("C01-metadata", "conformance", "pass", f"fhirVersion={v}", r.ms)


def c_content_type(cl, ctx):
    r = cl.get("metadata")
    if r.status != 200:
        return Result("C02-content-type", "conformance", "fail", _net(r), r.ms)
    ct = r.content_type
    if ct == "application/fhir+json":
        return Result("C02-content-type", "conformance", "pass", ct, r.ms)
    if ct == "application/json":
        return Result("C02-content-type", "conformance", "warn", "application/json instead of application/fhir+json", r.ms)
    return Result("C02-content-type", "conformance", "fail", f"content-type={ct!r}", r.ms)


def c_patient_declared(cl, ctx):
    cap = ctx.get("capability") or {}
    for rest in cap.get("rest", []):
        for res in rest.get("resource", []):
            if res.get("type") == "Patient":
                codes = {i.get("code") for i in res.get("interaction", [])}
                missing = {"read", "search-type"} - codes
                if missing:
                    return Result("C03-patient-declared", "conformance", "fail", f"missing {sorted(missing)}")
                return Result("C03-patient-declared", "conformance", "pass", f"{len(codes)} interactions")
    return Result("C03-patient-declared", "conformance", "fail", "Patient not in CapabilityStatement")


def c_read_missing(cl, ctx):
    r = cl.get(f"Patient/fhircheck-missing-{uuid.uuid4().hex[:12]}")
    if r.status not in (404, 410):
        return Result("C04-read-missing", "conformance", "fail", f"expected 404/410, got {_net(r)}", r.ms)
    if not _oo(r):
        return Result("C04-read-missing", "conformance", "warn", f"HTTP {r.status} without OperationOutcome", r.ms)
    return Result("C04-read-missing", "conformance", "pass", f"HTTP {r.status} + OperationOutcome", r.ms)


def c_search_bundle(cl, ctx):
    r = cl.get("Patient?_count=2")
    j = r.json() or {}
    if r.status != 200:
        return Result("C05-search-bundle", "conformance", "fail", _net(r), r.ms)
    if j.get("resourceType") != "Bundle" or j.get("type") != "searchset":
        return Result("C05-search-bundle", "conformance", "fail",
                      f"resourceType={j.get('resourceType')} type={j.get('type')}", r.ms)
    n = len(j.get("entry", []))
    if n > 2:
        return Result("C05-search-bundle", "conformance", "fail", f"_count=2 returned {n} entries", r.ms)
    return Result("C05-search-bundle", "conformance", "pass", f"searchset, {n} entries", r.ms)


# ---------------------------------------------------------------- write path

def _patient(run_id, family="Fhircheck"):
    return {"resourceType": "Patient",
            "identifier": [{"system": "urn:fhircheck:run", "value": run_id}],
            "name": [{"family": family, "given": ["Test"]}],
            "gender": "unknown", "birthDate": "2000-01-01"}


def w_create(cl, ctx):
    run_id = ctx["run_id"]
    r = cl.post("Patient", _patient(run_id), headers={"Prefer": "return=representation"})
    if r.status != 201:
        return Result("W01-create", "write", "fail", f"expected 201, got {_net(r)}", r.ms)
    loc = r.headers.get("location") or r.headers.get("content-location") or ""
    j = r.json() or {}
    pid = j.get("id")
    if not pid and "/Patient/" in loc:
        pid = loc.split("/Patient/")[1].split("/")[0]
    if not pid:
        return Result("W01-create", "write", "fail", "201 but no id in body or Location", r.ms)
    ctx["pid"] = pid
    if not loc:
        return Result("W01-create", "write", "warn", f"id={pid} but no Location header", r.ms)
    return Result("W01-create", "write", "pass", f"id={pid}", r.ms)


def w_read_back(cl, ctx):
    pid = ctx.get("pid")
    if not pid:
        return Result("W02-read-back", "write", "skip", "no created id")
    r = cl.get(f"Patient/{pid}")
    j = r.json() or {}
    if r.status != 200:
        return Result("W02-read-back", "write", "fail", _net(r), r.ms)
    fam = (j.get("name") or [{}])[0].get("family")
    if fam != "Fhircheck":
        return Result("W02-read-back", "write", "fail", f"family={fam!r}", r.ms)
    ctx["etag"] = r.headers.get("etag", "")
    ctx["v1"] = (j.get("meta") or {}).get("versionId")
    if not ctx["etag"]:
        return Result("W02-read-back", "write", "warn", "read ok but no ETag header", r.ms)
    return Result("W02-read-back", "write", "pass", f"ETag {ctx['etag']}", r.ms)


def w_update_version(cl, ctx):
    pid = ctx.get("pid")
    if not pid:
        return Result("W03-update-version", "write", "skip", "no created id")
    body = _patient(ctx["run_id"], family="Fhircheck-Updated")
    body["id"] = pid
    r = cl.put(f"Patient/{pid}", body, headers={"Prefer": "return=representation"})
    if r.status != 200:
        return Result("W03-update-version", "write", "fail", f"expected 200, got {_net(r)}", r.ms)
    g = cl.get(f"Patient/{pid}")
    v2 = ((g.json() or {}).get("meta") or {}).get("versionId")
    v1 = ctx.get("v1")
    ctx["v2"] = v2
    if v1 is None or v2 is None or str(v1) == str(v2):
        return Result("W03-update-version", "write", "fail", f"versionId {v1} -> {v2}", r.ms)
    return Result("W03-update-version", "write", "pass", f"versionId {v1} -> {v2}", r.ms)


def w_vread(cl, ctx):
    pid, v1 = ctx.get("pid"), ctx.get("v1")
    if not pid or v1 is None:
        return Result("W04-vread", "write", "skip", "no version to read")
    r = cl.get(f"Patient/{pid}/_history/{v1}")
    fam = ((r.json() or {}).get("name") or [{}])[0].get("family")
    if r.status != 200:
        return Result("W04-vread", "write", "fail", _net(r), r.ms)
    if fam != "Fhircheck":
        return Result("W04-vread", "write", "fail", f"version {v1} family={fam!r}", r.ms)
    return Result("W04-vread", "write", "pass", f"version {v1} unchanged", r.ms)


def w_search_identifier(cl, ctx, tries=4):
    wait = ctx.get("index_wait", 2.0)
    pid = ctx.get("pid")
    if not pid:
        return Result("W05-search-identifier", "write", "skip", "no created id")
    q = f"Patient?identifier=urn:fhircheck:run|{ctx['run_id']}"
    total = 0.0
    for i in range(tries):
        r = cl.get(q)
        total += r.ms
        ids = [e.get("resource", {}).get("id") for e in (r.json() or {}).get("entry", [])]
        if pid in ids:
            return Result("W05-search-identifier", "write", "pass", f"found after {i + 1} tries", total)
        time.sleep(wait)
    return Result("W05-search-identifier", "write", "fail", f"not indexed after {tries} tries", total)


def w_conditional_update(cl, ctx):
    pid, etag = ctx.get("pid"), ctx.get("etag")
    if not pid or not etag:
        return Result("W06-stale-etag", "write", "skip", "no ETag")
    body = _patient(ctx["run_id"], family="Fhircheck-Stale")
    body["id"] = pid
    r = cl.put(f"Patient/{pid}", body, headers={"If-Match": etag})  # etag is from version 1, now stale
    if r.status in (409, 412):
        return Result("W06-stale-etag", "write", "pass", f"stale If-Match rejected with {r.status}", r.ms)
    if 200 <= r.status < 300:
        return Result("W06-stale-etag", "write", "warn", f"stale If-Match accepted ({r.status}); lost-update risk", r.ms)
    return Result("W06-stale-etag", "write", "fail", _net(r), r.ms)


def w_delete(cl, ctx):
    pid = ctx.get("pid")
    if not pid:
        return Result("W07-delete", "write", "skip", "no created id")
    r = cl.delete(f"Patient/{pid}")
    if r.status not in (200, 202, 204):
        return Result("W07-delete", "write", "fail", f"expected 200/204, got {_net(r)}", r.ms)
    g = cl.get(f"Patient/{pid}")
    if g.status not in (404, 410):
        return Result("W07-delete", "write", "fail", f"read after delete returned {g.status}", r.ms)
    ctx["deleted"] = True
    return Result("W07-delete", "write", "pass", f"read after delete -> {g.status}", r.ms)


# ---------------------------------------------------------------- security (benign probes only)

def s_tls(cl, ctx):
    n = ctx.get("net") or {}
    if not n.get("tls"):
        return Result("S01-tls", "security", "fail", "server is not served over HTTPS")
    if n.get("error"):
        return Result("S01-tls", "security", "fail", n["error"])
    v = n.get("tls_version")
    days = n.get("cert_days_left")
    if not netprobe.tls_at_least_12(v):
        return Result("S01-tls", "security", "fail", f"negotiated {v}")
    if days is not None and days < 14:
        return Result("S01-tls", "security", "warn", f"{v}, certificate expires in {days} days")
    return Result("S01-tls", "security", "pass", f"{v}, cert {days} days left")


def s_headers(cl, ctx):
    r = cl.get("metadata")
    missing = [h for h in ("strict-transport-security", "x-content-type-options") if h not in r.headers]
    if r.status != 200:
        return Result("S02-headers", "security", "fail", _net(r), r.ms)
    if missing:
        return Result("S02-headers", "security", "warn", "missing " + ", ".join(missing), r.ms)
    return Result("S02-headers", "security", "pass", "HSTS and nosniff present", r.ms)


def s_malformed_json(cl, ctx):
    if not ctx.get("write"):
        return Result("S03-malformed-json", "security", "skip", "read-only server")
    r = cl.request("POST", "Patient", body=b'{"resourceType": "Patient", "name": [', raw=True)
    if r.status >= 500 or r.status == 0:
        return Result("S03-malformed-json", "security", "fail", f"malformed body caused {_net(r)}", r.ms)
    if not (400 <= r.status < 500):
        return Result("S03-malformed-json", "security", "fail", f"malformed body accepted with {r.status}", r.ms)
    leaks = _leaks(r)
    if leaks:
        return Result("S03-malformed-json", "security", "fail", f"{r.status} but leaks {leaks}", r.ms)
    return Result("S03-malformed-json", "security", "pass", f"rejected with {r.status}", r.ms)


def s_bad_param(cl, ctx):
    r = cl.get("Patient?birthdate=not-a-date&_count=1")
    if r.status >= 500 or r.status == 0:
        return Result("S04-bad-param", "security", "fail", f"invalid date caused {_net(r)}", r.ms)
    leaks = _leaks(r)
    if leaks:
        return Result("S04-bad-param", "security", "fail", f"{r.status} but leaks {leaks}", r.ms)
    return Result("S04-bad-param", "security", "pass", f"handled with {r.status}", r.ms)


def s_injection_param(cl, ctx):
    r = cl.get("Patient?family=" + "x%27%20OR%20%271%27%3D%271&_count=1")
    if r.status >= 500 or r.status == 0:
        return Result("S05-injection-string", "security", "fail", f"quote payload caused {_net(r)}", r.ms)
    leaks = _leaks(r)
    if leaks:
        return Result("S05-injection-string", "security", "fail", f"{r.status} but leaks {leaks}", r.ms)
    n = len((r.json() or {}).get("entry", []))
    return Result("S05-injection-string", "security", "pass", f"handled with {r.status}, {n} entries", r.ms)


# ---------------------------------------------------------------- performance

def percentile(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def p_latency(cl, ctx, n=20, budget_ms=2000.0, pause=None):
    pause = ctx.get("perf_pause", 0.25) if pause is None else pause
    ms, errors = [], 0
    for _ in range(n):
        r = cl.get("Patient?_count=1&_summary=true")
        if r.status == 200:
            ms.append(r.ms)
        else:
            errors += 1
        time.sleep(pause)  # stay polite on shared public servers
    if not ms:
        return Result("P01-latency", "performance", "fail", f"0/{n} requests succeeded")
    p50, p95 = percentile(ms, 50), percentile(ms, 95)
    ctx["latency"] = {"n": n, "ok": len(ms), "p50_ms": round(p50, 1), "p95_ms": round(p95, 1),
                      "max_ms": round(max(ms), 1), "mean_ms": round(statistics.mean(ms), 1)}
    detail = f"p50 {p50:.0f} ms, p95 {p95:.0f} ms, {errors} errors of {n}"
    if errors or p95 > budget_ms:
        return Result("P01-latency", "performance", "warn", detail + f" (budget p95 {budget_ms:.0f} ms)", p95)
    return Result("P01-latency", "performance", "pass", detail, p95)


CONFORMANCE = [c_metadata, c_content_type, c_patient_declared, c_read_missing, c_search_bundle]
WRITE = [w_create, w_read_back, w_update_version, w_vread, w_search_identifier, w_conditional_update, w_delete]
SECURITY = [s_tls, s_headers, s_malformed_json, s_bad_param, s_injection_param]

WRITE_IDS = ["W01-create", "W02-read-back", "W03-update-version", "W04-vread",
             "W05-search-identifier", "W06-stale-etag", "W07-delete"]
