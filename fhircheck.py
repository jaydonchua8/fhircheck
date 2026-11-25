"""fhircheck: run conformance, write-path, security, network and latency checks against FHIR R4 servers.

Usage:
  python fhircheck.py                          # all servers in servers.json
  python fhircheck.py --only hapi-r4 --perf-n 10
  python fhircheck.py --baseline baseline.json # exit 1 if a check that passed in the baseline now fails
  python fhircheck.py --update-baseline        # write current results as the new baseline
"""
import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import checks
import netprobe
from fhirclient import Client

HERE = os.path.dirname(os.path.abspath(__file__))


def run_server(srv, perf_n=20, timeout=20.0, write=True, **opts):
    cl = Client(srv["base"], timeout=timeout)
    ctx = {"run_id": "fhircheck-" + uuid.uuid4().hex[:10], "write": write and srv.get("write", False)}
    ctx.update(opts)  # e.g. index_wait, perf_pause for tests
    t0 = time.perf_counter()
    ctx["net"] = netprobe.probe(srv["base"])
    results = [f(cl, ctx) for f in checks.CONFORMANCE]
    if ctx["write"]:
        results += [f(cl, ctx) for f in checks.WRITE]
        if ctx.get("pid") and not ctx.get("deleted"):
            cl.delete(f"Patient/{ctx['pid']}")  # best-effort cleanup if a write check failed midway
    else:
        results += [checks.Result(cid, "write", "skip", "read-only server") for cid in checks.WRITE_IDS]
    results += [f(cl, ctx) for f in checks.SECURITY]
    if perf_n > 0:
        results.append(checks.p_latency(cl, ctx, n=perf_n))
    return {
        "server": srv["name"], "base": srv["base"],
        "network": ctx["net"], "latency": ctx.get("latency"),
        "requests": cl.requests, "seconds": round(time.perf_counter() - t0, 1),
        "results": [r.as_dict() for r in results],
    }


def summarize(run):
    counts = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
    for r in run["results"]:
        counts[r["status"]] += 1
    return counts


def regressions(current, baseline):
    """Checks that passed in the baseline and do not pass now, per server."""
    base = {(s["server"], r["id"]): r["status"] for s in baseline.get("servers", []) for r in s["results"]}
    out = []
    for s in current["servers"]:
        for r in s["results"]:
            if base.get((s["server"], r["id"])) == "pass" and r["status"] == "fail":
                out.append({"server": s["server"], "id": r["id"], "detail": r["detail"]})
    return out


def markdown(report, regs):
    lines = [f"# fhircheck report", "", f"Run {report['started']} on {report['platform']}", ""]
    for s in report["servers"]:
        c = summarize(s)
        n = s["network"]
        lines += [f"## {s['server']} ({s['base']})", "",
                  f"{c['pass']} pass, {c['fail']} fail, {c['warn']} warn, {c['skip']} skip; "
                  f"{s['requests']} requests in {s['seconds']} s", ""]
        if "error" in n:
            lines.append(f"Network: {n['error']}")
        else:
            lines.append(f"Network: DNS {n.get('dns_ms')} ms, TCP {n.get('tcp_connect_ms')} ms, "
                         f"TLS {n.get('tls_handshake_ms')} ms ({n.get('tls_version')}), cert {n.get('cert_days_left')} days")
        if s.get("latency"):
            l = s["latency"]
            lines.append(f"Latency: p50 {l['p50_ms']} ms, p95 {l['p95_ms']} ms, max {l['max_ms']} ms over {l['ok']}/{l['n']}")
        lines += ["", "| check | status | detail |", "|---|---|---|"]
        lines += [f"| {r['id']} | {r['status']} | {r['detail']} |" for r in s["results"]]
        lines.append("")
    lines.append("## Regressions vs baseline")
    lines.append("")
    lines += [f"- {g['server']} {g['id']}: {g['detail']}" for g in regs] or ["None."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--servers", default=os.path.join(HERE, "servers.json"))
    ap.add_argument("--only", action="append", help="server name to run (repeatable)")
    ap.add_argument("--out", default="results")
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--perf-n", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args(argv)

    with open(a.servers) as f:
        servers = json.load(f)
    if a.only:
        servers = [s for s in servers if s["name"] in a.only]
    report = {"started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "platform": sys.platform, "python": sys.version.split()[0], "servers": []}
    for srv in servers:
        print(f"== {srv['name']} {srv['base']}", flush=True)
        run = run_server(srv, perf_n=a.perf_n, timeout=a.timeout, write=not a.no_write)
        report["servers"].append(run)
        for r in run["results"]:
            print(f"  {r['status']:5} {r['id']:24} {r['detail']}", flush=True)

    regs = []
    if a.baseline and os.path.exists(a.baseline):
        with open(a.baseline) as f:
            regs = regressions(report, json.load(f))
    report["regressions"] = regs
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, f"report-{sys.platform}.json"), "w") as f:
        json.dump(report, f, indent=1)
    with open(os.path.join(a.out, f"report-{sys.platform}.md"), "w", encoding="utf-8") as f:
        f.write(markdown(report, regs))
    if a.update_baseline:
        with open(a.baseline or "baseline.json", "w") as f:
            json.dump(report, f, indent=1)
    for g in regs:
        print(f"REGRESSION {g['server']} {g['id']}: {g['detail']}")
    return 1 if regs else 0


if __name__ == "__main__":
    sys.exit(main())
