"""In-memory FHIR R4 Patient server for offline tests, with injectable faults."""
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAULTS = {
    "wrong_ctype", "no_patient_in_cap", "no_oo_404", "ignore_count", "no_location",
    "no_version_bump", "accept_stale_etag", "delete_noop", "500_on_malformed",
    "leak_trace", "500_on_bad_date", "no_index", "slow", "old_fhir",
}


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.res = {}       # id -> list of versions (dicts)
        self.deleted = set()
        self.next = 1


def make_handler(store, faults):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj=None, headers=None):
            body = b"" if obj is None else json.dumps(obj).encode()
            self.send_response(code)
            ct = "application/json" if "wrong_ctype" in faults else "application/fhir+json; charset=utf-8"
            self.send_header("Content-Type", ct)
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _oo(self, code, msg):
            if code == 404 and "no_oo_404" in faults:
                return self._send(404, None)
            return self._send(code, {"resourceType": "OperationOutcome",
                                     "issue": [{"severity": "error", "code": "processing", "diagnostics": msg}]})

        def _parts(self):
            u = urllib.parse.urlsplit(self.path)
            return [p for p in u.path.split("/") if p], urllib.parse.parse_qs(u.query)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n)

        def do_GET(self):
            if "slow" in faults:
                time.sleep(0.05)
            parts, q = self._parts()
            if parts == ["metadata"]:
                inter = [{"code": c} for c in ("read", "vread", "update", "delete", "create", "search-type")]
                res = [] if "no_patient_in_cap" in faults else [{"type": "Patient", "interaction": inter}]
                return self._send(200, {"resourceType": "CapabilityStatement",
                                        "fhirVersion": "3.0.2" if "old_fhir" in faults else "4.0.1",
                                        "rest": [{"mode": "server", "resource": res}]})
            if parts == ["Patient"]:
                if "birthdate" in q and not q["birthdate"][0][:4].isdigit():
                    if "500_on_bad_date" in faults:
                        self.send_response(500); self.end_headers()
                        self.wfile.write(b"java.lang.IllegalArgumentException\n\tat org.example.Search(Search.java:42)")
                        return
                    return self._oo(400, "invalid date")
                with store.lock:
                    items = [v[-1] for k, v in store.res.items() if k not in store.deleted]
                if "identifier" in q and "no_index" not in faults:
                    val = q["identifier"][0].split("|")[-1]
                    items = [i for i in items if any(x.get("value") == val for x in i.get("identifier", []))]
                elif "identifier" in q:
                    items = []
                if "family" in q:
                    items = [i for i in items if i["name"][0]["family"] == q["family"][0]]
                cnt = int(q.get("_count", ["50"])[0])
                if "ignore_count" not in faults:
                    items = items[:cnt]
                return self._send(200, {"resourceType": "Bundle", "type": "searchset",
                                        "entry": [{"resource": i} for i in items]})
            if len(parts) >= 2 and parts[0] == "Patient":
                pid = parts[1]
                with store.lock:
                    if pid in store.deleted:
                        return self._oo(410, "deleted")
                    vers = store.res.get(pid)
                if not vers:
                    return self._oo(404, "not found")
                if len(parts) == 4 and parts[2] == "_history":
                    v = [x for x in vers if x["meta"]["versionId"] == parts[3]]
                    return self._send(200, v[0]) if v else self._oo(404, "no version")
                cur = vers[-1]
                return self._send(200, cur, {"ETag": f'W/"{cur["meta"]["versionId"]}"'})
            return self._oo(404, "unknown path")

        def do_POST(self):
            parts, _ = self._parts()
            raw = self._body()
            try:
                body = json.loads(raw)
            except ValueError:
                if "500_on_malformed" in faults:
                    self.send_response(500); self.end_headers()
                    self.wfile.write(b"Traceback (most recent call last):\n  File \"server.py\"")
                    return
                if "leak_trace" in faults:
                    self.send_response(400); self.end_headers()
                    self.wfile.write(b"bad json\n\tat org.example.Parser.parse(Parser.java:7)")
                    return
                return self._oo(400, "malformed JSON")
            if parts != ["Patient"]:
                return self._oo(404, "unknown")
            with store.lock:
                pid = str(store.next); store.next += 1
                body["id"] = pid
                body["meta"] = {"versionId": "1"}
                store.res[pid] = [body]
            h = {} if "no_location" in faults else {"Location": f"http://x/Patient/{pid}/_history/1"}
            return self._send(201, body, h)

        def do_PUT(self):
            parts, _ = self._parts()
            body = json.loads(self._body())
            pid = parts[1]
            with store.lock:
                vers = store.res.get(pid)
                if not vers or pid in store.deleted:
                    return self._oo(404, "not found")
                cur = vers[-1]["meta"]["versionId"]
                im = self.headers.get("If-Match")
                if im and im != f'W/"{cur}"' and "accept_stale_etag" not in faults:
                    return self._oo(412, "version conflict")
                nv = cur if "no_version_bump" in faults else str(int(cur) + 1)
                body["id"] = pid
                body["meta"] = {"versionId": nv}
                vers.append(body)
            return self._send(200, body, {"ETag": f'W/"{nv}"'})

        def do_DELETE(self):
            parts, _ = self._parts()
            with store.lock:
                if "delete_noop" not in faults:
                    store.deleted.add(parts[1])
            return self._send(204)

    return H


class MockFHIR:
    def __init__(self, faults=()):
        bad = set(faults) - FAULTS
        if bad:
            raise ValueError(f"unknown faults {bad}")
        self.store = Store()
        for i in range(3):  # seed records so paging and _count are observable
            pid = str(self.store.next); self.store.next += 1
            self.store.res[pid] = [{"resourceType": "Patient", "id": pid, "meta": {"versionId": "1"},
                                    "name": [{"family": f"Seed{i}"}]}]
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, set(faults)))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
