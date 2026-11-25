"""Minimal FHIR REST client on the standard library, with timing."""
import json
import time
import urllib.error
import urllib.request

FHIR_JSON = "application/fhir+json"
UA = "fhircheck/0.1 (+https://github.com/jaydonchua8/fhircheck)"


class Response:
    def __init__(self, status, headers, body, ms, error=None):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body or b""
        self.ms = ms
        self.error = error

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    @property
    def content_type(self):
        return self.headers.get("content-type", "").split(";")[0].strip().lower()


class Client:
    def __init__(self, base, timeout=20.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.requests = 0

    def url(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.base + "/" + path.lstrip("/")

    def request(self, method, path, body=None, headers=None, raw=False):
        h = {"Accept": FHIR_JSON, "User-Agent": UA}
        data = None
        if body is not None:
            data = body if raw else json.dumps(body).encode("utf-8")
            h["Content-Type"] = FHIR_JSON
        h.update(headers or {})
        req = urllib.request.Request(self.url(path), data=data, headers=h, method=method)
        self.requests += 1
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                b = r.read()
                return Response(r.status, dict(r.headers), b, (time.perf_counter() - t0) * 1000)
        except urllib.error.HTTPError as e:
            b = e.read() if hasattr(e, "read") else b""
            return Response(e.code, dict(e.headers or {}), b, (time.perf_counter() - t0) * 1000)
        except Exception as e:  # network error, timeout, TLS failure
            return Response(0, {}, b"", (time.perf_counter() - t0) * 1000, error=f"{type(e).__name__}: {e}")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body, **kw):
        return self.request("POST", path, body=body, **kw)

    def put(self, path, body, **kw):
        return self.request("PUT", path, body=body, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)
