import json
import os
import tempfile
import unittest

import checks
import fhircheck
import netprobe
from fhirclient import Client
from mockfhir import MockFHIR


def run(faults=(), write=True, perf_n=3):
    with MockFHIR(faults) as m:
        srv = {"name": "mock", "base": m.base, "write": write}
        rep = fhircheck.run_server(srv, perf_n=perf_n, timeout=5, index_wait=0.0, perf_pause=0.0)
        return {r["id"]: r for r in rep["results"]}, rep, m


class Healthy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res, cls.rep, cls.m = run()

    def test_conformance_and_write_pass(self):
        for cid, r in self.res.items():
            if r["category"] in ("conformance", "write"):
                self.assertEqual(r["status"], "pass", (cid, r["detail"]))

    def test_security_on_plain_http(self):
        self.assertEqual(self.res["S01-tls"]["status"], "fail")           # not HTTPS
        self.assertEqual(self.res["S02-headers"]["status"], "warn")       # no HSTS
        for cid in ("S03-malformed-json", "S04-bad-param", "S05-injection-string"):
            self.assertEqual(self.res[cid]["status"], "pass", cid)

    def test_latency_recorded(self):
        self.assertEqual(self.res["P01-latency"]["status"], "pass")
        self.assertEqual(self.rep["latency"]["ok"], 3)

    def test_cleanup_deleted_patient(self):
        self.assertEqual(len(self.m.store.deleted), 1)

    def test_network_probe_plain(self):
        n = self.rep["network"]
        self.assertFalse(n["tls"])
        self.assertIn("tcp_connect_ms", n)
        self.assertIn("127.0.0.1", n["addresses"])


class Faults(unittest.TestCase):
    """Each injected server bug must be caught by the check aimed at it."""
    CASES = [
        ("old_fhir", "C01-metadata", "fail"),
        ("wrong_ctype", "C02-content-type", "warn"),
        ("no_patient_in_cap", "C03-patient-declared", "fail"),
        ("no_oo_404", "C04-read-missing", "warn"),
        ("ignore_count", "C05-search-bundle", "fail"),
        ("no_location", "W01-create", "warn"),
        ("no_version_bump", "W03-update-version", "fail"),
        ("no_index", "W05-search-identifier", "fail"),
        ("accept_stale_etag", "W06-stale-etag", "warn"),
        ("delete_noop", "W07-delete", "fail"),
        ("500_on_malformed", "S03-malformed-json", "fail"),
        ("leak_trace", "S03-malformed-json", "fail"),
        ("500_on_bad_date", "S04-bad-param", "fail"),
    ]

    def test_each_fault_is_caught(self):
        for fault, cid, want in self.CASES:
            with self.subTest(fault=fault):
                res, _, _ = run([fault], perf_n=0)
                self.assertEqual(res[cid]["status"], want, (fault, res[cid]["detail"]))

    def test_faults_do_not_cause_unrelated_failures(self):
        allowed = {"S01-tls"}
        for fault, cid, _ in self.CASES:
            with self.subTest(fault=fault):
                res, _, _ = run([fault], perf_n=0)
                other = [k for k, r in res.items() if r["status"] == "fail" and k != cid and k not in allowed]
                # ignore_count breaks the identifier search only if more than _count patients exist; no_version_bump
                # also makes the stale ETag look current. Both are expected knock-on effects.
                knock_on = {"no_version_bump": {"W06-stale-etag"}}
                self.assertEqual(set(other) - knock_on.get(fault, set()), set(), fault)

    def test_cleanup_after_midway_failure(self):
        _, _, m = run(["no_version_bump"], perf_n=0)
        self.assertEqual(len(m.store.deleted), 1)


class ReadOnly(unittest.TestCase):
    def test_write_checks_skipped(self):
        res, _, m = run(write=False, perf_n=0)
        self.assertTrue(all(r["status"] == "skip" for r in res.values() if r["category"] == "write"))
        self.assertEqual(res["S03-malformed-json"]["status"], "skip")
        self.assertEqual(len(m.store.res), 3)  # only the seed records, nothing written


class Unreachable(unittest.TestCase):
    def test_dead_port_fails_cleanly(self):
        srv = {"name": "dead", "base": "http://127.0.0.1:9", "write": True}
        rep = fhircheck.run_server(srv, perf_n=1, timeout=2, index_wait=0.0, perf_pause=0.0)
        res = {r["id"]: r for r in rep["results"]}
        self.assertEqual(res["C01-metadata"]["status"], "fail")
        self.assertIn("network error", res["C01-metadata"]["detail"])
        self.assertIn("error", rep["network"])


class Regression(unittest.TestCase):
    def test_regression_detected_and_gates_exit(self):
        base = {"servers": [{"server": "s", "results": [{"id": "C01", "status": "pass"}, {"id": "C02", "status": "warn"}]}]}
        cur = {"servers": [{"server": "s", "results": [{"id": "C01", "status": "fail", "detail": "x"},
                                                        {"id": "C02", "status": "fail", "detail": "y"}]}]}
        regs = fhircheck.regressions(cur, base)
        self.assertEqual([r["id"] for r in regs], ["C01"])  # warn -> fail is not counted, pass -> fail is

    def test_cli_end_to_end_with_baseline(self):
        with MockFHIR() as good, tempfile.TemporaryDirectory() as d:
            sf = os.path.join(d, "servers.json")
            with open(sf, "w") as f:
                json.dump([{"name": "mock", "base": good.base, "write": True}], f)
            bl = os.path.join(d, "baseline.json")
            out = os.path.join(d, "out")
            self.assertEqual(fhircheck.main(["--servers", sf, "--out", out, "--baseline", bl,
                                             "--update-baseline", "--perf-n", "0"]), 0)
            self.assertTrue(os.path.exists(bl))
            md = [p for p in os.listdir(out) if p.endswith(".md")]
            self.assertEqual(len(md), 1)
            with MockFHIR(["no_version_bump"]) as bad:
                with open(sf, "w") as f:
                    json.dump([{"name": "mock", "base": bad.base, "write": True}], f)
                self.assertEqual(fhircheck.main(["--servers", sf, "--out", os.path.join(d, "o2"),
                                                 "--baseline", bl, "--perf-n", "0"]), 1)


class Units(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(checks.percentile([1, 2, 3, 4, 5], 50), 3)
        self.assertAlmostEqual(checks.percentile(list(range(1, 101)), 95), 95.05)
        self.assertIsNone(checks.percentile([], 50))

    def test_tls_version_rule(self):
        self.assertTrue(netprobe.tls_at_least_12("TLSv1.3"))
        self.assertFalse(netprobe.tls_at_least_12("TLSv1.1"))

    def test_tls_check_flags_old_version_and_expiring_cert(self):
        cl = Client("https://example.invalid")
        r = checks.s_tls(cl, {"net": {"tls": True, "tls_version": "TLSv1.1", "cert_days_left": 300}})
        self.assertEqual(r.status, "fail")
        r = checks.s_tls(cl, {"net": {"tls": True, "tls_version": "TLSv1.3", "cert_days_left": 5}})
        self.assertEqual(r.status, "warn")


if __name__ == "__main__":
    unittest.main()
