# fhircheck

A test suite that checks live FHIR R4 servers for spec conformance, safe write behavior, error handling and latency, and fails CI when a check that used to pass starts failing.

FHIR is the HL7 standard most health data platforms expose (InterSystems IRIS for Health and HealthShare included). fhircheck runs the same set of checks against any FHIR R4 base URL and is pointed at three public test servers in `servers.json`.

Python standard library only. Runs on Linux and Windows.

## What it checks

| Area | Checks |
|---|---|
| Network | DNS resolution time, TCP connect time, TLS handshake time, negotiated TLS version, certificate days left |
| Conformance | CapabilityStatement and FHIR version, `application/fhir+json` content type, Patient read and search declared, 404/410 with an OperationOutcome for a missing resource, searchset Bundle that honors `_count` |
| Write path | create returns 201 with an id and Location, read back with ETag, update bumps `meta.versionId`, vread of version 1 is unchanged, search by identifier finds the new record, a stale `If-Match` is rejected, delete makes the record unreadable |
| Security (benign probes) | TLS 1.2 or newer, HSTS and nosniff headers, malformed JSON is rejected with a 4xx and no stack trace, invalid search values and quote characters do not cause a 5xx or leak internals |
| Performance | p50 / p95 / max latency of a small search over N sequential requests, with a p95 budget |

Write checks only run on servers marked `"write": true`. They create one synthetic Patient tagged with a run id and delete it at the end, including after a failed check. Requests are sequential with a pause between latency samples, so the suite stays light on shared public servers.

## Running it

```bash
./run.sh                          # Linux / macOS: unit tests, then the live suite
./run.sh --only hapi-r4 --perf-n 10
```

```powershell
.\run.ps1                         # Windows
.\run.ps1 -Only hapi-r4 -NoWrite
```

Each run writes `results/report-<platform>.json` and a Markdown report. With `--baseline baseline.json`, the exit code is 1 if any check that passed in the baseline now fails, which is what gates CI. `--update-baseline` records the current run as the new baseline.

## CI

`.github/workflows/fhircheck.yml` runs the unit tests and the live suite on `ubuntu-latest` (Bash) and `windows-latest` (PowerShell) on every push and once a day, publishes the Markdown report to the job summary and uploads the JSON as an artifact. `.gitlab-ci.yml` and `Jenkinsfile` run the same scripts on those systems; they are included but this repository only exercises GitHub Actions.

## Tests

`test_fhircheck.py` runs every check against `mockfhir.py`, an in-memory FHIR server with 13 injectable bugs (wrong content type, missing Location, no version bump, accepting a stale ETag, delete that does nothing, 500 on malformed input, stack trace in an error body, and others). Each test asserts the bug is caught by the check aimed at it and does not make unrelated checks fail.

```bash
python -m unittest -v
```

## Limits

- Three public test servers are not production systems; their data and behavior change and they are sometimes slow or down.
- The security checks are benign input-handling probes, not a penetration test, and do not cover authentication because the public servers are open.
- Latency is measured from GitHub's runners, so it includes their network path.
