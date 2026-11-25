"""Network-level probes: DNS resolution, TCP connect, TLS handshake, certificate expiry."""
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone


def probe(base_url, timeout=10.0):
    u = urllib.parse.urlsplit(base_url)
    host = u.hostname
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    out = {"host": host, "port": port, "tls": tls}
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        out["error"] = f"dns: {e}"
        return out
    out["dns_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["addresses"] = sorted({i[4][0] for i in infos})
    family, _, _, _, addr = infos[0][0], None, None, None, infos[0][4]
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t1 = time.perf_counter()
    try:
        sock.connect(addr)
    except OSError as e:
        sock.close()
        out["error"] = f"tcp: {e}"
        return out
    out["tcp_connect_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    if not tls:
        sock.close()
        return out
    ctx = ssl.create_default_context()
    t2 = time.perf_counter()
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            out["tls_handshake_ms"] = round((time.perf_counter() - t2) * 1000, 1)
            out["tls_version"] = s.version()
            out["cipher"] = s.cipher()[0]
            cert = s.getpeercert()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            out["cert_days_left"] = (exp - datetime.now(timezone.utc)).days
    except (ssl.SSLError, OSError) as e:
        out["error"] = f"tls: {e}"
    finally:
        sock.close()
    return out


def tls_at_least_12(version):
    return version in ("TLSv1.2", "TLSv1.3")
