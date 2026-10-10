"""ENG-1066 — successful health probes stay out of the access log.

Kubernetes probes every pod every few seconds and each probe was one uvicorn
access-log line in CloudWatch. Successful probes are dropped; failing probes
and every real request are kept. uvicorn access records carry
(client_addr, method, full_path, http_version, status_code).
"""
import logging

from postgres_mcp.server import HealthCheckAccessLogFilter

FMT = '%s - "%s %s HTTP/%s" %d'


def _access(path, status, method="GET"):
    return logging.LogRecord("uvicorn.access", logging.INFO, "h11_impl.py", 1, FMT,
                             ("10.0.146.84:37556", method, path, "1.1", status), None)


def test_successful_probes_are_dropped():
    f = HealthCheckAccessLogFilter()
    for path in ("/health", "/healthz", "/health/db", "/", "/health?verbose=1"):
        record = _access(path, 200)
        assert f'"GET {path} HTTP/1.1" 200' in record.getMessage()  # precondition: renders like uvicorn
        assert f.filter(record) is False, path


def test_failing_probes_and_real_requests_are_kept():
    f = HealthCheckAccessLogFilter()
    assert f.filter(_access("/health", 503)) is True
    assert f.filter(_access("/health/db", 500)) is True
    assert f.filter(_access("/mcp", 200, method="POST")) is True
    assert f.filter(_access("/sse", 200)) is True
    assert f.filter(_access("/healthcheck-lookalike", 200)) is True
    odd = logging.LogRecord("uvicorn.access", logging.INFO, "x", 1, "no args", None, None)
    assert f.filter(odd) is True
