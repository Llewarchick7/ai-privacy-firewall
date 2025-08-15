#!/usr/bin/env python3
"""
Pytest-friendly smoke tests for the AI Privacy Firewall backend API.
Skips gracefully if the backend server isn't running locally.
"""

import requests
import pytest

BASE_URL = "http://localhost:8000"


def _call_endpoint(method: str, endpoint: str, data=None):
    url = f"{BASE_URL}{endpoint}"
    if method.upper() == "GET":
        return requests.get(url, timeout=3)
    elif method.upper() == "POST":
        return requests.post(url, json=data, timeout=3)
    else:
        raise ValueError("Unsupported method")


def _backend_available() -> bool:
    try:
        resp = requests.get(f"{BASE_URL}/api/health", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


@pytest.mark.smoke
def test_health_and_root_endpoints():
    if not _backend_available():
        pytest.skip("Backend not running on localhost:8000; skipping smoke test")

    r_health = _call_endpoint("GET", "/api/health")
    assert r_health.status_code == 200

    r_root = _call_endpoint("GET", "/")
    assert r_root.status_code == 200
