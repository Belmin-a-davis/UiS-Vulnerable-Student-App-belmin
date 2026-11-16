"""Shared helpers for the DAT250 SecureApp security regression tests.

These tests are black-box: they talk HTTP to a running instance, exactly like
the Assignment 1 attacks did.   Start the app first:

    docker compose down -v && docker compose up --build -d
    pip install -r tests/requirements.txt
    pytest -v tests/test_regression.py

Environment variables (optional):
    BASE_URL      default http://localhost:18181
"""
import os
import re
import uuid

import pytest
import requests

BASE = os.getenv("BASE_URL", "http://localhost:18181").rstrip("/")
STRONG_PW = "Str0ng-Passw0rd!"


class Client(requests.Session):
    """requests.Session bound to BASE that never follows redirects by default."""

    def request(self, method, url, **kw):
        kw.setdefault("allow_redirects", False)
        kw.setdefault("timeout", 15)
        if url.startswith("/"):
            url = BASE + url
        return super().request(method, url, **kw)

    def login(self, email, password):
        r = self.post("/login", data={"email": email, "password": password})
        return r


def login_as(email, password):
    c = Client()
    r = c.login(email, password)
    assert r.status_code == 302 and "session_token" in c.cookies, f"login failed for {email}: {r.status_code}"
    return c


def new_student():
    """Register + log in a brand-new throw-away student (never touches seed accounts)."""
    email = f"t{uuid.uuid4().hex[:10]}@test.local"
    anon = Client()
    r = anon.post("/register", data={"email": email, "full_name": "Test User", "password": STRONG_PW})
    assert r.status_code == 302, f"register failed: {r.status_code} {r.text[:200]}"
    c = login_as(email, STRONG_PW)
    c.email = email
    c.user_id = int(re.search(r"/profile/(\d+)", c.post("/profile/update", data={"full_name": "Test User"}).headers["location"]).group(1))
    return c


def role_of(client, user_id):
    html = client.get(f"/profile/{user_id}").text
    m = re.search(r'<strong>Role:</strong>\s*<span class="badge bg-secondary">([^<]+)</span>', html)
    assert m, "could not read role from profile page"
    return m.group(1)


@pytest.fixture(scope="session", autouse=True)
def _app_is_up():
    try:
        requests.get(BASE + "/health", timeout=5).raise_for_status()
    except Exception as exc:  # pragma: no cover
        pytest.exit(f"App not reachable at {BASE}: {exc}", returncode=2)


@pytest.fixture()
def alice():
    return login_as("alice@student.uis.no", "Alice123")


@pytest.fixture()
def bob():
    return login_as("bob@student.uis.no", "Bob123")


@pytest.fixture()
def teacher():
    return login_as("teacher@dat250.local", "Teacher123")


@pytest.fixture()
def admin():
    return login_as("admin@dat250.local", "Admin123")


@pytest.fixture()
def student():
    return new_student()
