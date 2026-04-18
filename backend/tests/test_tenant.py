"""Tests for multi-tenant organization management — Mongo-backed (v0.4)."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _setup():
    from mongo import C, col
    col(C.USERS).delete_many({})
    col(C.ORGANIZATIONS).delete_many({})


def _make_admin():
    from auth import hash_password
    import repositories as repos
    return repos.insert_user(
        {
            "email": "admin@test.com",
            "name": "Admin",
            "password_hash": hash_password("pass"),
            "role": "admin",
        }
    )


def _login(client, email="admin@test.com", password="pass"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return r.cookies


def test_create_org_and_list():
    from main import app
    client = TestClient(app)
    _make_admin()

    cookies = _login(client)
    r = client.post("/api/orgs", json={"name": "Acme Corp", "slug": "acme"}, cookies=cookies)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Acme Corp"
    assert data["slug"] == "acme"
    assert data["member_count"] == 1

    r = client.get("/api/orgs", cookies=cookies)
    assert r.status_code == 200
    orgs = r.json()
    assert len(orgs) == 1
    assert orgs[0]["slug"] == "acme"


def test_invite_member():
    from main import app
    from auth import hash_password
    import repositories as repos

    client = TestClient(app)
    _make_admin()
    repos.insert_user(
        {
            "email": "viewer@test.com",
            "name": "Viewer",
            "password_hash": hash_password("pass"),
            "role": "viewer",
        }
    )

    cookies = _login(client)
    r = client.post("/api/orgs", json={"name": "Acme", "slug": "acme2"}, cookies=cookies)
    org_id = r.json()["id"]

    r = client.post(
        f"/api/orgs/{org_id}/members",
        json={"email": "viewer@test.com", "role": "viewer"},
        cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"

    r = client.get(f"/api/orgs/{org_id}/members", cookies=cookies)
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_api_key_lifecycle():
    from main import app
    client = TestClient(app)
    _make_admin()

    cookies = _login(client)
    r = client.post("/api/orgs", json={"name": "Acme", "slug": "acme3"}, cookies=cookies)
    org_id = r.json()["id"]

    r = client.post(
        f"/api/orgs/{org_id}/api-keys",
        json={"name": "CI Key"},
        cookies=cookies,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["raw_key"].startswith("ps_")
    key_id = data["id"]

    r = client.get(f"/api/orgs/{org_id}/api-keys", cookies=cookies)
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = client.delete(f"/api/orgs/{org_id}/api-keys/{key_id}", cookies=cookies)
    assert r.status_code == 204


def test_duplicate_slug_rejected():
    from main import app
    client = TestClient(app)
    _make_admin()

    cookies = _login(client)
    client.post("/api/orgs", json={"name": "Acme", "slug": "dup"}, cookies=cookies)
    r = client.post("/api/orgs", json={"name": "Acme2", "slug": "dup"}, cookies=cookies)
    assert r.status_code == 409
