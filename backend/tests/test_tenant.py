"""Tests for multi-tenant organization management."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///")
    from database import Base, engine, init_db
    from models import Organization, OrgMember, ApiKey, PolicyVersion, ScanJob, EvalRun, BaselineFinding
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    init_db()


def _make_admin(db):
    from auth import hash_password
    from database import User
    user = User(email="admin@test.com", name="Admin", password_hash=hash_password("pass"), role="admin")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _login(client, email="admin@test.com", password="pass"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return r.cookies


def test_create_org_and_list():
    from main import app
    from database import SessionLocal
    client = TestClient(app)
    db = SessionLocal()
    try:
        _make_admin(db)
    finally:
        db.close()

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
    from database import SessionLocal, User
    from auth import hash_password
    client = TestClient(app)
    db = SessionLocal()
    try:
        _make_admin(db)
        viewer = User(email="viewer@test.com", name="Viewer", password_hash=hash_password("pass"), role="viewer")
        db.add(viewer)
        db.commit()
    finally:
        db.close()

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
    from database import SessionLocal
    client = TestClient(app)
    db = SessionLocal()
    try:
        _make_admin(db)
    finally:
        db.close()

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
    from database import SessionLocal
    client = TestClient(app)
    db = SessionLocal()
    try:
        _make_admin(db)
    finally:
        db.close()

    cookies = _login(client)
    client.post("/api/orgs", json={"name": "Acme", "slug": "dup"}, cookies=cookies)
    r = client.post("/api/orgs", json={"name": "Acme2", "slug": "dup"}, cookies=cookies)
    assert r.status_code == 409
