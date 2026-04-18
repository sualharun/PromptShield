from fastapi.testclient import TestClient

import main
from auth import (
    SESSION_COOKIE_NAME,
    bootstrap_admin_if_needed,
    create_session_token,
    hash_password,
    verify_password,
)
from database import SessionLocal, User


client = TestClient(main.app)


def _reset_users():
    db = SessionLocal()
    try:
        db.query(User).delete()
        db.commit()
    finally:
        db.close()


def _seed_user(email: str, password: str, role: str = "admin", name: str = "Test") -> User:
    db = SessionLocal()
    try:
        u = User(
            email=email.lower(),
            name=name,
            password_hash=hash_password(password),
            role=role,
        )
        db.add(u)
        db.commit()
        db.refresh(u)
        return u
    finally:
        db.close()


def test_password_hash_roundtrip():
    h = hash_password("correct horse")
    assert verify_password("correct horse", h)
    assert not verify_password("wrong", h)
    assert not verify_password("", h)


def test_login_rejects_unknown_user():
    _reset_users()
    r = client.post(
        "/api/auth/login", json={"email": "nobody@x.com", "password": "x"}
    )
    assert r.status_code == 401


def test_login_sets_cookie_and_me_returns_user():
    _reset_users()
    _seed_user("demo@ibm.com", "demo-pass", role="admin", name="Demo")
    r = client.post(
        "/api/auth/login",
        json={"email": "demo@ibm.com", "password": "demo-pass"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "demo@ibm.com"
    assert body["role"] == "admin"
    # Cookie is set and scoped to the session name.
    assert SESSION_COOKIE_NAME in client.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "demo@ibm.com"

    # Logout clears the cookie; /me returns null.
    out = client.post("/api/auth/logout")
    assert out.status_code == 200
    me2 = client.get("/api/auth/me")
    assert me2.status_code == 200
    assert me2.json() is None


def test_me_returns_null_when_anonymous():
    client.cookies.clear()
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json() is None


def test_require_role_blocks_without_session():
    from fastapi import Depends, FastAPI
    from auth import require_role

    app = FastAPI()

    @app.get("/pm-only")
    def pm_only(user=Depends(require_role("pm", "admin"))):
        return {"role": user.role}

    c = TestClient(app)
    r = c.get("/pm-only")
    assert r.status_code == 401


def test_require_role_rejects_wrong_role():
    from fastapi import Depends, FastAPI
    from auth import require_role

    _reset_users()
    _seed_user("viewer@x.com", "pw", role="viewer")

    app = FastAPI()

    @app.get("/pm-only")
    def pm_only(user=Depends(require_role("pm", "admin"))):
        return {"role": user.role}

    c = TestClient(app)
    c.post("/api/auth/login", json={})  # no-op; route not mounted on this app
    # Log in through the real app to get a signed cookie, then reuse it.
    real = TestClient(main.app)
    r = real.post(
        "/api/auth/login", json={"email": "viewer@x.com", "password": "pw"}
    )
    assert r.status_code == 200
    token = real.cookies.get(SESSION_COOKIE_NAME)
    res = c.get("/pm-only", cookies={SESSION_COOKIE_NAME: token})
    assert res.status_code == 403


def test_bootstrap_admin_creates_once(monkeypatch):
    _reset_users()
    from config import settings

    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "boot@x.com")
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_PASSWORD", "boot-pw")

    db = SessionLocal()
    try:
        bootstrap_admin_if_needed(db)
        bootstrap_admin_if_needed(db)  # second call should be a no-op
        count = db.query(User).filter(User.email == "boot@x.com").count()
        assert count == 1
        user = db.query(User).filter(User.email == "boot@x.com").one()
        assert user.role == "admin"
        assert verify_password("boot-pw", user.password_hash)
    finally:
        db.close()


def test_session_token_roundtrip():
    _reset_users()
    u = _seed_user("roundtrip@x.com", "pw")
    token = create_session_token(u)
    # Directly call /me with the token via header fallback (Authorization: Bearer).
    c = TestClient(main.app)
    c.cookies.clear()
    r = c.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == "roundtrip@x.com"
