"""Auth REST endpoints — fully Mongo-backed (v0.4 port)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

import repositories as repos
from auth import (
    SESSION_COOKIE_NAME,
    SessionUser,
    create_session_token,
    get_current_user,
    verify_password,
)
from config import settings


router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class MeResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str


def _to_me(user: SessionUser) -> MeResponse:
    return MeResponse(id=user.id, email=user.email, name=user.name, role=user.role)


@router.post("/login", response_model=MeResponse)
def login(body: LoginRequest, response: Response):
    email = body.email.lower().strip()
    doc = repos.find_user_by_email(email)
    if not doc or not verify_password(body.password, doc.get("password_hash") or ""):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user = SessionUser.from_doc(doc)
    token = create_session_token(user)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return _to_me(user)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=Optional[MeResponse])
def me(user: Optional[SessionUser] = Depends(get_current_user)):
    if user is None:
        return None
    return _to_me(user)
