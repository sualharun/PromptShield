from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    get_current_user,
    verify_password,
)
from config import settings
from database import User, get_db


router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class MeResponse(BaseModel):
    id: int
    email: str
    name: str
    role: str


def _to_me(user: User) -> MeResponse:
    return MeResponse(id=user.id, email=user.email, name=user.name, role=user.role)


@router.post("/login", response_model=MeResponse)
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
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
def me(user: Optional[User] = Depends(get_current_user)):
    if user is None:
        return None
    return _to_me(user)
