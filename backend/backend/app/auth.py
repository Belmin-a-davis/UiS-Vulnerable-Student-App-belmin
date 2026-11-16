import hashlib
import secrets

from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse

from app.database import run_query

STAFF_ROLES = ("admin", "teacher", "ta")
ALL_ROLES = ("admin", "teacher", "ta", "student")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def create_session(user_id: int) -> str:
    token = secrets.token_hex(16)
    run_query(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, token),
        commit=True,
    )
    return token


def get_user_from_session(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    session = run_query(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token = %s
        """,
        (session_token,),
        fetchone=True,
    )
    return session


def clear_session(token: str):
    run_query("DELETE FROM sessions WHERE session_token = %s", (token,), commit=True)


# ---------------------------------------------------------------------------
# Authorization helpers
# ---------------------------------------------------------------------------

def is_staff(user) -> bool:
    return bool(user) and user["role"] in STAFF_ROLES


def require_staff(request: Request):
    """Return (user, None) if the caller is staff, else (None, response).

    Unauthenticated callers are redirected to /login, authenticated
    non-staff callers receive 403 (not a silent redirect).
    """
    user = get_user_from_session(request)
    if not user:
        return None, RedirectResponse("/login", status_code=302)
    if user["role"] not in STAFF_ROLES:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user, None


def require_admin(request: Request):
    user = get_user_from_session(request)
    if not user:
        return None, RedirectResponse("/login", status_code=302)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return user, None
