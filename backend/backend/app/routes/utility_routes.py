import logging
from urllib.parse import urljoin

import requests
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import get_user_from_session, require_staff
from app.config import APP_ENV
from app.security import validate_outbound_url, UnsafeURL

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("app")

MAX_REDIRECTS = 3
MAX_BYTES = 64 * 1024  # never pull more than 64 KiB from a remote host


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/status", response_class=HTMLResponse)
def status(request: Request):
    # Was public and leaked environment/runtime/service info; now staff only,
    # and no longer reveals the interpreter version.
    user, denied = require_staff(request)
    if denied:
        return denied
    return templates.TemplateResponse(
        "status.html",
        {"request": request, "user": user, "env": APP_ENV, "service": "backend"},
    )


def _safe_fetch(url: str) -> str:
    """Fetch `url` with SSRF protection.

    Every hop (including redirects) is re-validated, because an allowed public
    host could otherwise 302 us to http://169.254.169.254/ or http://127.0.0.1/.
    """
    current = validate_outbound_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        with requests.get(current, timeout=5, allow_redirects=False, stream=True) as r:
            if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location")
                if not location:
                    raise UnsafeURL("Bad redirect.")
                current = validate_outbound_url(urljoin(current, location))
                continue
            chunk = next(r.iter_content(chunk_size=MAX_BYTES, decode_unicode=False), b"")
            return chunk.decode(r.encoding or "utf-8", errors="replace")[:2000]
    raise UnsafeURL("Too many redirects.")


@router.get("/resources/import", response_class=HTMLResponse)
def import_resource_get(request: Request, url: str = ""):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    body = ""
    error = ""
    if url:
        try:
            body = _safe_fetch(url)
        except UnsafeURL as exc:
            error = str(exc)  # our own, deliberately user-safe messages
        except Exception:
            # Do NOT echo str(exc): connection errors reveal internal hosts/ports
            # (this was a port-scanning oracle in the original code).
            log.exception("resource import failed")
            error = "The resource could not be fetched."
    return templates.TemplateResponse(
        "resource_import.html",
        {"request": request, "user": user, "body": body, "url": url, "error": error},
    )


@router.post("/resources/import", response_class=HTMLResponse)
def import_resource_post(request: Request, url: str = Form(...)):
    return import_resource_get(request, url)


@router.get("/error", response_class=HTMLResponse)
def trigger_error(request: Request):
    # Kept so the old finding can be re-tested: it still raises an exception,
    # but the global handler in main.py now returns a generic page.
    return 1 / 0
