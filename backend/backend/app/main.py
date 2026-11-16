import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.routes import (
    auth_routes,
    profile_routes,
    course_routes,
    assignment_routes,
    grade_routes,
    message_routes,
    admin_routes,
    utility_routes,
)

log = logging.getLogger("app")
templates = Jinja2Templates(directory="app/templates")

# debug=False: no interactive tracebacks. The auto-generated API docs / OpenAPI
# schema are disabled because they publish the full endpoint map to anonymous users.
app = FastAPI(
    title="DAT250 SecureApp",
    debug=False,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.mount("/uploads", StaticFiles(directory="app/uploads"), name="uploads")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    # Defence in depth against XSS: only our own scripts + the pinned CDN.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    ),
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def _error_page(request: Request, status_code: int, title: str, message: str, ref: str = ""):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "user": None, "title": title, "message": message, "ref": ref},
        status_code=status_code,
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    titles = {403: "Forbidden", 404: "Not found", 413: "File too large"}
    msg = exc.detail if isinstance(exc.detail, str) and exc.status_code in (400, 413) else "The request could not be completed."
    return _error_page(request, exc.status_code, titles.get(exc.status_code, "Error"), msg)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Full details go to the server log only; the client gets a correlation id.
    ref = uuid.uuid4().hex[:8]
    log.exception("Unhandled error ref=%s path=%s", ref, request.url.path, exc_info=exc)
    return _error_page(request, 500, "Unexpected error", "Something went wrong on our side.", ref)


app.include_router(auth_routes.router)
app.include_router(profile_routes.router)
app.include_router(course_routes.router)
app.include_router(assignment_routes.router)
app.include_router(grade_routes.router)
app.include_router(message_routes.router)
app.include_router(admin_routes.router)
app.include_router(utility_routes.router)
