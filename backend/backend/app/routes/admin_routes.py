from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from app.database import run_query
from app.security import like_pattern
from app.auth import require_staff, require_admin, ALL_ROLES

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request):
    user, denied = require_staff(request)
    if denied:
        return denied

    users_count = run_query("SELECT COUNT(*) as c FROM users", fetchone=True)
    submissions_count = run_query("SELECT COUNT(*) as c FROM submissions", fetchone=True)
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": user,
            "users_count": users_count["c"],
            "submissions_count": submissions_count["c"],
        },
    )


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request):
    user, denied = require_staff(request)
    if denied:
        return denied
    users = run_query("SELECT id, email, full_name, role FROM users ORDER BY id", fetchall=True)
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": user, "users": users})


@router.post("/admin/users/{user_id}/role")
def update_role(request: Request, user_id: int, role: str = Form(...)):
    # Only admins may change roles. The decision is made from the *server-side*
    # session, never from client-supplied headers or form fields (the old
    # `x-role` header / `role` field checks were attacker-controlled).
    user, denied = require_admin(request)
    if denied:
        return denied

    if role not in ALL_ROLES:
        return RedirectResponse("/admin/users", status_code=302)

    # Do not let an admin accidentally remove the last admin by demoting themselves.
    if user["id"] == user_id and role != "admin":
        return RedirectResponse("/admin/users", status_code=302)

    run_query("UPDATE users SET role=%s WHERE id=%s", (role, user_id), commit=True)
    return RedirectResponse("/admin/users", status_code=302)


@router.get("/admin/grades", response_class=HTMLResponse)
def admin_grades(request: Request):
    user, denied = require_staff(request)
    if denied:
        return denied

    grades = run_query(
        """
        SELECT g.id, u.full_name as student_name, a.title as assignment_title, g.grade_value, g.feedback
        FROM grades g
        JOIN users u ON u.id = g.student_id
        JOIN assignments a ON a.id = g.assignment_id
        ORDER BY g.id DESC
        """,
        fetchall=True,
    )
    return templates.TemplateResponse("admin_grades.html", {"request": request, "user": user, "grades": grades})


@router.post("/admin/grades/{grade_id}/update")
def update_grade(
    request: Request,
    grade_id: int,
    grade_value: str = Form(..., max_length=10),
    feedback: str = Form(..., max_length=5000),
):
    # Role comes from the session. The old handler trusted a `role` form field
    # that any user could set to "admin".
    user, denied = require_staff(request)
    if denied:
        return denied

    run_query(
        "UPDATE grades SET grade_value=%s, feedback=%s, grader_id=%s, status='published', updated_at=NOW() WHERE id=%s",
        (grade_value, feedback, user["id"], grade_id),
        commit=True,
    )
    return RedirectResponse("/admin/grades", status_code=302)


@router.get("/admin/search-users", response_class=HTMLResponse)
def search_users(request: Request, q: str = ""):
    user, denied = require_staff(request)
    if denied:
        return denied

    # Parameterised query: `q` is bound as data and can never alter the SQL.
    pattern = like_pattern(q)
    users = run_query(
        """
        SELECT id, email, full_name, role FROM users
        WHERE email ILIKE %s OR full_name ILIKE %s
        ORDER BY id
        """,
        (pattern, pattern),
        fetchall=True,
    )
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": user, "users": users, "q": q})
