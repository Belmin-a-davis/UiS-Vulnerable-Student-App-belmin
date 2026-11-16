from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import run_query
from app.auth import get_user_from_session
from app.security import like_pattern

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/courses", response_class=HTMLResponse)
def courses(request: Request):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    course_rows = run_query("SELECT * FROM courses ORDER BY id", fetchall=True)
    return templates.TemplateResponse("courses.html", {"request": request, "user": user, "courses": course_rows})


@router.get("/courses/search", response_class=HTMLResponse)
def search_courses(request: Request, q: str = ""):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Parameterised query: `q` is bound as data and can never alter the SQL.
    courses = run_query(
        "SELECT * FROM courses WHERE title ILIKE %s ORDER BY id",
        (like_pattern(q),),
        fetchall=True,
    )

    return templates.TemplateResponse(
        "courses.html", {"request": request, "user": user, "courses": courses, "search_query": q}
    )


@router.get("/courses/{course_id}", response_class=HTMLResponse)
def course_detail(request: Request, course_id: int):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    course = run_query("SELECT * FROM courses WHERE id=%s", (course_id,), fetchone=True)
    if not course:
        raise HTTPException(status_code=404, detail="Not found")
    comments = run_query(
        """
        SELECT cc.*, u.full_name FROM course_comments cc
        JOIN users u ON u.id = cc.user_id
        WHERE cc.course_id=%s ORDER BY cc.created_at DESC
        """,
        (course_id,),
        fetchall=True,
    )
    return templates.TemplateResponse(
        "course_detail.html",
        {"request": request, "user": user, "course": course, "comments": comments},
    )


@router.post("/courses/{course_id}/register")
def register_course(request: Request, course_id: int, group_name: str = Form("", max_length=255)):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if run_query(
        "SELECT id FROM course_registrations WHERE user_id=%s AND course_id=%s",
        (user["id"], course_id),
        fetchone=True,
    ):
        return RedirectResponse(f"/courses/{course_id}", status_code=302)

    count_row = run_query(
        "SELECT COUNT(*) as cnt FROM course_registrations WHERE course_id=%s", (course_id,), fetchone=True
    )
    if count_row and count_row["cnt"] < 30:
        run_query(
            """
            INSERT INTO course_registrations (user_id, course_id, project_group)
            VALUES (%s, %s, %s)
            """,
            (user["id"], course_id, group_name or "Unassigned"),
            commit=True,
        )

    return RedirectResponse(f"/courses/{course_id}", status_code=302)


@router.post("/courses/{course_id}/comment")
def comment_course(request: Request, course_id: int, content: str = Form(..., max_length=2000)):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    run_query(
        "INSERT INTO course_comments (course_id, user_id, content) VALUES (%s, %s, %s)",
        (course_id, user["id"], content),
        commit=True,
    )
    return RedirectResponse(f"/courses/{course_id}", status_code=302)
