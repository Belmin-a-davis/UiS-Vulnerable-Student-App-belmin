"""Security regression tests for DAT250 SecureApp (Assignment 2).

Each class maps to one remediated vulnerability.  Every class contains
  * "attack" tests  - the original Assignment 1 exploit must now FAIL, and
  * "legit" tests   - normal behaviour must still WORK.
Run against the ORIGINAL code to see the attack tests fail (= vulnerable),
and against the fixed branch to see them pass.
"""
import re

import pytest
import requests

from conftest import Client, role_of

HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


# ============================================================================
# 1. SQL injection  (CWE-89)  /courses/search , /admin/search-users
# ============================================================================
class TestSqlInjection:
    def test_course_search_boolean_injection_returns_nothing(self, alice):
        r = alice.get("/courses/search", params={"q": "zzzz' OR '1'='1"})
        assert r.status_code == 200
        assert r.text.count("card-title") == 0, "boolean payload matched rows -> injectable"

    def test_course_search_union_injection_leaks_nothing(self, alice):
        payload = "zzzz' UNION SELECT id, email, password_hash, 0 FROM users--"
        r = alice.get("/courses/search", params={"q": payload})
        assert "dat250.local" not in r.text
        assert not HEX64.search(r.text), "password hashes leaked via UNION"

    def test_course_search_quote_does_not_error(self, alice):
        r = alice.get("/courses/search", params={"q": "'"})
        assert r.status_code == 200  # was a 500 with SQL error

    def test_admin_search_union_injection_leaks_nothing(self, teacher):
        payload = "zzzz' UNION SELECT id, email, password_hash, role FROM users--"
        r = teacher.get("/admin/search-users", params={"q": payload})
        assert r.status_code == 200
        assert not HEX64.search(r.text), "password hashes leaked via UNION"

    def test_login_sqli_payload_does_not_authenticate(self):
        c = Client()
        r = c.post("/login", data={"email": "anything' AND 1=1--", "password": "test"})
        assert r.status_code != 302 and "session_token" not in c.cookies
        r = c.post("/login", data={"email": "alice@student.uis.no' OR '1'='1", "password": "x"})
        assert r.status_code != 302

    # --- legitimate behaviour still works ---
    def test_course_search_legit(self, alice):
        r = alice.get("/courses/search", params={"q": "DAT250"})
        assert r.status_code == 200 and "Information and Software Security" in r.text
        assert r.text.count("card-title") == 1

    def test_course_search_is_case_insensitive_and_literal_percent(self, alice):
        assert "Database Systems" in alice.get("/courses/search", params={"q": "database"}).text
        # '%' must be treated literally, not as "match everything"
        assert alice.get("/courses/search", params={"q": "%"}).text.count("card-title") == 0

    def test_admin_search_legit(self, teacher):
        r = teacher.get("/admin/search-users", params={"q": "alice"})
        assert "alice@student.uis.no" in r.text and "bob@student.uis.no" not in r.text


# ============================================================================
# 2. Broken access control  (CWE-269 / CWE-639 / CWE-915)
# ============================================================================
class TestAccessControl:
    # ---- vertical privilege escalation ----
    def test_profile_update_cannot_set_role(self, student):
        student.post("/profile/update", data={"full_name": "Hacker", "role": "admin"})
        assert role_of(student, student.user_id) == "student"

    def test_student_cannot_open_admin_pages(self, student):
        for path in ("/admin", "/admin/users", "/admin/grades", "/admin/search-users?q=a"):
            assert student.get(path).status_code == 403, path

    def test_student_cannot_change_roles(self, student):
        for headers in ({}, {"x-role": "admin"}):
            r = student.post(f"/admin/users/{student.user_id}/role", data={"role": "admin"}, headers=headers)
            assert r.status_code == 403
        assert role_of(student, student.user_id) == "student"

    def test_student_cannot_update_grades_with_forged_role_field(self, student):
        r = student.post("/admin/grades/1/update", data={"grade_value": "A", "feedback": "pwned", "role": "admin"})
        assert r.status_code == 403

    def test_teacher_cannot_change_roles(self, teacher, student):
        r = teacher.post(f"/admin/users/{student.user_id}/role", data={"role": "admin"})
        assert r.status_code == 403

    def test_anonymous_is_sent_to_login(self):
        c = Client()
        for path in ("/admin", "/admin/users", "/dashboard", "/status"):
            r = c.get(path)
            assert r.status_code == 302 and r.headers["location"] == "/login", path

    # ---- horizontal (IDOR) ----
    def test_cannot_read_other_students_grade(self, alice):
        # seed: grade 1 = alice, 2 = bob, 3 = charlie
        assert alice.get("/grades/2").status_code == 404
        assert alice.get("/grades/3").status_code == 404

    def test_cannot_read_other_peoples_messages(self, alice):
        # seed: msg 1 teacher->alice, 2 ta->bob, 3 alice->bob
        assert alice.get("/messages/2").status_code == 404

    def test_cannot_view_other_profiles(self, alice):
        assert alice.get("/profile/5").status_code == 403  # bob
        assert alice.get("/profile/1").status_code == 403  # admin

    # ---- legitimate behaviour still works ----
    def test_student_can_access_own_data(self, alice):
        assert alice.get("/grades/1").status_code == 200
        assert alice.get("/messages/1").status_code == 200
        assert alice.get("/messages/3").status_code == 200  # sender may read too
        assert alice.get("/profile/4").status_code == 200
        assert alice.get("/profile").status_code == 200
        assert alice.get("/grades").status_code == 200

    def test_student_can_edit_own_profile(self, student):
        r = student.post("/profile/update", data={"full_name": "New Name", "phone": "123", "address": "A", "bio": "B"})
        assert r.status_code == 302
        assert "New Name" in student.get(f"/profile/{student.user_id}").text

    def test_staff_can_use_admin_area_and_view_any_grade(self, teacher):
        assert teacher.get("/admin").status_code == 200
        assert teacher.get("/admin/users").status_code == 200
        assert teacher.get("/admin/grades").status_code == 200
        assert teacher.get("/grades/2").status_code == 200
        assert teacher.get("/profile/4").status_code == 200

    def test_admin_can_change_role_and_staff_can_grade(self, admin, student):
        r = admin.post(f"/admin/users/{student.user_id}/role", data={"role": "ta"})
        assert r.status_code == 302 and role_of(admin, student.user_id) == "ta"
        admin.post(f"/admin/users/{student.user_id}/role", data={"role": "student"})
        assert role_of(admin, student.user_id) == "student"
        # invalid role value is ignored
        admin.post(f"/admin/users/{student.user_id}/role", data={"role": "superuser"})
        assert role_of(admin, student.user_id) == "student"

    def test_staff_can_update_grade(self, teacher):
        r = teacher.post("/admin/grades/3/update", data={"grade_value": "A-", "feedback": "Strong coverage of session handling."})
        assert r.status_code == 302


# ============================================================================
# 3. Server-side request forgery  (CWE-918)  /resources/import
# ============================================================================
BLOCKED_URLS = [
    "http://127.0.0.1:8000/health",
    "http://localhost:8000/health",
    "http://backend:8000/health",          # docker-internal service name
    "http://db:5432/",
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://[::1]:8000/health",
    "http://0.0.0.0:8000/health",
    "http://2130706433:8000/health",        # 127.0.0.1 as decimal
    "http://0x7f000001:8000/health",        # 127.0.0.1 as hex
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://user:pw@example.com/",          # embedded credentials
    "http://example.com:8025/",             # non-web port
    "file:///etc/passwd",
    "ftp://127.0.0.1:21",
    "gopher://127.0.0.1:6379/_PING",
]


class TestSSRF:
    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_internal_and_non_http_targets_are_blocked(self, alice, url):
        r = alice.get("/resources/import", params={"url": url})
        assert r.status_code == 200
        assert "Response preview" not in r.text, f"server fetched {url}"
        assert "root:x:0:0" not in r.text
        for leak in ("HTTPConnectionPool", "Max retries", "Connection refused", "NewConnectionError"):
            assert leak not in r.text, f"raw connection error leaked: {leak}"

    def test_post_variant_is_blocked_too(self, alice):
        r = alice.post("/resources/import", data={"url": "http://127.0.0.1:8000/health"})
        assert "Response preview" not in r.text

    def test_anonymous_cannot_use_importer(self):
        r = Client().get("/resources/import", params={"url": "http://example.com"})
        assert r.status_code == 302

    def test_error_message_is_generic_for_unreachable_public_host(self, alice):
        # .invalid never resolves (RFC 2606) -> must not leak resolver internals
        r = alice.get("/resources/import", params={"url": "http://nonexistent.invalid/"})
        assert "Response preview" not in r.text and "Traceback" not in r.text

    def test_legit_public_url_still_works(self, alice):
        # Needs outbound internet from the backend container; skipped if unavailable.
        try:
            requests.get("https://example.com", timeout=5)
        except Exception:
            pytest.skip("no internet access from the test machine")
        r = alice.get("/resources/import", params={"url": "https://example.com"})
        if "could not be fetched" in r.text:
            pytest.skip("backend container has no outbound internet access")
        assert "Response preview" in r.text and "Example Domain" in r.text


# ============================================================================
# 4. Verbose errors / debug mode  (CWE-209 / CWE-489)
# ============================================================================
class TestErrorHandling:
    def test_error_endpoint_does_not_leak_stack_trace(self):
        r = Client().get("/error")
        assert r.status_code == 500
        for leak in ("Traceback", "ZeroDivisionError", "/app/app/", ".py", "line 5", "division by zero"):
            assert leak not in r.text, f"leaked: {leak}"
        assert "Reference:" in r.text  # generic page with a correlation id

    def test_validation_errors_are_not_verbose(self, alice):
        r = alice.get("/courses/abc")  # int parse failure
        assert r.status_code in (404, 422)
        assert "Traceback" not in r.text and "/app/" not in r.text

    def test_unknown_course_is_404_not_500(self, alice):
        r = alice.get("/courses/99999")
        assert r.status_code == 404 and "Traceback" not in r.text

    def test_error_page_still_renders_normally(self):
        r = Client().get("/error")
        assert "Unexpected error" in r.text  # users still get a clear message


# ============================================================================
# 5. Exposed sensitive endpoints / security misconfiguration  (CWE-200 / CWE-16)
# ============================================================================
class TestExposure:
    @pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
    def test_api_docs_not_public(self, path):
        assert Client().get(path).status_code == 404

    def test_status_page_requires_staff(self, student, teacher):
        assert Client().get("/status").status_code == 302
        assert student.get("/status").status_code == 403
        r = teacher.get("/status")
        assert r.status_code == 200 and "3.11" not in r.text  # no runtime version

    def test_health_still_public(self):
        r = Client().get("/health")
        assert r.status_code == 200 and r.json() == {"status": "ok"}

    def test_nginx_version_not_disclosed(self):
        r = Client().get("/")
        assert not re.search(r"nginx/\d", r.headers.get("Server", ""))

    def test_no_directory_listing(self):
        for path in ("/static/", "/static/css/", "/uploads/"):
            r = Client().get(path)
            assert "Index of" not in r.text, path

    def test_security_headers_present(self):
        h = Client().get("/login").headers
        assert h.get("X-Content-Type-Options") == "nosniff"
        assert h.get("X-Frame-Options") == "DENY"
        assert "default-src 'self'" in h.get("Content-Security-Policy", "")

    def test_static_assets_still_served(self):
        assert Client().get("/static/css/style.css").status_code == 200

    def test_app_still_works_normally(self, alice):
        for path in ("/", "/login", "/register", "/dashboard", "/courses", "/assignments", "/messages"):
            assert alice.get(path).status_code == 200, path
