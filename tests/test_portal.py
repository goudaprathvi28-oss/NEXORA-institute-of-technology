import http.client
import json
import os
import tempfile
import threading
import unittest
from urllib.parse import urlencode

import server
from portal import PortalError, PortalStore


class PortalStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_directory.name, "portal.sqlite3")
        self.store = PortalStore(self.database_path, demo_mode=True)

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_demo_records_are_explicit_and_database_mode_cannot_be_reused(self):
        student = self.store.authenticate(
            "student.demo@nexora.invalid", "NEXORA-DEMO-STUDENT"
        )
        self.assertEqual(student["role"], "Student")
        with self.assertRaises(ValueError):
            PortalStore(self.database_path, demo_mode=False)

    def test_passwords_are_hashed_and_sessions_store_only_token_hashes(self):
        user = self.store.authenticate(
            "faculty.demo@nexora.invalid", "NEXORA-DEMO-FACULTY"
        )
        token, csrf_token, _ = self.store.create_session(user["id"])
        session = self.store.get_session(token)
        self.assertEqual(session["csrf_token"], csrf_token)
        self.assertNotEqual(token, session["token_hash"])
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT password_hash, password_salt FROM users WHERE id = ?",
                (user["id"],),
            ).fetchone()
        self.assertNotIn(b"NEXORA-DEMO-FACULTY", row["password_hash"])
        self.assertEqual(len(row["password_salt"]), 16)

    def test_student_attendance_is_read_only_and_reports_month_and_semester(self):
        student = self.store.authenticate(
            "student.demo@nexora.invalid", "NEXORA-DEMO-STUDENT"
        )
        report = self.store.student_attendance(student["id"], semester=True)
        self.assertEqual(report["student"]["student_id"], "DEMO-0001")
        self.assertEqual(len(report["subjects"]), 1)
        self.assertGreater(len(report["records"]), 0)
        with self.assertRaises(PortalError):
            self.store.save_attendance(
                student["id"], "demo-class", "demo-subject", "2099-12-31", 1,
                [{"student_user_id": student["id"], "status": "Present"}],
                {"Present", "Absent"},
            )

    def test_faculty_can_save_once_then_correct_with_audited_reason(self):
        faculty = self.store.authenticate(
            "faculty.demo@nexora.invalid", "NEXORA-DEMO-FACULTY"
        )
        student_id = "demo-student"
        entries = [{"student_user_id": student_id, "status": "Present"}]
        self.store.save_attendance(
            faculty["id"], "demo-class", "demo-subject", "2099-12-31", 6,
            entries, {"Present", "Absent", "Excused"},
        )
        with self.assertRaises(PortalError) as duplicate:
            self.store.save_attendance(
                faculty["id"], "demo-class", "demo-subject", "2099-12-31", 6,
                entries, {"Present", "Absent", "Excused"},
            )
        self.assertEqual(duplicate.exception.status, 409)
        self.store.save_attendance(
            faculty["id"], "demo-class", "demo-subject", "2099-12-31", 6,
            [{"student_user_id": student_id, "status": "Absent"}],
            {"Present", "Absent", "Excused"}, "Verified register correction",
        )
        report = self.store.attendance_report(
            faculty["id"], "demo-class", "demo-subject", "2099-12-31", "2099-12-31"
        )
        self.assertEqual(report[0]["status"], "Absent")
        with self.store.connect() as connection:
            audit = connection.execute(
                "SELECT action, reason FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(audit["action"], "attendance_corrected")
        self.assertEqual(audit["reason"], "Verified register correction")

    def test_unassigned_faculty_cannot_read_or_change_a_class(self):
        other_id = "unassigned-faculty"
        from portal import hash_password, utc_now
        salt, password_hash = hash_password("a-long-test-password")
        with self.store.connect() as connection:
            connection.execute(
                "INSERT INTO users (id, email, role, password_salt, password_hash, created_at) "
                "VALUES (?, ?, 'Faculty', ?, ?, ?)",
                (other_id, "other@nexora.invalid", salt, password_hash, utc_now()),
            )
            connection.execute(
                "INSERT INTO faculty VALUES (?, ?, ?, ?)",
                (other_id, "DEMO-F002", "Other Faculty", "Demo Engineering"),
            )
        with self.assertRaises(PortalError) as context:
            self.store.attendance_roster(
                other_id, "demo-class", "demo-subject", "2099-12-31", 1
            )
        self.assertEqual(context.exception.status, 403)

    def test_admin_cannot_deactivate_self_or_the_last_active_admin(self):
        admin = self.store.authenticate(
            "admin.demo@nexora.invalid", "NEXORA-DEMO-ADMIN"
        )
        with self.assertRaises(PortalError):
            self.store.set_user_access(
                admin["id"], False, actor_user_id=admin["id"]
            )
        with self.assertRaises(PortalError):
            self.store.set_user_access(admin["id"], False)

    def test_live_bootstrap_and_admin_managed_academic_relationships(self):
        live_path = os.path.join(self.temp_directory.name, "live.sqlite3")
        live_store = PortalStore(live_path, demo_mode=False)
        live_store.create_bootstrap_admin(
            "first.admin@nexora.invalid", "long-live-admin-password"
        )
        self.assertEqual(
            live_store.authenticate(
                "first.admin@nexora.invalid", "long-live-admin-password"
            )["role"],
            "Administrator",
        )
        with self.assertRaises(PortalError):
            live_store.create_bootstrap_admin(
                "second.admin@nexora.invalid", "another-long-password"
            )

        self.store.create_admin_record(
            "courses",
            {"code": "DEMO-TEST", "name": "Demo Test Course", "department": "Test"},
        )
        course_id = next(
            row["id"] for row in self.store.admin_records()["courses"]
            if row["code"] == "DEMO-TEST"
        )
        self.store.create_admin_record(
            "subjects",
            {"code": "DEMO-TEST-1", "name": "Demo Test Subject", "course_id": course_id, "semester": 1},
        )
        subject_id = next(
            row["id"] for row in self.store.admin_records()["subjects"]
            if row["code"] == "DEMO-TEST-1"
        )
        self.store.create_admin_record(
            "classes",
            {"course_id": course_id, "subject_id": subject_id, "section": "TEST-A", "semester": 1},
        )
        class_id = next(
            row["id"] for row in self.store.admin_records()["classes"]
            if row["section"] == "TEST-A"
        )
        with self.assertRaises(PortalError):
            self.store.create_admin_record(
                "classes",
                {"course_id": course_id, "subject_id": "demo-subject", "section": "TEST-B", "semester": 1},
            )
        self.assertTrue(class_id)


class PortalHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory()
        server.PORTAL_STORE = PortalStore(
            os.path.join(cls.temp_directory.name, "http-portal.sqlite3"),
            demo_mode=True,
        )
        cls.http_server = server.ThreadingHTTPServer(
            ("127.0.0.1", 0), server.CollegeAssistantHandler
        )
        cls.thread = threading.Thread(target=cls.http_server.serve_forever)
        cls.thread.start()
        cls.port = cls.http_server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.http_server.shutdown()
        cls.http_server.server_close()
        cls.thread.join()
        server.PORTAL_STORE = None
        cls.temp_directory.cleanup()

    def request(self, method, path, body=None, cookie=None, csrf=None, headers=None):
        request_headers = {"Content-Type": "application/json"}
        if cookie:
            request_headers["Cookie"] = cookie
        if csrf:
            request_headers["X-CSRF-Token"] = csrf
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port)
        connection.request(
            method,
            path,
            body=json.dumps(body) if body is not None else None,
            headers=request_headers,
        )
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def setUp(self):
        server.PORTAL_STORE.set_user_access("demo-student", True)

    def login(self, email, password):
        status, headers, body = self.request(
            "POST", "/api/auth/login", {"email": email, "password": password}
        )
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return result["user"], cookie, result["csrf_token"]

    def test_login_and_role_protected_pages(self):
        _, student_cookie, student_csrf = self.login(
            "student.demo@nexora.invalid", "NEXORA-DEMO-STUDENT"
        )
        self.assertEqual(
            self.request("GET", "/api/attendance/student", cookie=student_cookie)[0],
            200,
        )
        self.assertEqual(self.request("GET", "/admin", cookie=student_cookie)[0], 403)
        status, _, _ = self.request(
            "POST",
            "/api/admin/records",
            {"type": "notices", "record": {"title": "No", "body": "Denied"}},
            cookie=student_cookie,
            csrf=student_csrf,
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.request("GET", "/api/dashboard")[0], 401)

    def test_attendance_save_duplicate_correction_and_csv_report(self):
        _, cookie, csrf = self.login(
            "faculty.demo@nexora.invalid", "NEXORA-DEMO-FACULTY"
        )
        status, _, body = self.request(
            "POST", "/api/attendance",
            {
                "class_id": "demo-class", "subject_id": "demo-subject",
                "date": "2099-12-31", "period": 7,
                "entries": [{"student_user_id": "demo-student", "status": "Present"}],
            },
            cookie, csrf,
        )
        self.assertEqual(status, 200, body)
        duplicate_status, _, _ = self.request(
            "POST", "/api/attendance",
            {
                "class_id": "demo-class", "subject_id": "demo-subject",
                "date": "2099-12-31", "period": 7,
                "entries": [{"student_user_id": "demo-student", "status": "Present"}],
            },
            cookie, csrf,
        )
        self.assertEqual(duplicate_status, 409)
        correction_status, _, _ = self.request(
            "POST", "/api/attendance",
            {
                "class_id": "demo-class", "subject_id": "demo-subject",
                "date": "2099-12-31", "period": 7,
                "entries": [{"student_user_id": "demo-student", "status": "Absent"}],
                "correction_reason": "Corrected against signed register",
            },
            cookie, csrf,
        )
        self.assertEqual(correction_status, 200)
        query = urlencode({
            "class_id": "demo-class", "subject_id": "demo-subject",
            "start_date": "2099-12-31", "end_date": "2099-12-31",
        })
        status, headers, body = self.request(
            "GET", f"/api/faculty/report.csv?{query}", cookie=cookie
        )
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["Content-Type"])
        self.assertIn(b"DEMO-0001", body)
        self.assertIn(b"Absent", body)

    def test_missing_csrf_and_student_writes_are_rejected(self):
        _, faculty_cookie, _ = self.login(
            "faculty.demo@nexora.invalid", "NEXORA-DEMO-FACULTY"
        )
        status, _, _ = self.request(
            "POST",
            "/api/attendance",
            {
                "class_id": "demo-class", "subject_id": "demo-subject",
                "date": "2099-12-31", "period": 8,
                "entries": [{"student_user_id": "demo-student", "status": "Present"}],
            },
            cookie=faculty_cookie,
        )
        self.assertEqual(status, 403)
        _, student_cookie, student_csrf = self.login(
            "student.demo@nexora.invalid", "NEXORA-DEMO-STUDENT"
        )
        status, _, _ = self.request(
            "POST",
            "/api/attendance",
            {
                "class_id": "demo-class", "subject_id": "demo-subject",
                "date": "2099-12-31", "period": 8,
                "entries": [{"student_user_id": "demo-student", "status": "Present"}],
            },
            cookie=student_cookie,
            csrf=student_csrf,
        )
        self.assertEqual(status, 403)

    def test_admin_can_create_published_notice_and_disable_account(self):
        admin, cookie, csrf = self.login(
            "admin.demo@nexora.invalid", "NEXORA-DEMO-ADMIN"
        )
        status, _, body = self.request(
            "POST",
            "/api/admin/records",
            {
                "type": "notices",
                "record": {"title": "Test notice", "body": "Administrator-authored", "published": True},
            },
            cookie,
            csrf,
        )
        self.assertEqual(status, 201, body)
        notice = next(
            item for item in server.PORTAL_STORE.admin_records()["notices"]
            if item["title"] == "Test notice"
        )
        status, _, body = self.request(
            "POST",
            f"/api/admin/records/notices/{notice['id']}",
            {
                "record": {
                    "title": "Updated test notice",
                    "body": "Administrator-edited",
                    "published": True,
                }
            },
            cookie,
            csrf,
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(
            any(
                item["title"] == "Updated test notice"
                for item in server.PORTAL_STORE.admin_records()["notices"]
            )
        )
        student = server.PORTAL_STORE.authenticate(
            "student.demo@nexora.invalid", "NEXORA-DEMO-STUDENT"
        )
        status, _, _ = self.request(
            "POST",
            f"/api/admin/users/{student['id']}/active",
            {"active": False},
            cookie,
            csrf,
        )
        self.assertEqual(status, 200)
        with self.assertRaises(PortalError):
            server.PORTAL_STORE.authenticate(
                "student.demo@nexora.invalid", "NEXORA-DEMO-STUDENT"
            )


if __name__ == "__main__":
    unittest.main()
