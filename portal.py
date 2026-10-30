"""SQLite-backed records and authentication for the NEXORA portal."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


PASSWORD_ITERATIONS = 310_000
SESSION_HOURS = 10
ROLES = {"Student", "Faculty", "Administrator"}

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS portal_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role TEXT NOT NULL CHECK (role IN ('Student', 'Faculty', 'Administrator')),
    password_salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS students (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    student_id TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    department TEXT NOT NULL,
    semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 12),
    enrollment_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS faculty (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    faculty_id TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    department TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS courses (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    department TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subjects (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    course_id TEXT NOT NULL REFERENCES courses(id),
    semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 12),
    UNIQUE(id, course_id)
);
CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY,
    course_id TEXT NOT NULL REFERENCES courses(id),
    subject_id TEXT NOT NULL REFERENCES subjects(id),
    section TEXT NOT NULL,
    semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 12),
    UNIQUE(course_id, subject_id, section, semester),
    UNIQUE(id, subject_id),
    FOREIGN KEY(subject_id, course_id) REFERENCES subjects(id, course_id)
);
CREATE TABLE IF NOT EXISTS faculty_assignments (
    faculty_user_id TEXT NOT NULL REFERENCES faculty(user_id) ON DELETE CASCADE,
    class_id TEXT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    subject_id TEXT NOT NULL REFERENCES subjects(id),
    PRIMARY KEY (faculty_user_id, class_id, subject_id),
    FOREIGN KEY(class_id, subject_id) REFERENCES classes(id, subject_id)
);
CREATE TABLE IF NOT EXISTS enrollments (
    student_user_id TEXT NOT NULL REFERENCES students(user_id) ON DELETE CASCADE,
    class_id TEXT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    PRIMARY KEY (student_user_id, class_id)
);
CREATE TABLE IF NOT EXISTS timetable (
    id TEXT PRIMARY KEY,
    class_id TEXT NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    subject_id TEXT NOT NULL REFERENCES subjects(id),
    faculty_user_id TEXT NOT NULL REFERENCES faculty(user_id),
    day_of_week INTEGER NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
    period INTEGER NOT NULL CHECK (period BETWEEN 1 AND 16),
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    FOREIGN KEY(class_id, subject_id) REFERENCES classes(id, subject_id)
);
CREATE TABLE IF NOT EXISTS calendar_events (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    starts_at TEXT NOT NULL,
    ends_at TEXT,
    location TEXT NOT NULL DEFAULT '',
    published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0, 1))
);
CREATE TABLE IF NOT EXISTS notices (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    published_at TEXT,
    published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0, 1))
);
CREATE TABLE IF NOT EXISTS study_materials (
    id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES subjects(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0, 1))
);
CREATE TABLE IF NOT EXISTS attendance_sessions (
    id TEXT PRIMARY KEY,
    class_id TEXT NOT NULL REFERENCES classes(id),
    subject_id TEXT NOT NULL REFERENCES subjects(id),
    faculty_user_id TEXT NOT NULL REFERENCES faculty(user_id),
    attendance_date TEXT NOT NULL,
    period INTEGER NOT NULL CHECK (period BETWEEN 1 AND 16),
    created_at TEXT NOT NULL,
    UNIQUE(class_id, subject_id, attendance_date, period),
    FOREIGN KEY(class_id, subject_id) REFERENCES classes(id, subject_id),
    FOREIGN KEY(faculty_user_id, class_id, subject_id)
        REFERENCES faculty_assignments(faculty_user_id, class_id, subject_id)
);
CREATE TABLE IF NOT EXISTS attendance_entries (
    session_id TEXT NOT NULL REFERENCES attendance_sessions(id) ON DELETE CASCADE,
    student_user_id TEXT NOT NULL REFERENCES students(user_id),
    status TEXT NOT NULL,
    marked_by TEXT NOT NULL REFERENCES users(id),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(session_id, student_user_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance_entries(student_user_id);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance_sessions(attendance_date);
CREATE INDEX IF NOT EXISTS idx_notices_published ON notices(published, published_at);
CREATE INDEX IF NOT EXISTS idx_events_published ON calendar_events(published, starts_at);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_datetime(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PortalError(f"Enter a valid {field}.")
    try:
        datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise PortalError(f"Enter a valid {field} in ISO 8601 format.") from error
    return value.strip()


def validate_secure_url(value: str) -> str:
    if not isinstance(value, str):
        raise PortalError("Enter a valid study material URL.")
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise PortalError("Study material links must use a valid HTTPS URL.")
    return value.strip()


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt, password_hash


class PortalError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


class PortalStore:
    def __init__(self, database_path: str | Path, demo_mode: bool = False) -> None:
        self.database_path = Path(database_path)
        self.demo_mode = demo_mode
        if str(self.database_path) != ":memory:":
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            mode = "demo" if demo_mode else "live"
            existing_mode = connection.execute(
                "SELECT value FROM portal_metadata WHERE key = 'database_mode'"
            ).fetchone()
            if existing_mode and existing_mode["value"] != mode:
                raise ValueError(
                    "This database belongs to a different portal mode; choose a separate database path."
                )
            connection.execute(
                "INSERT OR IGNORE INTO portal_metadata (key, value) VALUES ('database_mode', ?)",
                (mode,),
            )
        if demo_mode:
            self.seed_demo_data()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path), timeout=10, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def seed_demo_data(self) -> None:
        """Create clearly synthetic records only in explicit demo mode."""
        with self.connect() as connection:
            if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return

            now = utc_now()
            demo_users = [
                ("demo-student", "student.demo@nexora.invalid", "Student", "NEXORA-DEMO-STUDENT"),
                ("demo-faculty", "faculty.demo@nexora.invalid", "Faculty", "NEXORA-DEMO-FACULTY"),
                ("demo-admin", "admin.demo@nexora.invalid", "Administrator", "NEXORA-DEMO-ADMIN"),
            ]
            for user_id, email, role, password in demo_users:
                salt, password_hash = hash_password(password)
                connection.execute(
                    "INSERT INTO users (id, email, role, password_salt, password_hash, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, email, role, salt, password_hash, now),
                )

            connection.execute(
                "INSERT INTO students VALUES (?, ?, ?, ?, ?, ?)",
                ("demo-student", "DEMO-0001", "Demo Student", "Demo Engineering", 3, "Demo active"),
            )
            connection.execute(
                "INSERT INTO faculty VALUES (?, ?, ?, ?)",
                ("demo-faculty", "DEMO-F001", "Demo Faculty", "Demo Engineering"),
            )
            connection.execute(
                "INSERT INTO courses VALUES (?, ?, ?, ?)",
                ("demo-course", "DEMO-BE", "Demo Engineering Programme", "Demo Engineering"),
            )
            connection.execute(
                "INSERT INTO subjects VALUES (?, ?, ?, ?, ?)",
                ("demo-subject", "DEMO-CS301", "Demo Computing Subject", "demo-course", 3),
            )
            connection.execute(
                "INSERT INTO classes VALUES (?, ?, ?, ?, ?)",
                ("demo-class", "demo-course", "demo-subject", "DEMO-A", 3),
            )
            connection.execute(
                "INSERT INTO faculty_assignments VALUES (?, ?, ?)",
                ("demo-faculty", "demo-class", "demo-subject"),
            )
            connection.execute(
                "INSERT INTO enrollments VALUES (?, ?)",
                ("demo-student", "demo-class"),
            )
            connection.execute(
                "INSERT INTO timetable VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "demo-timetable", "demo-class", "demo-subject", "demo-faculty",
                    0, 1, "09:00", "10:00",
                ),
            )
            connection.execute(
                "INSERT INTO notices VALUES (?, ?, ?, ?, ?)",
                (
                    "demo-notice", "Sample notice — DEMO DATA",
                    "This synthetic notice is for local demonstration only.",
                    now, 1,
                ),
            )
            connection.execute(
                "INSERT INTO calendar_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "demo-event", "Sample event — DEMO DATA",
                    "Synthetic event record for local demonstration only.",
                    now, None, "Demo location", 1,
                ),
            )
            connection.execute(
                "INSERT INTO study_materials VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "demo-material", "demo-subject", "Sample material — DEMO DATA",
                    "Synthetic resource placeholder.", "https://example.invalid/demo", 1,
                ),
            )
            for index in range(1, 13):
                attendance_date = (datetime.now(timezone.utc) - timedelta(days=index * 3)).date().isoformat()
                session_id = f"demo-session-{index}"
                connection.execute(
                    "INSERT INTO attendance_sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        session_id, "demo-class", "demo-subject", "demo-faculty",
                        attendance_date, 1, now,
                    ),
                )
                connection.execute(
                    "INSERT INTO attendance_entries VALUES (?, ?, ?, ?, ?)",
                    (
                        session_id, "demo-student",
                        "Present" if index % 4 else "Absent",
                        "demo-faculty", now,
                    ),
                )

    def authenticate(self, email: str, password: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, email, role, password_salt, password_hash, active "
                "FROM users WHERE email = ? COLLATE NOCASE",
                (email.strip(),),
            ).fetchone()
        if not row or not row["active"]:
            # Perform a dummy derivation to reduce the account-existence timing difference.
            hash_password(password, b"nexora-dummy-salt")
            raise PortalError("Email or password is incorrect.", 401)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), row["password_salt"], PASSWORD_ITERATIONS
        )
        if not hmac.compare_digest(candidate, row["password_hash"]):
            raise PortalError("Email or password is incorrect.", 401)
        return {"id": row["id"], "email": row["email"], "role": row["role"]}

    def create_bootstrap_admin(self, email: str, password: str) -> None:
        if not isinstance(email, str) or "@" not in email or len(email) > 320:
            raise PortalError("Enter a valid administrator email address.")
        if not isinstance(password, str) or len(password) < 14 or len(password) > 256:
            raise PortalError("The initial administrator password must be 14–256 characters.")
        with self.connect() as connection:
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise PortalError("Bootstrap is only available before the first account is created.", 409)
            salt, password_hash = hash_password(password)
            try:
                connection.execute(
                    "INSERT INTO users (id, email, role, password_salt, password_hash, created_at) "
                    "VALUES (?, ?, 'Administrator', ?, ?, ?)",
                    (secrets.token_hex(16), email.strip().lower(), salt, password_hash, utc_now()),
                )
            except sqlite3.IntegrityError as error:
                raise PortalError("An account already uses this email address.", 409) from error

    def create_session(self, user_id: str) -> tuple[str, str, str]:
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat(
            timespec="seconds"
        )
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO login_sessions VALUES (?, ?, ?, ?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    user_id,
                    csrf_token,
                    expires_at,
                ),
            )
        return token, csrf_token, expires_at

    def get_session(self, token: str) -> dict[str, Any] | None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT s.csrf_token, s.expires_at, u.id, u.email, u.role "
                "FROM login_sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ? AND u.active = 1",
                (token_hash,),
            ).fetchone()
            if row and row["expires_at"] <= utc_now():
                connection.execute(
                    "DELETE FROM login_sessions WHERE token_hash = ?", (token_hash,)
                )
                return None
        if not row:
            return None
        return {
            "user": {"id": row["id"], "email": row["email"], "role": row["role"]},
            "csrf_token": row["csrf_token"],
            "expires_at": row["expires_at"],
            "token_hash": token_hash,
        }

    def delete_session(self, token: str) -> None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM login_sessions WHERE token_hash = ?", (token_hash,)
            )

    def student_attendance(
        self,
        user_id: str,
        month: str | None = None,
        semester: bool = False,
        counted_statuses: set[str] | None = None,
    ) -> dict[str, Any]:
        with self.connect() as connection:
            student = connection.execute(
                "SELECT student_id, full_name, department, semester, enrollment_status "
                "FROM students WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if not student:
                raise PortalError("Student record is not available.", 404)
            parameters: list[Any] = [user_id]
            where = "WHERE e.student_user_id = ?"
            if month:
                try:
                    datetime.strptime(month, "%Y-%m")
                except ValueError as error:
                    raise PortalError("Choose a valid month.") from error
                where += " AND substr(a.attendance_date, 1, 7) = ?"
                parameters.append(month)
            if semester:
                where += " AND c.semester = ?"
                parameters.append(student["semester"])
            counted_statuses = counted_statuses or {"Present"}
            status_marks = ",".join("?" for _ in counted_statuses)
            rows = connection.execute(
                "SELECT s.code AS subject_code, s.name AS subject_name, "
                "a.attendance_date, a.period, e.status "
                "FROM attendance_entries e "
                "JOIN attendance_sessions a ON a.id = e.session_id "
                "JOIN subjects s ON s.id = a.subject_id "
                "JOIN classes c ON c.id = a.class_id "
                f"{where} ORDER BY a.attendance_date DESC, a.period DESC",
                parameters,
            ).fetchall()
            summary = connection.execute(
                "SELECT s.code AS subject_code, s.name AS subject_name, "
                "COUNT(*) AS total_classes, "
                f"SUM(CASE WHEN e.status IN ({status_marks}) THEN 1 ELSE 0 END) AS attended "
                "FROM attendance_entries e "
                "JOIN attendance_sessions a ON a.id = e.session_id "
                "JOIN subjects s ON s.id = a.subject_id "
                "JOIN classes c ON c.id = a.class_id "
                f"{where} GROUP BY s.id ORDER BY s.name",
                [*counted_statuses, *parameters],
            ).fetchall()
        totals = [
            {
                **dict(row),
                "percentage": round(100 * row["attended"] / row["total_classes"], 1)
                if row["total_classes"]
                else 0,
            }
            for row in summary
        ]
        return {
            "student": dict(student),
            "threshold": 75,
            "subjects": totals,
            "records": [dict(row) for row in rows],
        }

    def faculty_classes(self, faculty_user_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT c.id AS class_id, c.section, c.semester, "
                "s.id AS subject_id, s.code AS subject_code, s.name AS subject_name, "
                "co.name AS course_name "
                "FROM faculty_assignments fa "
                "JOIN classes c ON c.id = fa.class_id "
                "JOIN subjects s ON s.id = fa.subject_id "
                "JOIN courses co ON co.id = c.course_id "
                "WHERE fa.faculty_user_id = ? ORDER BY c.semester, c.section, s.name",
                (faculty_user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def attendance_roster(
        self, faculty_user_id: str, class_id: str, subject_id: str,
        attendance_date: str, period: int,
    ) -> dict[str, Any]:
        self._require_assignment(faculty_user_id, class_id, subject_id)
        with self.connect() as connection:
            students = connection.execute(
                "SELECT st.user_id, st.student_id, st.full_name "
                "FROM enrollments e JOIN students st ON st.user_id = e.student_user_id "
                "WHERE e.class_id = ? ORDER BY st.full_name",
                (class_id,),
            ).fetchall()
            session = connection.execute(
                "SELECT id FROM attendance_sessions "
                "WHERE class_id = ? AND subject_id = ? AND attendance_date = ? AND period = ?",
                (class_id, subject_id, attendance_date, period),
            ).fetchone()
            entries = {}
            if session:
                entries = {
                    row["student_user_id"]: row["status"]
                    for row in connection.execute(
                        "SELECT student_user_id, status FROM attendance_entries WHERE session_id = ?",
                        (session["id"],),
                    )
                }
        return {
            "session_exists": bool(session),
            "students": [
                {
                    **dict(student),
                    "status": entries.get(student["user_id"], "Present"),
                }
                for student in students
            ],
        }

    def _require_assignment(
        self, faculty_user_id: str, class_id: str, subject_id: str
    ) -> None:
        with self.connect() as connection:
            assigned = connection.execute(
                "SELECT 1 FROM faculty_assignments "
                "WHERE faculty_user_id = ? AND class_id = ? AND subject_id = ?",
                (faculty_user_id, class_id, subject_id),
            ).fetchone()
        if not assigned:
            raise PortalError("You are not assigned to this class and subject.", 403)

    def save_attendance(
        self,
        faculty_user_id: str,
        class_id: str,
        subject_id: str,
        attendance_date: str,
        period: int,
        entries: list[dict[str, str]],
        statuses: set[str],
        correction_reason: str = "",
    ) -> None:
        if not isinstance(class_id, str) or not isinstance(subject_id, str):
            raise PortalError("Choose a valid class and subject.")
        self._require_assignment(faculty_user_id, class_id, subject_id)
        if not isinstance(attendance_date, str):
            raise PortalError("Choose a valid attendance date.")
        try:
            datetime.strptime(attendance_date, "%Y-%m-%d")
        except ValueError as error:
            raise PortalError("Choose a valid attendance date.") from error
        if isinstance(period, bool) or not isinstance(period, int) or not 1 <= period <= 16:
            raise PortalError("Choose a valid class period.")
        if not isinstance(entries, list) or not entries or len(entries) > 500:
            raise PortalError("The class roster is empty or too large.")
        if not isinstance(correction_reason, str) or len(correction_reason) > 500:
            raise PortalError("Enter a valid attendance correction reason.")
        seen: set[str] = set()
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("student_user_id"), str)
                or entry["student_user_id"] in seen
                or not isinstance(entry.get("status"), str)
                or entry.get("status") not in statuses
            ):
                raise PortalError("Check the roster and attendance statuses.")
            seen.add(entry["student_user_id"])
        now = utc_now()
        with self.connect() as connection:
            valid_students = {
                row["student_user_id"]
                for row in connection.execute(
                    "SELECT student_user_id FROM enrollments WHERE class_id = ?",
                    (class_id,),
                )
            }
            if seen != valid_students:
                raise PortalError("Attendance must be submitted for the complete class roster.")
            session = connection.execute(
                "SELECT id FROM attendance_sessions "
                "WHERE class_id = ? AND subject_id = ? AND attendance_date = ? AND period = ?",
                (class_id, subject_id, attendance_date, period),
            ).fetchone()
            if session and not correction_reason.strip():
                raise PortalError("Attendance already exists for this class, date, and period.", 409)
            if session:
                session_id = session["id"]
                for entry in entries:
                    old = connection.execute(
                        "SELECT status FROM attendance_entries "
                        "WHERE session_id = ? AND student_user_id = ?",
                        (session_id, entry["student_user_id"]),
                    ).fetchone()
                    if old and old["status"] != entry["status"]:
                        connection.execute(
                            "INSERT INTO audit_log "
                            "(actor_user_id, action, entity_type, entity_id, reason, details, created_at) "
                            "VALUES (?, 'attendance_corrected', 'attendance_entry', ?, ?, ?, ?)",
                            (
                                faculty_user_id, f"{session_id}:{entry['student_user_id']}",
                                correction_reason.strip(),
                                json.dumps({"from": old["status"], "to": entry["status"]}),
                                now,
                            ),
                        )
                    connection.execute(
                        "UPDATE attendance_entries SET status = ?, marked_by = ?, updated_at = ? "
                        "WHERE session_id = ? AND student_user_id = ?",
                        (
                            entry["status"], faculty_user_id, now,
                            session_id, entry["student_user_id"],
                        ),
                    )
                return

            session_id = secrets.token_hex(16)
            connection.execute(
                "INSERT INTO attendance_sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id, class_id, subject_id, faculty_user_id,
                    attendance_date, period, now,
                ),
            )
            connection.executemany(
                "INSERT INTO attendance_entries VALUES (?, ?, ?, ?, ?)",
                [
                    (session_id, entry["student_user_id"], entry["status"], faculty_user_id, now)
                    for entry in entries
                ],
            )
            connection.execute(
                "INSERT INTO audit_log "
                "(actor_user_id, action, entity_type, entity_id, reason, details, created_at) "
                "VALUES (?, 'attendance_saved', 'attendance_session', ?, '', ?, ?)",
                (
                    faculty_user_id, session_id,
                    json.dumps({"class_id": class_id, "subject_id": subject_id}),
                    now,
                ),
            )

    def published_records(self, table: str) -> list[dict[str, Any]]:
        allowed = {
            "notices": "SELECT id, title, body, published_at FROM notices "
            "WHERE published = 1 ORDER BY published_at DESC",
            "events": "SELECT id, title, description, starts_at, ends_at, location "
            "FROM calendar_events WHERE published = 1 ORDER BY starts_at",
            "materials": "SELECT m.id, m.title, m.description, m.url, s.code AS subject_code, "
            "s.name AS subject_name FROM study_materials m "
            "JOIN subjects s ON s.id = m.subject_id WHERE m.published = 1 ORDER BY s.name, m.title",
        }
        if table not in allowed:
            raise PortalError("Records are not available.", 404)
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(allowed[table])]

    def admin_records(self) -> dict[str, list[dict[str, Any]]]:
        queries = {
            "users": "SELECT id, email, role, active, created_at FROM users ORDER BY email",
            "students": "SELECT u.email, s.student_id, s.full_name, s.department, "
            "s.semester, s.enrollment_status FROM students s "
            "JOIN users u ON u.id = s.user_id ORDER BY s.student_id",
            "faculty": "SELECT u.email, f.faculty_id, f.full_name, f.department "
            "FROM faculty f JOIN users u ON u.id = f.user_id ORDER BY f.faculty_id",
            "courses": "SELECT id, code, name, department FROM courses ORDER BY code",
            "subjects": "SELECT s.id, s.code, s.name, s.semester, c.code AS course_code "
            "FROM subjects s JOIN courses c ON c.id = s.course_id ORDER BY s.code",
            "classes": "SELECT cl.id, c.code AS course_code, s.code AS subject_code, "
            "cl.section, cl.semester FROM classes cl "
            "JOIN courses c ON c.id = cl.course_id JOIN subjects s ON s.id = cl.subject_id",
            "assignments": "SELECT u.email AS faculty_email, cl.id AS class_id, "
            "s.code AS subject_code FROM faculty_assignments fa "
            "JOIN users u ON u.id = fa.faculty_user_id "
            "JOIN classes cl ON cl.id = fa.class_id JOIN subjects s ON s.id = fa.subject_id",
            "timetable": "SELECT t.id, cl.id AS class_id, s.code AS subject_code, "
            "u.email AS faculty_email, t.day_of_week, t.period, t.starts_at, t.ends_at "
            "FROM timetable t JOIN classes cl ON cl.id = t.class_id "
            "JOIN subjects s ON s.id = t.subject_id JOIN users u ON u.id = t.faculty_user_id",
            "notices": "SELECT id, title, published_at, published FROM notices ORDER BY published_at DESC",
            "events": "SELECT id, title, starts_at, location, published FROM calendar_events ORDER BY starts_at",
            "materials": "SELECT id, title, url, published FROM study_materials ORDER BY title",
            "attendance_audit": "SELECT a.id, u.email AS actor_email, a.action, "
            "a.entity_type, a.entity_id, a.reason, a.details, a.created_at "
            "FROM audit_log a JOIN users u ON u.id = a.actor_user_id "
            "ORDER BY a.created_at DESC LIMIT 200",
        }
        with self.connect() as connection:
            return {
                name: [dict(row) for row in connection.execute(query)]
                for name, query in queries.items()
            }

    def create_admin_record(self, record_type: str, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise PortalError("Send a valid record.")
        now = utc_now()

        def required(name: str) -> str:
            value = data.get(name)
            if not isinstance(value, str) or not value.strip() or len(value) > 240:
                raise PortalError(f"Enter a valid {name.replace('_', ' ')}.")
            return value.strip()

        def integer(name: str, minimum: int, maximum: int) -> int:
            value = data.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise PortalError(f"Enter a valid {name.replace('_', ' ')}.")
            return value

        try:
            with self.connect() as connection:
                if record_type in {"students", "faculty"}:
                    email = required("email").lower()
                    if not re.fullmatch(r"[^@\s]{1,128}@[^@\s]{1,190}", email):
                        raise PortalError("Enter a valid email address.")
                    password = required("password")
                    if len(password) < 12:
                        raise PortalError("Passwords must contain at least 12 characters.")
                    name = required("full_name")
                    department = required("department")
                    user_id = secrets.token_hex(16)
                    role = "Student" if record_type == "students" else "Faculty"
                    salt, password_hash = hash_password(password)
                    connection.execute(
                        "INSERT INTO users (id, email, role, password_salt, password_hash, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (user_id, email, role, salt, password_hash, now),
                    )
                    if role == "Student":
                        connection.execute(
                            "INSERT INTO students VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                user_id, required("student_id"), name, department,
                                integer("semester", 1, 12), required("enrollment_status"),
                            ),
                        )
                    else:
                        connection.execute(
                            "INSERT INTO faculty VALUES (?, ?, ?, ?)",
                            (user_id, required("faculty_id"), name, department),
                        )
                elif record_type == "administrators":
                    email = required("email").lower()
                    if not re.fullmatch(r"[^@\s]{1,128}@[^@\s]{1,190}", email):
                        raise PortalError("Enter a valid email address.")
                    password = required("password")
                    if len(password) < 12:
                        raise PortalError("Passwords must contain at least 12 characters.")
                    salt, password_hash = hash_password(password)
                    connection.execute(
                        "INSERT INTO users (id, email, role, password_salt, password_hash, created_at) "
                        "VALUES (?, ?, 'Administrator', ?, ?, ?)",
                        (secrets.token_hex(16), email, salt, password_hash, now),
                    )
                elif record_type == "courses":
                    connection.execute(
                        "INSERT INTO courses VALUES (?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("code"), required("name"),
                            required("department"),
                        ),
                    )
                elif record_type == "subjects":
                    connection.execute(
                        "INSERT INTO subjects VALUES (?, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("code"), required("name"),
                            required("course_id"), integer("semester", 1, 12),
                        ),
                    )
                elif record_type == "classes":
                    connection.execute(
                        "INSERT INTO classes VALUES (?, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("course_id"),
                            required("subject_id"), required("section"),
                            integer("semester", 1, 12),
                        ),
                    )
                elif record_type == "assignments":
                    connection.execute(
                        "INSERT INTO faculty_assignments VALUES (?, ?, ?)",
                        (
                            required("faculty_user_id"), required("class_id"),
                            required("subject_id"),
                        ),
                    )
                elif record_type == "enrollments":
                    connection.execute(
                        "INSERT INTO enrollments VALUES (?, ?)",
                        (required("student_user_id"), required("class_id")),
                    )
                elif record_type == "timetable":
                    day = integer("day_of_week", 0, 6)
                    period = integer("period", 1, 16)
                    starts_at, ends_at = required("starts_at"), required("ends_at")
                    try:
                        datetime.strptime(starts_at, "%H:%M")
                        datetime.strptime(ends_at, "%H:%M")
                    except ValueError as error:
                        raise PortalError("Enter timetable times in HH:MM format.") from error
                    if starts_at >= ends_at:
                        raise PortalError("End time must be after start time.")
                    connection.execute(
                        "INSERT INTO timetable VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("class_id"),
                            required("subject_id"), required("faculty_user_id"),
                            day, period, starts_at, ends_at,
                        ),
                    )
                elif record_type == "notices":
                    connection.execute(
                        "INSERT INTO notices VALUES (?, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("title"), required("body"),
                            now if data.get("published") is True else None,
                            int(data.get("published") is True),
                        ),
                    )
                elif record_type == "events":
                    starts_at = validate_datetime(required("starts_at"), "event start time")
                    ends_at_value = data.get("ends_at")
                    ends_at = (
                        validate_datetime(ends_at_value, "event end time")
                        if ends_at_value
                        else None
                    )
                    if ends_at and ends_at < starts_at:
                        raise PortalError("Event end time must be after its start time.")
                    description = data.get("description", "")
                    location = data.get("location", "")
                    if not isinstance(description, str) or not isinstance(location, str):
                        raise PortalError("Enter valid event details.")
                    connection.execute(
                        "INSERT INTO calendar_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("title"),
                            description[:4000], starts_at, ends_at,
                            location[:240],
                            int(data.get("published") is True),
                        ),
                    )
                elif record_type == "materials":
                    url = validate_secure_url(required("url"))
                    connection.execute(
                        "INSERT INTO study_materials VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(16), required("subject_id"),
                            required("title"), str(data.get("description", ""))[:4000],
                            url, int(data.get("published") is True),
                        ),
                    )
                else:
                    raise PortalError("Choose a supported record type.")
        except sqlite3.IntegrityError as error:
            raise PortalError("A related record is missing or this record already exists.", 409) from error

    def update_admin_record(
        self, record_type: str, identifier: str, data: dict[str, Any]
    ) -> None:
        if not isinstance(data, dict) or not identifier or len(identifier) > 240:
            raise PortalError("Send a valid record update.")
        now = utc_now()

        def text(name: str, maximum: int = 240) -> str:
            value = data.get(name)
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise PortalError(f"Enter a valid {name.replace('_', ' ')}.")
            return value.strip()

        def integer(name: str, minimum: int, maximum: int) -> int:
            value = data.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise PortalError(f"Enter a valid {name.replace('_', ' ')}.")
            return value

        try:
            with self.connect() as connection:
                if record_type == "students":
                    profile = connection.execute(
                        "SELECT user_id FROM students WHERE student_id = ?", (identifier,)
                    ).fetchone()
                    if not profile:
                        raise PortalError("Student record not found.", 404)
                    email = text("email").lower()
                    if not re.fullmatch(r"[^@\s]{1,128}@[^@\s]{1,190}", email):
                        raise PortalError("Enter a valid email address.")
                    connection.execute(
                        "UPDATE users SET email = ? WHERE id = ?", (email, profile["user_id"])
                    )
                    connection.execute(
                        "UPDATE students SET full_name = ?, department = ?, semester = ?, "
                        "enrollment_status = ? WHERE user_id = ?",
                        (
                            text("full_name"), text("department"),
                            integer("semester", 1, 12), text("enrollment_status"),
                            profile["user_id"],
                        ),
                    )
                elif record_type == "faculty":
                    profile = connection.execute(
                        "SELECT user_id FROM faculty WHERE faculty_id = ?", (identifier,)
                    ).fetchone()
                    if not profile:
                        raise PortalError("Faculty record not found.", 404)
                    email = text("email").lower()
                    if not re.fullmatch(r"[^@\s]{1,128}@[^@\s]{1,190}", email):
                        raise PortalError("Enter a valid email address.")
                    connection.execute(
                        "UPDATE users SET email = ? WHERE id = ?", (email, profile["user_id"])
                    )
                    connection.execute(
                        "UPDATE faculty SET full_name = ?, department = ? WHERE user_id = ?",
                        (text("full_name"), text("department"), profile["user_id"]),
                    )
                elif record_type == "courses":
                    connection.execute(
                        "UPDATE courses SET code = ?, name = ?, department = ? WHERE id = ?",
                        (text("code"), text("name"), text("department"), identifier),
                    )
                elif record_type == "subjects":
                    connection.execute(
                        "UPDATE subjects SET code = ?, name = ?, semester = ? WHERE id = ?",
                        (text("code"), text("name"), integer("semester", 1, 12), identifier),
                    )
                elif record_type == "classes":
                    connection.execute(
                        "UPDATE classes SET section = ?, semester = ? WHERE id = ?",
                        (text("section"), integer("semester", 1, 12), identifier),
                    )
                elif record_type == "timetable":
                    starts_at, ends_at = text("starts_at", 20), text("ends_at", 20)
                    try:
                        datetime.strptime(starts_at, "%H:%M")
                        datetime.strptime(ends_at, "%H:%M")
                    except ValueError as error:
                        raise PortalError("Enter timetable times in HH:MM format.") from error
                    if starts_at >= ends_at:
                        raise PortalError("End time must be after start time.")
                    connection.execute(
                        "UPDATE timetable SET day_of_week = ?, period = ?, starts_at = ?, ends_at = ? "
                        "WHERE id = ?",
                        (
                            integer("day_of_week", 0, 6), integer("period", 1, 16),
                            starts_at, ends_at, identifier,
                        ),
                    )
                elif record_type == "notices":
                    published = data.get("published")
                    if not isinstance(published, bool):
                        raise PortalError("Choose whether the notice should be published.")
                    connection.execute(
                        "UPDATE notices SET title = ?, body = ?, published = ?, published_at = ? "
                        "WHERE id = ?",
                        (
                            text("title"), text("body", 4000), int(published),
                            now if published else None, identifier,
                        ),
                    )
                elif record_type == "events":
                    published = data.get("published")
                    if not isinstance(published, bool):
                        raise PortalError("Choose whether the event should be published.")
                    ends_at = data.get("ends_at") or None
                    starts_at = validate_datetime(text("starts_at", 40), "event start time")
                    if ends_at is not None:
                        ends_at = validate_datetime(ends_at, "event end time")
                        if ends_at < starts_at:
                            raise PortalError("Event end time must be after its start time.")
                    description = data.get("description", "")
                    location = data.get("location", "")
                    if not isinstance(description, str) or not isinstance(location, str):
                        raise PortalError("Enter valid event details.")
                    connection.execute(
                        "UPDATE calendar_events SET title = ?, description = ?, starts_at = ?, "
                        "ends_at = ?, location = ?, published = ? WHERE id = ?",
                        (
                            text("title"), description[:4000],
                            starts_at, ends_at,
                            location[:240], int(published), identifier,
                        ),
                    )
                elif record_type == "materials":
                    published = data.get("published")
                    url = validate_secure_url(text("url", 2000))
                    if not isinstance(published, bool):
                        raise PortalError("Choose the publication status.")
                    description = data.get("description", "")
                    if not isinstance(description, str):
                        raise PortalError("Enter a valid material description.")
                    connection.execute(
                        "UPDATE study_materials SET title = ?, description = ?, url = ?, "
                        "published = ? WHERE id = ?",
                        (
                            text("title"), description[:4000],
                            url, int(published), identifier,
                        ),
                    )
                else:
                    raise PortalError("This record type cannot be edited.")
                if connection.total_changes == 0:
                    raise PortalError("Record not found.", 404)
        except sqlite3.IntegrityError as error:
            raise PortalError("The change conflicts with another record.", 409) from error

    def set_user_access(
        self, user_id: str, active: bool, actor_user_id: str | None = None
    ) -> None:
        if not isinstance(active, bool):
            raise PortalError("Choose whether the account should be active.")
        with self.connect() as connection:
            target = connection.execute(
                "SELECT role, active FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if not target:
                raise PortalError("Account not found.", 404)
            if not active and actor_user_id == user_id:
                raise PortalError("You cannot deactivate your own signed-in account.", 409)
            if not active and target["role"] == "Administrator":
                active_admins = connection.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'Administrator' AND active = 1"
                ).fetchone()[0]
                if active_admins <= 1:
                    raise PortalError("The last active administrator cannot be deactivated.", 409)
            cursor = connection.execute(
                "UPDATE users SET active = ? WHERE id = ?", (int(active), user_id)
            )
            if cursor.rowcount != 1:
                raise PortalError("Account not found.", 404)
            if not active:
                connection.execute(
                    "DELETE FROM login_sessions WHERE user_id = ?", (user_id,)
                )

    def attendance_report(
        self, faculty_user_id: str, class_id: str, subject_id: str,
        start_date: str, end_date: str,
    ) -> list[dict[str, Any]]:
        self._require_assignment(faculty_user_id, class_id, subject_id)
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT st.student_id, st.full_name, a.attendance_date, a.period, e.status "
                "FROM attendance_sessions a "
                "JOIN attendance_entries e ON e.session_id = a.id "
                "JOIN students st ON st.user_id = e.student_user_id "
                "WHERE a.class_id = ? AND a.subject_id = ? "
                "AND a.attendance_date BETWEEN ? AND ? "
                "ORDER BY a.attendance_date, a.period, st.student_id",
                (class_id, subject_id, start_date, end_date),
            ).fetchall()
        return [dict(row) for row in rows]

    def attendance_audit(self, user_id: str, role: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            if role == "Administrator":
                rows = connection.execute(
                    "SELECT a.action, a.entity_type, a.entity_id, a.reason, "
                    "a.details, a.created_at, u.email AS actor_email "
                    "FROM audit_log a JOIN users u ON u.id = a.actor_user_id "
                    "ORDER BY a.created_at DESC LIMIT 200"
                ).fetchall()
            elif role == "Faculty":
                rows = connection.execute(
                    "SELECT action, entity_type, entity_id, reason, details, created_at "
                    "FROM audit_log WHERE actor_user_id = ? "
                    "ORDER BY created_at DESC LIMIT 200",
                    (user_id,),
                ).fetchall()
            else:
                raise PortalError("Faculty or administrator access is required.", 403)
        return [dict(row) for row in rows]

    def academic_records(self, user_id: str, role: str) -> dict[str, list[dict[str, Any]]]:
        with self.connect() as connection:
            if role == "Student":
                course_filter = (
                    "WHERE EXISTS (SELECT 1 FROM classes cl "
                    "JOIN enrollments en ON en.class_id = cl.id "
                    "WHERE cl.course_id = co.id AND en.student_user_id = ?)"
                )
                params: tuple[Any, ...] = (user_id,)
            elif role == "Faculty":
                course_filter = (
                    "WHERE EXISTS (SELECT 1 FROM faculty_assignments fa "
                    "JOIN classes cl ON cl.id = fa.class_id "
                    "WHERE cl.course_id = co.id AND fa.faculty_user_id = ?)"
                )
                params = (user_id,)
            else:
                course_filter, params = "", ()
            courses = connection.execute(
                "SELECT co.id, co.code, co.name, co.department FROM courses co "
                + course_filter + " ORDER BY co.code",
                params,
            ).fetchall()
            course_ids = [course["id"] for course in courses]
            if course_ids:
                marks = ",".join("?" for _ in course_ids)
                subjects = connection.execute(
                    "SELECT code, name, course_id, semester FROM subjects "
                    f"WHERE course_id IN ({marks}) ORDER BY code",
                    course_ids,
                ).fetchall()
            else:
                subjects = []
            if role == "Student":
                timetable = connection.execute(
                    "SELECT t.day_of_week, t.period, t.starts_at, t.ends_at, "
                    "co.name AS course_name, cl.section, s.code AS subject_code, "
                    "s.name AS subject_name, f.full_name AS faculty_name "
                    "FROM timetable t JOIN classes cl ON cl.id = t.class_id "
                    "JOIN enrollments en ON en.class_id = cl.id "
                    "JOIN courses co ON co.id = cl.course_id "
                    "JOIN subjects s ON s.id = t.subject_id "
                    "JOIN faculty f ON f.user_id = t.faculty_user_id "
                    "WHERE en.student_user_id = ? ORDER BY t.day_of_week, t.period",
                    (user_id,),
                ).fetchall()
            elif role == "Faculty":
                timetable = connection.execute(
                    "SELECT t.day_of_week, t.period, t.starts_at, t.ends_at, "
                    "co.name AS course_name, cl.section, s.code AS subject_code, "
                    "s.name AS subject_name, f.full_name AS faculty_name "
                    "FROM timetable t JOIN classes cl ON cl.id = t.class_id "
                    "JOIN courses co ON co.id = cl.course_id "
                    "JOIN subjects s ON s.id = t.subject_id "
                    "JOIN faculty f ON f.user_id = t.faculty_user_id "
                    "WHERE t.faculty_user_id = ? ORDER BY t.day_of_week, t.period",
                    (user_id,),
                ).fetchall()
            else:
                timetable = connection.execute(
                    "SELECT t.day_of_week, t.period, t.starts_at, t.ends_at, "
                    "co.name AS course_name, cl.section, s.code AS subject_code, "
                    "s.name AS subject_name, f.full_name AS faculty_name "
                    "FROM timetable t JOIN classes cl ON cl.id = t.class_id "
                    "JOIN courses co ON co.id = cl.course_id "
                    "JOIN subjects s ON s.id = t.subject_id "
                    "JOIN faculty f ON f.user_id = t.faculty_user_id "
                    "ORDER BY t.day_of_week, t.period"
                ).fetchall()
        subjects_by_course: dict[str, list[str]] = {}
        for subject in subjects:
            subjects_by_course.setdefault(subject["course_id"], []).append(
                f'{subject["code"]} — {subject["name"]} (semester {subject["semester"]})'
            )
        return {
            "courses": [
                {
                    **dict(course),
                    "subjects": subjects_by_course.get(course["id"], []),
                }
                for course in courses
            ],
            "timetable": [dict(row) for row in timetable],
        }

    def faculty_directory(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT f.full_name, f.department, u.email, "
                "GROUP_CONCAT(DISTINCT s.code || ' — ' || s.name) AS subjects "
                "FROM faculty f JOIN users u ON u.id = f.user_id "
                "LEFT JOIN faculty_assignments fa ON fa.faculty_user_id = f.user_id "
                "LEFT JOIN subjects s ON s.id = fa.subject_id "
                "WHERE u.active = 1 GROUP BY f.user_id ORDER BY f.full_name"
            ).fetchall()
        return [
            {
                "full_name": row["full_name"],
                "department": row["department"],
                "email": row["email"],
                "subjects": row["subjects"].split(",") if row["subjects"] else [],
            }
            for row in rows
        ]

    def profile(self, user_id: str, role: str) -> dict[str, Any]:
        table = {"Student": "students", "Faculty": "faculty"}.get(role)
        if not table:
            return {}
        with self.connect() as connection:
            row = connection.execute(
                f"SELECT * FROM {table} WHERE user_id = ?", (user_id,)
            ).fetchone()
        if not row:
            return {}
        return {key: value for key, value in dict(row).items() if key != "user_id"}
