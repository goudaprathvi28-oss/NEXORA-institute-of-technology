# NEXORA College Portal

The project keeps the existing one-page homepage and adds standalone portal
pages, a Python standard-library HTTP backend, and a SQLite records database.
No packages need to be installed; Python 3.10+ is required.

## Run a clearly labeled local demo

In PowerShell, from the project directory:

```powershell
$env:DEMO_MODE = "1"
$env:HOST = "127.0.0.1"
python server.py
```

Open <http://127.0.0.1:8000>. Demo mode is accepted only on localhost. It uses
a separate `data/nexora-demo.sqlite3` database and synthetic records. Each
portal page displays a demo warning. Do not enter real student/faculty
information in this mode.

Demo accounts:

| Role | Email | Password |
|---|---|---|
| Student | `student.demo@nexora.invalid` | `NEXORA-DEMO-STUDENT` |
| Faculty | `faculty.demo@nexora.invalid` | `NEXORA-DEMO-FACULTY` |
| Administrator | `admin.demo@nexora.invalid` | `NEXORA-DEMO-ADMIN` |

Pages: `/admissions`, `/student-dashboard`, `/faculty-dashboard`, `/attendance`,
`/academics`, `/events`, `/notices`, `/study-materials`, `/placements`,
`/faculty-directory`, `/assistant`, and `/admin`.

The demo accounts and sample records are created only when `DEMO_MODE=1`. The
live and demo databases are mode-tagged and cannot be opened in the other mode.
Database files are ignored by Git.

## Set up a live database

Use the live database (demo mode off), create the first administrator, then
start the server with the same environment and database path:

```powershell
$env:DEMO_MODE = "0"
$env:NEXORA_DB_PATH = "data/nexora.sqlite3"
$env:HOST = "127.0.0.1"
$env:COOKIE_SECURE = "0"
python server.py --create-admin
python server.py
```

The setup command asks for an administrator email and a 14-character minimum
initial password. Bootstrap is allowed only while the live database has no
accounts. The administrator can then add student/faculty accounts and records
from `/admin`. Passwords are hashed with PBKDF2-HMAC-SHA256; the database stores
only salted hashes. There is no password-reset email or institutional SSO
integration in this version.

The following environment variables are supported:

| Variable | Purpose |
|---|---|
| `DEMO_MODE` | Set to `1` only for local, synthetic-data demonstrations. |
| `NEXORA_DB_PATH` | SQLite file path; defaults to a separate live or demo file under `data/`. |
| `HOST`, `PORT` | Bind address and port; local defaults are `127.0.0.1:8000`. |
| `COOKIE_SECURE` | Set to `1` when HTTPS is provided by the production reverse proxy. |
| `ATTENDANCE_THRESHOLD` | Warning threshold from 1–100 percent. The default 75 is illustrative, not NEXORA policy. |
| `ATTENDANCE_STATUSES` | Comma-separated approved statuses; default `Present,Absent,Excused`. |
| `ATTENDANCE_COUNTED_STATUSES` | Which configured statuses count as attended; default `Present`. |
| `AI_API_KEY`, `AI_API_URL`, `AI_MODEL` | Server-side credentials and endpoint for the AI assistant. |

`.env.example` contains placeholders. The server does not automatically load
`.env`; configure environment variables through PowerShell or the hosting
platform's secret manager. Never publish API keys or real records.

## Database schema

`portal.py` defines and initializes the SQLite schema. It contains:

- `users`, `students`, `faculty` — accounts, roles, and college identity fields.
- `courses`, `subjects`, `classes`, `faculty_assignments`, `enrollments` —
  academic catalog and role-to-class associations.
- `timetable`, `calendar_events`, `notices`, `study_materials` — schedules and
  published campus records.
- `attendance_sessions`, `attendance_entries` — period-level attendance with a
  unique class/subject/date/period constraint.
- `audit_log` — attendance creation/correction actor, reason, changed values,
  and timestamp.
- `login_sessions`, `portal_metadata` — hashed session-token lookup and
  demo/live database separation.

Foreign keys constrain course, subject, class, assignment, enrollment, and
attendance relationships. Faculty assignments are checked in the backend
before roster reads, attendance changes, and report exports.

## Portal behavior and permissions

- Students can read only their own attendance and profile summary. Their
  attendance endpoints are read-only.
- Faculty can see only assigned classes, load the enrolled roster, submit
  attendance, correct an existing session with a reason, review their audit
  history, and export an assigned-class CSV report.
- A unique database constraint prevents duplicate attendance for the same
  class, subject, date, and period. Corrections update the original records and
  add audit rows.
- Administrators can create and edit student/faculty, course, subject, class,
  timetable, notice, event, and study-material records, create faculty
  assignments and student enrollments, and deactivate/reactivate accounts.
- Login uses salted PBKDF2 password hashes, expiring server-side sessions,
  HttpOnly/SameSite cookies, CSRF tokens, request limits, and role checks on
  data endpoints. Student/faculty data and AI calls require an authenticated
  session.
- Reports export to CSV. CSV values that could be interpreted as spreadsheet
  formulas are escaped.

## Official-data and production limits

No approved NEXORA roster, academic catalog, attendance rules, calendar, or
identity service was supplied. Demo records are clearly synthetic and use
`.invalid` email addresses. No NEXORA achievements, fees, events, faculty
profiles, or attendance policy are asserted. The configured 75% threshold and
default statuses are examples; set the actual institution-approved values
before real use.

The existing assistant source excerpts still refer to BMSIT&M and are not
verified NEXORA sources. The UI warns users not to treat those facts as
NEXORA information. Configure the AI key only on the server and replace the
allowlisted source material with authoritative NEXORA pages before relying on
the assistant.

Before entering real records, the institution should approve the identity
workflow, data-retention/access policies, attendance statuses and threshold,
and data import process. Set `COOKIE_SECURE=1`, terminate HTTPS at a maintained
reverse proxy, keep the built-in server private behind it, restrict access to
the database file, configure encrypted backups, and add institutional
monitoring and recovery procedures. SQLite is suitable for a small deployment
or prototype; assess a managed database and institutional identity integration
for high-concurrency production use.

## Tests

Run the dependency-free backend tests:

```powershell
python -m unittest discover -s tests -v
```

Tests cover password hashing and demo/live separation, login and RBAC, student
read-only attendance, faculty assignment checks, duplicate prevention,
correction/audit behavior, CSV export, and the existing AI proxy.

The homepage's existing Unsplash images remain illustrative placeholders;
replace them with institution-approved, licensed assets before production.
