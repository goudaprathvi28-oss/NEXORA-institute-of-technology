(() => {
  "use strict";

  const pagePath = window.NEXORA_PORTAL.page;
  const pageTitles = {
    "/admissions": "Admissions",
    "/student-dashboard": "Student Dashboard",
    "/faculty-dashboard": "Faculty Dashboard",
    "/attendance": "Attendance",
    "/academics": "Academics",
    "/events": "Events",
    "/notices": "Notices",
    "/study-materials": "Study Materials",
    "/placements": "Placements",
    "/faculty-directory": "Faculty Directory",
    "/assistant": "AI College Assistant",
    "/admin": "Administrator Dashboard",
    "/login": "Portal Sign In",
  };
  const root = document.querySelector("#portal-page");
  const statusBox = document.querySelector("#portal-status");
  let context = { authenticated: false, user: null, csrf_token: null, demo_mode: false };

  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);

  const showStatus = (message, kind = "error") => {
    statusBox.textContent = message;
    statusBox.className = `status-message ${kind === "success" ? "success" : kind === "info" ? "info" : ""}`;
    statusBox.hidden = false;
  };
  const clearStatus = () => { statusBox.hidden = true; statusBox.textContent = ""; };

  async function api(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    if (options.method && options.method !== "GET" && context.csrf_token) {
      headers.set("X-CSRF-Token", context.csrf_token);
    }
    const response = await fetch(url, { credentials: "same-origin", ...options, headers });
    const type = response.headers.get("content-type") || "";
    if (!type.includes("application/json")) {
      if (!response.ok) throw new Error(`Request failed (${response.status}).`);
      return response;
    }
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    return result;
  }

  function button(label, type = "submit", extra = "") {
    return `<button class="button ${extra}" type="${type}">${escapeHtml(label)}</button>`;
  }
  function empty(message) {
    return `<div class="empty-state">${escapeHtml(message)}</div>`;
  }
  function metric(label, value) {
    return `<article class="card"><span class="metric">${escapeHtml(value)}</span><span class="metric-label">${escapeHtml(label)}</span></article>`;
  }
  function table(headers, rows) {
    if (!rows.length) return empty("No records are available yet.");
    return `<div class="table-wrap"><table><thead><tr>${headers.map((value) => `<th>${escapeHtml(value)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
  }
  function noVerifiedContent(message) {
    return `<div class="panel"><h2 class="section-title">Official information pending</h2><p>${escapeHtml(message)}</p><p class="metadata">No institution-approved NEXORA source or record set has been connected. No details are being inferred or invented.</p></div>`;
  }

  function setNavigation() {
    const signedIn = context.authenticated;
    document.querySelector("#demo-banner").hidden = !context.demo_mode;
    document.querySelector("#sign-in-link").hidden = signedIn;
    document.querySelector("#sign-out-button").hidden = !signedIn;
    document.querySelectorAll("[data-auth-link]").forEach((link) => { link.hidden = !signedIn; });
    document.querySelectorAll("[data-role-link]").forEach((link) => {
      link.hidden = !signedIn || link.dataset.roleLink !== context.user.role;
    });
    document.querySelector("#sign-out-button").addEventListener("click", async () => {
      try {
        await api("/api/auth/logout", { method: "POST", body: "{}" });
        window.location.assign("/login");
      } catch (error) {
        showStatus(error.message);
      }
    }, { once: true });
  }

  async function loadContext() {
    context = await api("/api/me");
    setNavigation();
    document.querySelector("#breadcrumb-current").textContent = pageTitles[pagePath] || "Portal";
    return context;
  }

  function requireRole(roles) {
    if (!context.authenticated) {
      window.location.assign(`/login?next=${encodeURIComponent(pagePath)}`);
      return false;
    }
    if (roles && !roles.includes(context.user.role)) {
      root.innerHTML = empty("Your account does not have permission to view this page.");
      return false;
    }
    return true;
  }

  async function renderLogin() {
    const params = new URLSearchParams(location.search);
    const next = params.get("next") || "/";
    const safeNext = Object.hasOwn(pageTitles, next) ? next : "/";
    root.innerHTML = `
      <div class="two-column">
        <form class="form-card" id="login-form" novalidate>
          <h2 class="section-title">Sign in to your portal</h2>
          <p>Use your institution-provisioned account. Access depends on your assigned role.</p>
          <div class="stack">
            <div class="field"><label for="login-email">Institutional email</label><input id="login-email" type="email" autocomplete="username" maxlength="320" required></div>
            <div class="field"><label for="login-password">Password</label><input id="login-password" type="password" autocomplete="current-password" maxlength="256" required></div>
          </div>
          <div class="form-actions">${button("Sign in")}</div>
          <p class="metadata" id="login-message" role="status" aria-live="polite"></p>
        </form>
        <aside class="panel">
          <h2 class="section-title">Account security</h2>
          <p>Never share your password. Sign out after using a shared device. Your records are available only to authenticated roles authorized by the college.</p>
          ${context.demo_mode ? `<div class="demo-credentials" id="demo-credentials"><strong>Local demo accounts only — synthetic data.</strong><p>Loading local demo sign-in details…</p></div>` : `<p class="metadata">No demo accounts are enabled. Ask your institution administrator for access.</p>`}
        </aside>
      </div>`;
    document.querySelector("#login-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const message = document.querySelector("#login-message");
      const submit = form.querySelector('button[type="submit"]');
      if (!form.reportValidity()) return;
      submit.disabled = true;
      submit.textContent = "Signing in…";
      message.textContent = "";
      try {
        const result = await api("/api/auth/login", {
          method: "POST",
          body: JSON.stringify({
            email: document.querySelector("#login-email").value.trim(),
            password: document.querySelector("#login-password").value,
          }),
        });
        context = { authenticated: true, user: result.user, csrf_token: result.csrf_token, demo_mode: context.demo_mode };
        window.location.assign(safeNext);
      } catch (error) {
        message.textContent = error.message;
        submit.disabled = false;
        submit.textContent = "Sign in";
      }
    });
    if (context.demo_mode) {
      try {
        const { accounts } = await api("/api/demo-credentials");
        const panel = document.querySelector("#demo-credentials");
        panel.replaceChildren();
        const heading = document.createElement("strong");
        heading.textContent = "Local demo accounts only — synthetic data.";
        panel.append(heading);
        accounts.forEach((account) => {
          const row = document.createElement("p");
          const email = document.createElement("code");
          const password = document.createElement("code");
          email.textContent = account.email;
          password.textContent = account.password;
          row.append(`${account.role}: `, email, " / ", password);
          panel.append(row);
        });
        const note = document.createElement("p");
        note.textContent = "Demo credentials are unavailable when demo mode is disabled.";
        panel.append(note);
      } catch (error) {
        showStatus(error.message);
      }
    }
  }

  async function renderStudentDashboard() {
    if (!requireRole(["Student"])) return;
    const data = await api("/api/dashboard");
    const profile = data.profile || {};
    const attendance = data.attendance || {};
    root.innerHTML = `
      <div class="stack">
        <div class="panel"><h2 class="section-title">Welcome, ${escapeHtml(profile.full_name || "Student")}</h2><p>${escapeHtml(profile.student_id)} · ${escapeHtml(profile.department)} · Semester ${escapeHtml(profile.semester)} · ${escapeHtml(profile.enrollment_status)}</p></div>
        <div class="card-grid">${(attendance.subjects || []).map((subject) => metric(`${subject.subject_code} attendance`, `${subject.percentage}%`)).join("") || metric("Attendance records", "—")}</div>
        <div class="panel"><h2 class="section-title">Attendance by subject</h2><p>Threshold shown for this environment: ${escapeHtml(data.threshold)}%. Verify the institution's approved policy before production use.</p>
          ${table(["Subject", "Total classes", "Attended", "Percentage", "Status"], (attendance.subjects || []).map((subject) => `<tr><td>${escapeHtml(subject.subject_name)} (${escapeHtml(subject.subject_code)})</td><td>${escapeHtml(subject.total_classes)}</td><td>${escapeHtml(subject.attended)}</td><td>${escapeHtml(subject.percentage)}%</td><td>${subject.percentage < data.threshold ? `<span class="attendance-warning">Below threshold</span>` : "On track"}</td></tr>`))}
        </div>
        <div class="form-actions"><a class="button" href="/attendance">Open attendance reports</a><a class="button secondary" href="/notices">View notices</a><a class="button secondary" href="/study-materials">Study materials</a></div>
      </div>`;
  }

  async function renderStudentAttendance() {
    if (!requireRole(["Student"])) return;
    root.innerHTML = `
      <div class="stack">
        <div class="panel"><h2 class="section-title">Your attendance records</h2><p>Only your own records are displayed. Students have read-only access.</p>
          <div class="toolbar"><div class="field"><label for="attendance-month">Month</label><input id="attendance-month" type="month"></div><label><input id="semester-only" type="checkbox"> Current-semester records</label>${button("Apply filters", "button")}</div>
          <div id="student-attendance-results">${empty("Loading attendance records…")}</div>
        </div>
      </div>`;
    const load = async () => {
      const month = document.querySelector("#attendance-month").value;
      const semester = document.querySelector("#semester-only").checked;
      const params = new URLSearchParams();
      if (month) params.set("month", month);
      if (semester) params.set("semester", "true");
      const result = await api(`/api/attendance/student?${params}`);
      const box = document.querySelector("#student-attendance-results");
      const subjects = result.subjects || [];
      box.innerHTML = `<p>Attendance warning threshold: <strong>${escapeHtml(result.threshold)}%</strong>. This is the environment setting, not a confirmed NEXORA policy.</p>
        ${subjects.map((subject) => subject.percentage < result.threshold ? `<p class="attendance-warning">${escapeHtml(subject.subject_code)} is below the configured threshold (${escapeHtml(subject.percentage)}%).</p>` : "").join("")}
        ${table(["Subject", "Date", "Period", "Status"], (result.records || []).map((record) => `<tr><td>${escapeHtml(record.subject_name)} (${escapeHtml(record.subject_code)})</td><td>${escapeHtml(record.attendance_date)}</td><td>${escapeHtml(record.period)}</td><td>${escapeHtml(record.status)}</td></tr>`))}
        <h3>Summary</h3>${table(["Subject", "Classes", "Attended", "Attendance"], subjects.map((subject) => `<tr><td>${escapeHtml(subject.subject_name)}</td><td>${escapeHtml(subject.total_classes)}</td><td>${escapeHtml(subject.attended)}</td><td>${escapeHtml(subject.percentage)}%</td></tr>`))}`;
    };
    document.querySelector(".toolbar .button").addEventListener("click", async () => {
      try { await load(); } catch (error) { showStatus(error.message); }
    });
    await load();
  }

  async function renderFacultyDashboard() {
    if (!requireRole(["Faculty"])) return;
    const data = await api("/api/dashboard");
    const profile = data.profile || {};
    const classes = data.classes || [];
    root.innerHTML = `<div class="stack">
      <div class="panel"><h2 class="section-title">Welcome, ${escapeHtml(profile.full_name || "Faculty member")}</h2><p>${escapeHtml(profile.faculty_id)} · ${escapeHtml(profile.department)}</p></div>
      <div class="card-grid">${metric("Assigned classes", classes.length)}${metric("Assigned subjects", new Set(classes.map((item) => item.subject_id)).size)}</div>
      <div class="panel"><h2 class="section-title">Your assigned classes</h2>${table(["Course", "Section", "Semester", "Subject"], classes.map((item) => `<tr><td>${escapeHtml(item.course_name)}</td><td>${escapeHtml(item.section)}</td><td>${escapeHtml(item.semester)}</td><td>${escapeHtml(item.subject_name)} (${escapeHtml(item.subject_code)})</td></tr>`))}</div>
      <div class="form-actions"><a class="button" href="/attendance">Manage attendance</a></div></div>`;
  }

  async function renderFacultyAttendance() {
    if (!requireRole(["Faculty"])) return;
    const { classes } = await api("/api/faculty/classes");
    const options = classes.map((item) => `<option value="${escapeHtml(item.class_id)}" data-subject="${escapeHtml(item.subject_id)}">${escapeHtml(item.course_name)} · ${escapeHtml(item.section)} · ${escapeHtml(item.subject_code)}</option>`).join("");
    root.innerHTML = `<div class="stack">
      <div class="panel"><h2 class="section-title">Take attendance</h2><p>Only assigned classes are available. Saving a second entry requires a correction reason and creates an audit record.</p>
        ${classes.length ? `<form id="attendance-form">
          <div class="toolbar">
            <div class="field"><label for="attendance-class">Assigned class and subject</label><select id="attendance-class" required>${options}</select></div>
            <div class="field"><label for="attendance-date">Date</label><input id="attendance-date" type="date" required value="${new Date().toISOString().slice(0, 10)}"></div>
            <div class="field"><label for="attendance-period">Period</label><input id="attendance-period" type="number" min="1" max="16" value="1" required></div>
            <button class="button" id="load-roster" type="button">Load class roster</button>
          </div>
          <div id="roster-status" class="metadata" role="status"></div>
          <div id="attendance-roster"></div>
          <div id="correction-field" class="field" hidden><label for="correction-reason">Correction reason (required for an existing attendance session)</label><textarea id="correction-reason" maxlength="500"></textarea></div>
          <div class="form-actions"><button class="button" type="submit" id="save-attendance" disabled>Save attendance</button></div>
        </form>` : empty("No class or subject assignments are available for this faculty account.")}
      </div>
      <div class="panel"><h2 class="section-title">Export an attendance report</h2>
        <form id="report-form" class="toolbar">
          <div class="field"><label for="report-class">Assigned class</label><select id="report-class" required>${options}</select></div>
          <div class="field"><label for="report-start">From</label><input id="report-start" type="date" required></div>
          <div class="field"><label for="report-end">To</label><input id="report-end" type="date" required></div>
          <button class="button" type="submit">Download CSV</button>
        </form><p class="metadata">CSV export includes student IDs, names, dates, periods, and statuses for the selected assigned class.</p>
      </div>
      <div class="panel"><h2 class="section-title">Your attendance audit history</h2><div id="attendance-audit">${empty("Loading audit history…")}</div></div>
    </div>`;
    const refreshAudit = async () => {
      const audit = await api("/api/attendance/audit");
      document.querySelector("#attendance-audit").innerHTML = table(
        ["Action", "Record", "Reason", "Changes", "Time"],
        (audit.records || []).map((item) => `<tr><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.entity_id)}</td><td>${escapeHtml(item.reason || "—")}</td><td>${escapeHtml(item.details)}</td><td>${escapeHtml(item.created_at)}</td></tr>`),
      );
    };
    await refreshAudit();
    if (!classes.length) return;
    const select = document.querySelector("#attendance-class");
    const rosterEl = document.querySelector("#attendance-roster");
    const loadButton = document.querySelector("#load-roster");
    const saveButton = document.querySelector("#save-attendance");
    const readSelection = () => ({
      class_id: select.value,
      subject_id: select.selectedOptions[0].dataset.subject,
      date: document.querySelector("#attendance-date").value,
      period: Number(document.querySelector("#attendance-period").value),
    });
    const loadRoster = async () => {
      clearStatus();
      loadButton.disabled = true;
      loadButton.textContent = "Loading…";
      try {
        const selection = readSelection();
        const query = new URLSearchParams({
          class_id: selection.class_id, subject_id: selection.subject_id,
          date: selection.date, period: String(selection.period),
        });
        const result = await api(`/api/faculty/roster?${query}`);
        document.querySelector("#roster-status").textContent = result.session_exists
          ? "Attendance exists. Changes require a reason and will be audited."
          : `${result.students.length} enrolled student(s) loaded.`;
        document.querySelector("#correction-field").hidden = !result.session_exists;
        rosterEl.innerHTML = result.students.length ? result.students.map((student) => `
          <div class="attendance-row" data-student="${escapeHtml(student.user_id)}">
            <span><strong>${escapeHtml(student.full_name)}</strong><br><span class="metadata">${escapeHtml(student.student_id)}</span></span>
            <div class="field"><label for="status-${escapeHtml(student.user_id)}">Attendance status</label>
              <select id="status-${escapeHtml(student.user_id)}" class="attendance-status">
                ${(result.statuses || ["Present", "Absent", "Excused"]).map((status) => `<option ${student.status === status ? "selected" : ""}>${escapeHtml(status)}</option>`).join("")}
              </select>
            </div>
          </div>`).join("") : empty("No students are enrolled in this class.");
        saveButton.disabled = !result.students.length;
      } catch (error) {
        showStatus(error.message);
        rosterEl.innerHTML = "";
      } finally {
        loadButton.disabled = false;
        loadButton.textContent = "Load class roster";
      }
    };
    loadButton.addEventListener("click", loadRoster);
    document.querySelector("#attendance-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const rows = [...rosterEl.querySelectorAll(".attendance-row")];
      if (!rows.length) return;
      const selection = readSelection();
      const correctionReason = document.querySelector("#correction-reason").value.trim();
      saveButton.disabled = true;
      saveButton.textContent = "Saving…";
      try {
        const result = await api("/api/attendance", {
          method: "POST",
          body: JSON.stringify({
            ...selection,
            correction_reason: correctionReason,
            entries: rows.map((row) => ({
              student_user_id: row.dataset.student,
              status: row.querySelector(".attendance-status").value,
            })),
          }),
        });
        document.querySelector("#correction-reason").value = "";
        await loadRoster();
        await refreshAudit();
        showStatus(result.message, "success");
      } catch (error) {
        showStatus(error.message);
      } finally {
        saveButton.disabled = false;
        saveButton.textContent = "Save attendance";
      }
    });
    document.querySelector("#report-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const reportClass = document.querySelector("#report-class");
      const option = reportClass.selectedOptions[0];
      const query = new URLSearchParams({
        class_id: reportClass.value,
        subject_id: option.dataset.subject,
        start_date: document.querySelector("#report-start").value,
        end_date: document.querySelector("#report-end").value,
      });
      location.assign(`/api/faculty/report.csv?${query}`);
    });
  }

  async function renderNotices() {
    if (!requireRole(["Student", "Faculty", "Administrator"])) return;
    const result = await api("/api/notices");
    root.innerHTML = `<div class="stack"><p class="metadata">Only administrator-published notices are shown.</p>${result.records.length ? `<ul class="notice-list">${result.records.map((item) => `<li class="notice-item"><h3>${escapeHtml(item.title)}</h3><time>${escapeHtml(item.published_at || "")}</time><p>${escapeHtml(item.body)}</p></li>`).join("")}</ul>` : empty("No published notices are available.")}</div>`;
  }

  async function renderEvents() {
    if (!requireRole(["Student", "Faculty", "Administrator"])) return;
    const result = await api("/api/events");
    root.innerHTML = `<div class="stack"><p class="metadata">Only administrator-published calendar entries are shown.</p>${result.records.length ? `<div class="card-grid">${result.records.map((item) => `<article class="card"><p class="eyebrow">${escapeHtml(item.starts_at)}</p><h2>${escapeHtml(item.title)}</h2><p>${escapeHtml(item.description)}</p><p><strong>Location:</strong> ${escapeHtml(item.location || "Not specified")}</p></article>`).join("")}</div>` : empty("No published events are available.")}</div>`;
  }

  async function renderMaterials() {
    if (!requireRole(["Student", "Faculty", "Administrator"])) return;
    const result = await api("/api/materials");
    root.innerHTML = `<div class="stack"><p class="metadata">Published study-resource links for the available subjects.</p>${result.records.length ? `<div class="card-grid">${result.records.map((item) => `<article class="card"><p class="eyebrow">${escapeHtml(item.subject_code)}</p><h2>${escapeHtml(item.title)}</h2><p>${escapeHtml(item.description)}</p><a class="card-link" href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">Open material ↗</a></article>`).join("")}</div>` : empty("No study materials have been published.")}</div>`;
  }

  async function renderAcademics() {
    if (!context.authenticated) {
      root.innerHTML = `${noVerifiedContent("The official NEXORA course catalog is not connected yet.")}<p class="form-actions"><a class="button" href="/login">Sign in to view connected academic records</a></p>`;
      return;
    }
    const result = await api("/api/academics");
    root.innerHTML = `<div class="stack"><p class="metadata">Records shown here are entered by an administrator. Demo records are synthetic.</p>
      <div class="panel"><h2 class="section-title">Courses and subjects</h2>${result.courses.length ? table(["Course", "Department", "Subjects"], result.courses.map((course) => `<tr><td>${escapeHtml(course.name)} (${escapeHtml(course.code)})</td><td>${escapeHtml(course.department)}</td><td>${escapeHtml(course.subjects.join(", ") || "—")}</td></tr>`)) : empty("No course records are available.")}</div>
      <div class="panel"><h2 class="section-title">Class timetable</h2>${result.timetable.length ? table(["Day", "Period", "Time", "Course / section", "Subject", "Faculty"], result.timetable.map((item) => `<tr><td>${["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"][item.day_of_week]}</td><td>${escapeHtml(item.period)}</td><td>${escapeHtml(item.starts_at)}–${escapeHtml(item.ends_at)}</td><td>${escapeHtml(item.course_name)} / ${escapeHtml(item.section)}</td><td>${escapeHtml(item.subject_name)} (${escapeHtml(item.subject_code)})</td><td>${escapeHtml(item.faculty_name)}</td></tr>`)) : empty("No timetable entries are available.")}</div>
    </div>`;
  }

  async function renderFacultyDirectory() {
    if (!context.authenticated) {
      root.innerHTML = `${empty("Sign in to view the internal faculty directory.")}<p class="form-actions"><a class="button" href="/login">Sign in</a></p>`;
      return;
    }
    const result = await api("/api/faculty-directory");
    root.innerHTML = `<div class="stack"><p class="metadata">Internal directory for signed-in community members.</p>${result.faculty.length ? `<div class="card-grid">${result.faculty.map((person) => `<article class="card"><h2>${escapeHtml(person.full_name)}</h2><p>${escapeHtml(person.department)}</p><p><a href="mailto:${escapeHtml(person.email)}">${escapeHtml(person.email)}</a></p><p class="metadata">${escapeHtml(person.subjects.join(", ") || "Assigned subjects not listed")}</p></article>`).join("")}</div>` : empty("No faculty directory records are available.")}</div>`;
  }

  async function renderAssistant() {
    if (!requireRole(["Student", "Faculty", "Administrator"])) return;
    root.innerHTML = `<div class="stack">
      <div class="panel"><p>The assistant can only cite its configured sources. Its legacy information currently refers to BMSIT&amp;M and is not verified NEXORA information. Do not rely on it for NEXORA policies, fees, dates, or official records.</p></div>
      <div class="chat-window"><div class="chat-messages" id="chat-messages"><div class="chat-message assistant">Hello. Ask a question. I will clearly distinguish available BMSIT&amp;M source material from unverified NEXORA information.</div></div>
        <form id="chat-form" class="chat-form"><label class="sr-only" for="chat-input">Your question</label><input id="chat-input" maxlength="1000" placeholder="Ask a question…" required><button class="button" type="submit">Send</button></form>
      </div>
    </div>`;
    const history = [];
    const form = document.querySelector("#chat-form");
    const input = document.querySelector("#chat-input");
    const messages = document.querySelector("#chat-messages");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const question = input.value.trim();
      if (!question) return;
      history.push({ role: "user", content: question });
      const userBubble = document.createElement("div");
      userBubble.className = "chat-message user";
      userBubble.textContent = question;
      messages.append(userBubble);
      input.value = "";
      form.querySelector("button").disabled = true;
      try {
        const result = await api("/api/chat", {
          method: "POST", body: JSON.stringify({ messages: history.slice(-8) }),
        });
        history.push({ role: "assistant", content: result.answer });
        const bubble = document.createElement("div");
        bubble.className = "chat-message assistant";
        bubble.textContent = result.answer;
        if (result.sources?.length) {
          const sourceList = document.createElement("p");
          sourceList.className = "metadata";
          sourceList.textContent = "Sources: ";
          result.sources.forEach((source, index) => {
            const link = document.createElement("a");
            link.href = source.url;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = source.title;
            sourceList.append(link);
            if (index < result.sources.length - 1) sourceList.append(document.createTextNode(" · "));
          });
          bubble.append(sourceList);
        }
        messages.append(bubble);
      } catch (error) {
        history.pop();
        showStatus(error.message);
      } finally {
        form.querySelector("button").disabled = false;
        messages.scrollTop = messages.scrollHeight;
        input.focus();
      }
    });
  }

  async function renderAdmin() {
    if (!requireRole(["Administrator"])) return;
    root.innerHTML = `<div class="stack">
      <div class="card-grid" id="admin-metrics"></div>
      <div class="panel"><h2 class="section-title">Create a college record</h2>
        <div class="field"><label for="record-type">Record type</label><select id="record-type">
          <option value="students">Student</option><option value="faculty">Faculty member</option>
          <option value="administrators">Administrator account</option>
          <option value="courses">Course</option><option value="subjects">Subject</option>
          <option value="classes">Class / section</option><option value="assignments">Faculty assignment</option>
          <option value="enrollments">Student enrollment</option><option value="timetable">Timetable entry</option>
          <option value="notices">Notice</option><option value="events">Event</option>
          <option value="materials">Study material</option>
        </select></div>
        <form id="admin-record-form"><div id="admin-fields" class="form-grid"></div><div class="form-actions">${button("Create record")}</div></form>
      </div>
      <div class="panel"><h2 class="section-title">Records and account permissions</h2><div class="toolbar"><div class="field"><label for="admin-table">Select records</label><select id="admin-table"></select></div><button id="refresh-admin" type="button" class="button secondary">Refresh</button></div><div id="admin-records"></div><div id="admin-edit-container"></div></div>
    </div>`;
    let records = {};
    const type = document.querySelector("#record-type");
    const fields = document.querySelector("#admin-fields");
    const schema = {
      students: [["email","Institutional email","email"],["password","Initial password (12+ characters)","password"],["student_id","Student ID"],["full_name","Full name"],["department","Department"],["semester","Semester","number"],["enrollment_status","Enrollment status"]],
      faculty: [["email","Institutional email","email"],["password","Initial password (12+ characters)","password"],["faculty_id","Faculty ID"],["full_name","Full name"],["department","Department"]],
      administrators: [["email","Institutional email","email"],["password","Initial password (12+ characters)","password"]],
      courses: [["code","Course code"],["name","Course name"],["department","Department"]],
      subjects: [["code","Subject code"],["name","Subject name"],["course_id","Course","select","courses","id","code"],["semester","Semester","number"]],
      classes: [["course_id","Course","select","courses","id","code"],["subject_id","Subject","select","subjects","id","code"],["section","Section"],["semester","Semester","number"]],
      assignments: [["faculty_user_id","Faculty account","select","users","id","email","Faculty"],["class_id","Class","select","classes","id","id"],["subject_id","Subject","select","subjects","id","code"]],
      enrollments: [["student_user_id","Student account","select","users","id","email","Student"],["class_id","Class","select","classes","id","id"]],
      timetable: [["class_id","Class","select","classes","id","id"],["subject_id","Subject","select","subjects","id","code"],["faculty_user_id","Faculty account","select","users","id","email","Faculty"],["day_of_week","Day of week (0=Mon)","number"],["period","Period","number"],["starts_at","Start time (HH:MM)","time"],["ends_at","End time (HH:MM)","time"]],
      notices: [["title","Title"],["body","Notice text","textarea"],["published","Publish now","checkbox"]],
      events: [["title","Title"],["description","Description","textarea"],["starts_at","Start time (ISO 8601)"],["ends_at","End time (optional)"],["location","Location"],["published","Publish now","checkbox"]],
      materials: [["subject_id","Subject","select","subjects","id","code"],["title","Title"],["description","Description","textarea"],["url","Secure material URL (HTTPS)","url"],["published","Publish now","checkbox"]],
    };
    function renderFields() {
      fields.innerHTML = schema[type.value].map(([name,label,kind="text",collection,key,labelKey,filterRole]) => {
        const id = `record-${name}`;
        if (kind === "select") {
          const options = (records[collection] || []).filter((item) => !filterRole || item.role === filterRole)
            .map((item) => `<option value="${escapeHtml(item[key])}">${escapeHtml(item[labelKey])}</option>`).join("");
          return `<div class="field"><label for="${id}">${escapeHtml(label)}</label><select id="${id}" name="${name}" required>${options}</select></div>`;
        }
        if (kind === "checkbox") return `<div class="field"><label><input id="${id}" name="${name}" type="checkbox"> ${escapeHtml(label)}</label></div>`;
        if (kind === "textarea") return `<div class="field full"><label for="${id}">${escapeHtml(label)}</label><textarea id="${id}" name="${name}" maxlength="4000" ${name === "body" ? "required" : ""}></textarea></div>`;
        return `<div class="field"><label for="${id}">${escapeHtml(label)}</label><input id="${id}" name="${name}" type="${kind}" ${kind === "number" ? 'min="0" max="16"' : ""} maxlength="${kind === "number" || kind === "time" ? "" : "240"}" ${name === "ends_at" ? "" : "required"}></div>`;
      }).join("");
    }
    async function refreshRecords() {
      records = await api("/api/admin/records");
      document.querySelector("#admin-metrics").innerHTML = Object.entries(records)
        .map(([name, list]) => metric(name, list.length)).join("");
      const select = document.querySelector("#admin-table");
      const selected = select.value;
      select.innerHTML = Object.keys(records).map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("");
      if (records[selected]) select.value = selected;
      renderFields();
      renderRecordTable(select.value);
    }
    function renderRecordTable(name) {
      const rows = records[name] || [];
      if (!rows.length) {
        document.querySelector("#admin-records").innerHTML = empty("No records in this category.");
        document.querySelector("#admin-edit-container").replaceChildren();
        return;
      }
      const columns = Object.keys(rows[0]);
      const identifiers = {
        students: "student_id", faculty: "faculty_id", courses: "id",
        subjects: "id", classes: "id", timetable: "id", notices: "id",
        events: "id", materials: "id",
      };
      const editable = Object.hasOwn(identifiers, name);
      document.querySelector("#admin-records").innerHTML = table(
        columns.concat(name === "users" ? ["Account access"] : editable ? ["Actions"] : []),
        rows.map((record) => `<tr>${columns.map((column) => `<td>${escapeHtml(record[column])}</td>`).join("")}${name === "users" ? `<td><button class="button ${record.active ? "danger" : ""}" type="button" data-user-id="${escapeHtml(record.id)}" data-active="${record.active ? "false" : "true"}">${record.active ? "Deactivate" : "Reactivate"}</button></td>` : editable ? `<td><button class="button secondary" type="button" data-edit-type="${name}" data-edit-id="${escapeHtml(record[identifiers[name]])}">Edit</button></td>` : ""}</tr>`),
      ) + `<div id="record-edit-slot"></div>`;
      document.querySelectorAll("[data-user-id]").forEach((buttonEl) => {
        buttonEl.addEventListener("click", async () => {
          if (!window.confirm(`${buttonEl.dataset.active === "true" ? "Reactivate" : "Deactivate"} this account?`)) return;
          try {
            await api(`/api/admin/users/${encodeURIComponent(buttonEl.dataset.userId)}/active`, {
              method: "POST", body: JSON.stringify({ active: buttonEl.dataset.active === "true" }),
            });
            await refreshRecords();
            showStatus("Account permissions updated.", "success");
          } catch (error) { showStatus(error.message); }
        });
      });
      document.querySelectorAll("[data-edit-type]").forEach((buttonEl) => {
        buttonEl.addEventListener("click", () => {
          const record = rows.find((item) => String(item[identifiers[name]]) === buttonEl.dataset.editId);
          if (record) renderEditForm(name, buttonEl.dataset.editId, record);
        });
      });
    }
    function renderEditForm(name, identifier, record) {
      const editFields = {
        students: [["email","Email","email"],["full_name","Full name"],["department","Department"],["semester","Semester","number"],["enrollment_status","Enrollment status"]],
        faculty: [["email","Email","email"],["full_name","Full name"],["department","Department"]],
        courses: [["code","Course code"],["name","Course name"],["department","Department"]],
        subjects: [["code","Subject code"],["name","Subject name"],["semester","Semester","number"]],
        classes: [["section","Section"],["semester","Semester","number"]],
        timetable: [["day_of_week","Day (0=Mon)","number"],["period","Period","number"],["starts_at","Start time"],["ends_at","End time"]],
        notices: [["title","Title"],["body","Notice text","textarea"],["published","Published","checkbox"]],
        events: [["title","Title"],["description","Description","textarea"],["starts_at","Start time"],["ends_at","End time"],["location","Location"],["published","Published","checkbox"]],
        materials: [["title","Title"],["description","Description","textarea"],["url","Secure URL","url"],["published","Published","checkbox"]],
      };
      const fieldsMarkup = editFields[name].map(([key,label,kind="text"]) => {
        const id = `edit-${key}`;
        const value = record[key] ?? "";
        if (kind === "checkbox") return `<div class="field"><label><input id="${id}" name="${key}" type="checkbox" ${value ? "checked" : ""}> ${escapeHtml(label)}</label></div>`;
        if (kind === "textarea") return `<div class="field full"><label for="${id}">${escapeHtml(label)}</label><textarea id="${id}" name="${key}" maxlength="4000">${escapeHtml(value)}</textarea></div>`;
        return `<div class="field"><label for="${id}">${escapeHtml(label)}</label><input id="${id}" name="${key}" type="${kind}" value="${escapeHtml(value)}" ${kind === "number" ? 'min="0" max="16"' : ""} required></div>`;
      }).join("");
      const slot = document.querySelector("#record-edit-slot");
      slot.innerHTML = `<form id="edit-record-form" class="form-card"><h3>Edit ${escapeHtml(name)} record</h3><div class="form-grid">${fieldsMarkup}</div><div class="form-actions"><button class="button" type="submit">Save changes</button><button class="button secondary" type="button" id="cancel-edit">Cancel</button></div></form>`;
      document.querySelector("#cancel-edit").addEventListener("click", () => slot.replaceChildren());
      document.querySelector("#edit-record-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        if (!form.reportValidity()) return;
        const recordData = {};
        new FormData(form).forEach((value, key) => { recordData[key] = value; });
        form.querySelectorAll('input[type="checkbox"]').forEach((input) => { recordData[input.name] = input.checked; });
        form.querySelectorAll('input[type="number"]').forEach((input) => { recordData[input.name] = Number(input.value); });
        const saveButton = form.querySelector('button[type="submit"]');
        saveButton.disabled = true;
        try {
          await api(`/api/admin/records/${encodeURIComponent(name)}/${encodeURIComponent(identifier)}`, {
            method: "POST", body: JSON.stringify({ record: recordData }),
          });
          slot.replaceChildren();
          await refreshRecords();
          showStatus("Record updated.", "success");
        } catch (error) {
          showStatus(error.message);
          saveButton.disabled = false;
        }
      });
    }
    type.addEventListener("change", renderFields);
    document.querySelector("#admin-table").addEventListener("change", (event) => renderRecordTable(event.target.value));
    document.querySelector("#refresh-admin").addEventListener("click", () => refreshRecords().catch((error) => showStatus(error.message)));
    document.querySelector("#admin-record-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      if (!form.reportValidity()) return;
      const record = {};
      new FormData(form).forEach((value, key) => { record[key] = value; });
      form.querySelectorAll('input[type="checkbox"]').forEach((input) => { record[input.name] = input.checked; });
      form.querySelectorAll('input[type="number"]').forEach((input) => { record[input.name] = Number(input.value); });
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        await api("/api/admin/records", { method: "POST", body: JSON.stringify({ type: type.value, record }) });
        form.reset();
        await refreshRecords();
        showStatus("Record created.", "success");
      } catch (error) { showStatus(error.message); }
      finally { submit.disabled = false; }
    });
    await refreshRecords();
  }

  function renderStatic() {
    const copy = {
      "/admissions": "Admissions requirements, application dates, fees, and processes must come from an approved NEXORA source. No official admissions content has been provided.",
      "/placements": "No verified placement outcomes, employer partnerships, or statistics have been provided. No achievements or figures are displayed.",
    };
    root.innerHTML = `${noVerifiedContent(copy[pagePath] || "Official NEXORA information has not been connected.")}<div class="form-actions"><a class="button" href="/assistant">Ask the College Assistant</a><a class="button secondary" href="/">Return home</a></div>`;
  }

  const renderers = {
    "/login": renderLogin,
    "/student-dashboard": renderStudentDashboard,
    "/faculty-dashboard": renderFacultyDashboard,
    "/attendance": async () => context.user?.role === "Student" ? renderStudentAttendance()
      : context.user?.role === "Faculty" ? renderFacultyAttendance()
        : context.user?.role === "Administrator" ? (requireRole(["Administrator"]), root.innerHTML = empty("Administrators can review attendance records using the administrative data tools.")) : (requireRole(["Student", "Faculty", "Administrator"]), undefined),
    "/academics": renderAcademics,
    "/events": renderEvents,
    "/notices": renderNotices,
    "/study-materials": renderMaterials,
    "/placements": renderStatic,
    "/admissions": renderStatic,
    "/faculty-directory": renderFacultyDirectory,
    "/assistant": renderAssistant,
    "/admin": renderAdmin,
  };

  document.querySelector("#nav-toggle").addEventListener("click", (event) => {
    const nav = document.querySelector("#primary-nav");
    const open = nav.classList.toggle("open");
    event.currentTarget.setAttribute("aria-expanded", String(open));
  });

  loadContext()
    .then(() => (renderers[pagePath] || renderStatic)())
    .catch((error) => {
      root.innerHTML = empty(error.message || "The page could not be loaded.");
      showStatus(error.message || "The page could not be loaded.");
    });
})();
