use actix_web::HttpResponse;

use super::email::escape_html;

pub(crate) fn render_message_page(title: &str, headline: &str, detail: &str) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_shell(
            title,
            "",
            &format!(
                "<section class=\"panel single\"><h2>{}</h2><p>{}</p></section>",
                escape_html(headline),
                escape_html(detail),
            ),
            "",
        ))
}

pub(crate) fn render_password_reset_page(auth_base: &str, token: Option<&str>) -> String {
    let body = if let Some(token) = token.filter(|token| !token.trim().is_empty()) {
        format!(
            "<section class=\"panel\"><h2>Choose A New Password</h2><form id=\"reset-form\"><input type=\"hidden\" id=\"reset-token\" value=\"{}\"><label>New password</label><input id=\"new-password\" type=\"password\" autocomplete=\"new-password\" required><button type=\"submit\">Reset password</button></form><p id=\"reset-result\" class=\"muted\"></p></section>",
            escape_html(token),
        )
    } else {
        "<section class=\"panel\"><h2>Request Password Reset</h2><form id=\"reset-request-form\"><label>Email address</label><input id=\"reset-email\" type=\"email\" autocomplete=\"email\" required><button type=\"submit\">Send reset link</button></form><p id=\"reset-result\" class=\"muted\"></p></section>".to_owned()
    };
    let script = format!(
        "const authBase = {auth_base:?};\n\
         const token = document.getElementById('reset-token');\n\
         async function submitJson(path, payload) {{\n\
             const response = await fetch(`${{authBase}}/${{path}}`, {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify(payload), credentials: 'include' }});\n\
             if (response.ok) return {{ ok: true }};\n\
             let detail = 'Request failed';\n\
             try {{ const body = await response.json(); detail = body.message || detail; }} catch {{}}\n\
             return {{ ok: false, detail }};\n\
         }}\n\
         const result = document.getElementById('reset-result');\n\
         document.getElementById('reset-request-form')?.addEventListener('submit', async (event) => {{\n\
             event.preventDefault();\n\
             const email = document.getElementById('reset-email').value.trim();\n\
             const outcome = await submitJson('password-reset/request', {{ email }});\n\
             result.textContent = outcome.ok ? 'If that account exists, a reset link has been sent.' : outcome.detail;\n\
         }});\n\
         document.getElementById('reset-form')?.addEventListener('submit', async (event) => {{\n\
             event.preventDefault();\n\
             const newPassword = document.getElementById('new-password').value;\n\
             const outcome = await submitJson('password-reset/confirm', {{ token: token.value, new_password: newPassword }});\n\
             result.textContent = outcome.ok ? 'Password updated. Return to the app and sign in.' : outcome.detail;\n\
         }});"
    );
    render_shell(
        "Password Reset",
        "Built-in account recovery",
        &body,
        &script,
    )
}

pub(crate) fn render_account_portal_page(
    title: &str,
    auth_base: &str,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> String {
    let body = r#"
        <section class="panel wide">
            <p class="kicker">Account Portal</p>
            <h2>Account Portal</h2>
            <p class="muted">Review your live account record, password, and verification state without leaving the app.</p>
            <div id="account-status" class="status-note info">Loading account…</div>
            <div id="account-summary" class="summary-grid">
                <article class="stat"><span class="stat-label">Email</span><strong>-</strong></article>
                <article class="stat"><span class="stat-label">Role</span><strong>-</strong></article>
                <article class="stat"><span class="stat-label">Verification</span><strong>-</strong></article>
            </div>
            <div class="toolbar">
                <label class="wide-field">
                    <span>Optional bearer token</span>
                    <input id="bearer-token" type="text" placeholder="Paste a bearer token if you are not using cookies">
                </label>
                <div class="actions">
                    <button id="refresh-account" type="button">Refresh account</button>
                    <button id="logout-button" type="button" class="secondary">Log out</button>
                </div>
            </div>
            <pre id="account-state">Loading account…</pre>
        </section>
        <section class="panel">
            <h2>Change password</h2>
            <form id="change-password-form">
                <label>
                    <span>Current password</span>
                    <input id="current-password" type="password" autocomplete="current-password" required>
                </label>
                <label>
                    <span>New password</span>
                    <input id="next-password" type="password" autocomplete="new-password" required>
                </label>
                <button type="submit">Update password</button>
            </form>
            <p id="password-result" class="muted"></p>
        </section>
        <section class="panel">
            <h2>Email verification</h2>
            <p class="muted">If the account is still pending verification, request a fresh verification link.</p>
            <div class="actions">
                <button id="resend-verification" type="button">Send verification email</button>
                <a class="text-link" id="password-reset-link" href="/auth/password-reset">Open password reset page</a>
            </div>
            <p id="verification-result" class="muted"></p>
        </section>
    "#;
    let script_template = r#"
const authBase = __AUTH_BASE__;
const csrfCookieName = __CSRF_COOKIE_NAME__;
const csrfHeaderName = __CSRF_HEADER_NAME__;
const accountStateEl = document.getElementById('account-state');
const accountSummaryEl = document.getElementById('account-summary');
const accountStatusEl = document.getElementById('account-status');
document.getElementById('password-reset-link').href = `${authBase}/password-reset`;

function bearerToken() {
  return document.getElementById('bearer-token').value.trim();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function csrfToken() {
  const escaped = csrfCookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = document.cookie.match(new RegExp(`(?:^|; )${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

async function responseMessage(response, fallback = 'Request failed') {
  const text = await response.text();
  if (!text) return fallback;
  try {
    const payload = JSON.parse(text);
    return payload.message || payload.code || fallback;
  } catch {
    return text;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = bearerToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const method = (options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = csrfToken();
    if (csrf) {
      headers.set(csrfHeaderName, csrf);
    }
  }
  return fetch(`${authBase}/${path}`, { ...options, headers, credentials: 'include' });
}

function setAccountStatus(message, kind = 'info') {
  accountStatusEl.textContent = message;
  accountStatusEl.className = `status-note ${kind}`;
}

function renderAccountSummary(account) {
  const verified = account?.email_verified ? 'Verified' : 'Pending verification';
  accountSummaryEl.innerHTML = `
    <article class="stat"><span class="stat-label">Email</span><strong>${escapeHtml(account?.email || '-')}</strong></article>
    <article class="stat"><span class="stat-label">Role</span><strong>${escapeHtml(account?.role || '-')}</strong></article>
    <article class="stat"><span class="stat-label">Verification</span><strong>${escapeHtml(verified)}</strong></article>
  `;
}

async function refreshAccount(showSuccess = false) {
  const response = await api('account');
  if (!response.ok) {
    accountStateEl.textContent = await responseMessage(response);
    renderAccountSummary(null);
    setAccountStatus('Could not load account details.', 'error');
    return;
  }
  const payload = await response.json();
  accountStateEl.textContent = JSON.stringify(payload, null, 2);
  renderAccountSummary(payload);
  if (showSuccess) {
    setAccountStatus('Account details refreshed.', 'success');
  } else {
    setAccountStatus('Account details loaded.', 'success');
  }
}

document.getElementById('refresh-account').addEventListener('click', () => {
  refreshAccount(true).catch((error) => {
    setAccountStatus(error.message || 'Could not refresh account.', 'error');
  });
});

document.getElementById('change-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = {
    current_password: document.getElementById('current-password').value,
    new_password: document.getElementById('next-password').value,
  };
  const response = await api('account/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  document.getElementById('password-result').textContent = response.ok
    ? 'Password updated successfully.'
    : await responseMessage(response);
});

document.getElementById('resend-verification').addEventListener('click', async () => {
  const response = await api('account/verification', { method: 'POST' });
  document.getElementById('verification-result').textContent = response.ok
    ? 'Verification email sent.'
    : await responseMessage(response);
});

document.getElementById('logout-button').addEventListener('click', async () => {
  const response = await api('logout', { method: 'POST' });
  if (response.ok) {
    accountStateEl.textContent = 'Logged out.';
    renderAccountSummary(null);
    setAccountStatus('Session cleared.', 'success');
    document.getElementById('verification-result').textContent = 'Logged out.';
    return;
  }
  document.getElementById('verification-result').textContent = await responseMessage(response);
});

refreshAccount(false).catch((error) => {
  setAccountStatus(error.message || 'Could not load account.', 'error');
});
"#;
    let script = script_template
        .replace("__AUTH_BASE__", &format!("{auth_base:?}"))
        .replace("__CSRF_COOKIE_NAME__", &format!("{csrf_cookie_name:?}"))
        .replace("__CSRF_HEADER_NAME__", &format!("{csrf_header_name:?}"));
    render_shell(title, "Built-in account management", body, &script)
}

pub(crate) fn render_admin_dashboard_page(
    title: &str,
    auth_base: &str,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> String {
    let body = r#"
        <section class="panel wide">
            <p class="kicker">Admin Dashboard</p>
            <h2>Admin Dashboard</h2>
            <p class="muted">Create accounts, update roles, resend verification, trigger recovery, and remove access from one place.</p>
            <div id="admin-status" class="status-note info">Loading user directory…</div>
            <form id="admin-search-form" class="toolbar">
                <label class="wide-field">
                    <span>Optional bearer token</span>
                    <input id="bearer-token" type="text" placeholder="Paste a bearer token if you are not using cookies">
                </label>
                <label class="wide-field">
                    <span>Search by email</span>
                    <input id="user-search" type="search" placeholder="jane@example.com">
                </label>
                <div class="actions">
                    <button id="load-users" type="submit">Refresh users</button>
                </div>
            </form>
        </section>
        <section class="panel">
            <h2>Create user</h2>
            <form id="create-user-form">
                <label>
                    <span>Email</span>
                    <input id="create-user-email" type="email" autocomplete="email" required>
                </label>
                <label>
                    <span>Initial password</span>
                    <input id="create-user-password" type="password" autocomplete="new-password" required>
                </label>
                <label>
                    <span>Role</span>
                    <input id="create-user-role" type="text" value="user" required>
                </label>
                <label>
                    <span>Verification state</span>
                    <select id="create-user-verified">
                        <option value="false">Pending verification</option>
                        <option value="true">Verified immediately</option>
                    </select>
                </label>
                <label>
                    <span>Verification email</span>
                    <select id="create-user-send-verification">
                        <option value="true">Send verification email</option>
                        <option value="false">Do not send</option>
                    </select>
                </label>
                <button type="submit">Create user</button>
            </form>
            <p id="create-user-result" class="muted"></p>
        </section>
        <section class="panel wide">
            <div class="section-head">
                <div>
                    <h2>User directory</h2>
                    <p id="admin-summary" class="muted">Loading users…</p>
                </div>
            </div>
            <div id="user-list" class="user-list"></div>
        </section>
    "#;
    let script_template = r#"
const authBase = __AUTH_BASE__;
const csrfCookieName = __CSRF_COOKIE_NAME__;
const csrfHeaderName = __CSRF_HEADER_NAME__;
const userListEl = document.getElementById('user-list');
const adminSummaryEl = document.getElementById('admin-summary');
const adminStatusEl = document.getElementById('admin-status');
let currentAccount = null;
let users = [];

function bearerToken() {
  return document.getElementById('bearer-token').value.trim();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll('`', '&#96;');
}

function csrfToken() {
  const escaped = csrfCookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = document.cookie.match(new RegExp(`(?:^|; )${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

async function responseMessage(response, fallback = 'Request failed') {
  const text = await response.text();
  if (!text) return fallback;
  try {
    const payload = JSON.parse(text);
    return payload.message || payload.code || fallback;
  } catch {
    return text;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = bearerToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const method = (options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = csrfToken();
    if (csrf) {
      headers.set(csrfHeaderName, csrf);
    }
  }
  return fetch(`${authBase}/${path}`, { ...options, headers, credentials: 'include' });
}

function setAdminStatus(message, kind = 'info') {
  adminStatusEl.textContent = message;
  adminStatusEl.className = `status-note ${kind}`;
}

async function loadCurrentAccount() {
  const response = await api('account');
  if (!response.ok) {
    throw new Error(await responseMessage(response, 'Could not load admin account'));
  }
  currentAccount = await response.json();
}

function renderUsers() {
  if (users.length === 0) {
    userListEl.innerHTML = '<article class="user-card"><p class="muted">No users match the current filter.</p></article>';
    adminSummaryEl.textContent = 'No matching users.';
    return;
  }

  adminSummaryEl.textContent = `${users.length} user${users.length === 1 ? '' : 's'} loaded.`;
  userListEl.innerHTML = users.map((item) => {
    const verified = item.email_verified ? 'true' : 'false';
    const verifiedLabel = item.email_verified ? 'Verified' : 'Pending verification';
    const disableDelete = currentAccount && currentAccount.id === item.id;
    const claims = item.claims && Object.keys(item.claims).length > 0
      ? `<details><summary>Claims</summary><pre>${escapeHtml(JSON.stringify(item.claims, null, 2))}</pre></details>`
      : '';
    return `
      <article class="user-card">
        <header class="card-head">
          <div>
            <strong>${escapeHtml(item.email)}</strong>
            <p class="muted">User #${escapeHtml(item.id)} · ${escapeHtml(item.created_at || 'created timestamp unavailable')}</p>
          </div>
          <span class="badge ${item.email_verified ? 'success' : 'warning'}">${escapeHtml(verifiedLabel)}</span>
        </header>
        <div class="summary-grid compact">
          <article class="stat"><span class="stat-label">Role</span><strong>${escapeHtml(item.role)}</strong></article>
          <article class="stat"><span class="stat-label">Updated</span><strong>${escapeHtml(item.updated_at || '-')}</strong></article>
          <article class="stat"><span class="stat-label">Verification</span><strong>${escapeHtml(item.email_verified_at || 'Not verified')}</strong></article>
        </div>
        <form class="inline-form" data-user-id="${escapeAttribute(item.id)}">
          <label>
            <span>Role</span>
            <input id="user-role-${escapeAttribute(item.id)}" type="text" value="${escapeAttribute(item.role)}">
          </label>
          <label>
            <span>Verification state</span>
            <select id="user-verified-${escapeAttribute(item.id)}">
              <option value="false"${verified === 'false' ? ' selected' : ''}>Pending verification</option>
              <option value="true"${verified === 'true' ? ' selected' : ''}>Verified</option>
            </select>
          </label>
        </form>
        <div class="actions">
          <button data-action="save" data-id="${escapeAttribute(item.id)}" type="button">Save changes</button>
          <button data-action="verify" data-id="${escapeAttribute(item.id)}" type="button" class="secondary">Resend verification</button>
          <button data-action="reset" data-id="${escapeAttribute(item.id)}" data-email="${escapeAttribute(item.email)}" type="button" class="secondary">Send reset email</button>
          <button data-action="delete" data-id="${escapeAttribute(item.id)}" type="button" class="danger"${disableDelete ? ' disabled' : ''}>Delete user</button>
        </div>
        ${claims}
      </article>
    `;
  }).join('');
}

async function loadUsers() {
  const email = document.getElementById('user-search').value.trim();
  const params = new URLSearchParams();
  if (email) {
    params.set('email', email);
  }
  const suffix = params.toString() ? `?${params.toString()}` : '';
  const response = await api(`admin/users${suffix}`);
  if (!response.ok) {
    throw new Error(await responseMessage(response, 'Could not load users'));
  }
  const payload = await response.json();
  users = payload.items || [];
  renderUsers();
  setAdminStatus('User directory refreshed.', 'success');
}

document.getElementById('admin-search-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await loadUsers();
  } catch (error) {
    setAdminStatus(error.message || 'Could not load users.', 'error');
  }
});

document.getElementById('create-user-verified').addEventListener('change', (event) => {
  if (event.target.value === 'true') {
    document.getElementById('create-user-send-verification').value = 'false';
  }
});

document.getElementById('create-user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const emailVerified = document.getElementById('create-user-verified').value === 'true';
  const payload = {
    email: document.getElementById('create-user-email').value.trim(),
    password: document.getElementById('create-user-password').value,
    role: document.getElementById('create-user-role').value.trim(),
    email_verified: emailVerified,
    send_verification_email: !emailVerified && document.getElementById('create-user-send-verification').value === 'true',
  };
  const response = await api('admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const resultEl = document.getElementById('create-user-result');
  if (!response.ok) {
    resultEl.textContent = await responseMessage(response, 'Could not create user');
    return;
  }
  const payloadBody = await response.json();
  resultEl.textContent = `Created ${payloadBody.email}.`;
  document.getElementById('create-user-form').reset();
  document.getElementById('create-user-role').value = 'user';
  document.getElementById('create-user-verified').value = 'false';
  document.getElementById('create-user-send-verification').value = 'true';
  await loadUsers();
});

userListEl.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) {
    return;
  }
  const id = button.dataset.id;
  try {
    if (button.dataset.action === 'save') {
      const role = document.getElementById(`user-role-${id}`).value.trim();
      const emailVerified = document.getElementById(`user-verified-${id}`).value === 'true';
      const response = await api(`admin/users/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role, email_verified: emailVerified }),
      });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not update user'));
      }
      await loadUsers();
      return;
    }

    if (button.dataset.action === 'verify') {
      const response = await api(`admin/users/${id}/verification`, { method: 'POST' });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not send verification email'));
      }
      setAdminStatus('Verification email queued.', 'success');
      return;
    }

    if (button.dataset.action === 'reset') {
      const response = await api('password-reset/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: button.dataset.email }),
      });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not send password reset email'));
      }
      setAdminStatus('Password reset email queued.', 'success');
      return;
    }

    if (button.dataset.action === 'delete') {
      if (!window.confirm('Delete this user and revoke built-in auth access?')) {
        return;
      }
      const response = await api(`admin/users/${id}`, { method: 'DELETE' });
      if (!response.ok) {
        throw new Error(await responseMessage(response, 'Could not delete user'));
      }
      await loadUsers();
      setAdminStatus('User deleted.', 'success');
    }
  } catch (error) {
    setAdminStatus(error.message || 'Admin action failed.', 'error');
  }
});

Promise.all([loadCurrentAccount(), loadUsers()]).catch((error) => {
  setAdminStatus(error.message || 'Could not load admin dashboard.', 'error');
});
"#;
    let script = script_template
        .replace("__AUTH_BASE__", &format!("{auth_base:?}"))
        .replace("__CSRF_COOKIE_NAME__", &format!("{csrf_cookie_name:?}"))
        .replace("__CSRF_HEADER_NAME__", &format!("{csrf_header_name:?}"));
    render_shell(title, "Built-in admin account management", body, &script)
}

pub(crate) fn render_shell(title: &str, subtitle: &str, body: &str, script: &str) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><style>:root{{--bg:#f3f5f8;--surface:#ffffff;--surface-soft:#f7f9fc;--ink:#15202b;--muted:#5b6774;--border:#d9e1ea;--accent:#1d4ed8;--accent-strong:#163fbc;--accent-soft:rgba(29,78,216,.1);--danger:#b42318;--danger-soft:rgba(180,35,24,.08);--success-soft:rgba(22,163,74,.1);--warning-soft:rgba(217,119,6,.12);--shadow:0 28px 80px rgba(15,23,42,.08);}}*{{box-sizing:border-box}}body{{margin:0;font-family:"SF Pro Text","Segoe UI",ui-sans-serif,system-ui,sans-serif;color:var(--ink);background:linear-gradient(180deg,#f9fbfd 0%,var(--bg) 100%);min-height:100vh}}body::before{{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at top left,rgba(29,78,216,.08),transparent 34%),radial-gradient(circle at top right,rgba(15,23,42,.06),transparent 28%)}}main{{position:relative;max-width:1180px;margin:0 auto;padding:40px 20px 64px}}header.hero{{display:grid;gap:10px;margin-bottom:24px}}header.hero h1{{margin:0;font-size:clamp(2.25rem,5vw,3.8rem);letter-spacing:-0.05em;font-family:"Iowan Old Style","Palatino Linotype","Book Antiqua",ui-serif,serif}}header.hero p{{margin:0;color:var(--muted);max-width:62ch;line-height:1.65}}.kicker{{margin:0;color:var(--accent);font-size:.82rem;font-weight:700;letter-spacing:.18em;text-transform:uppercase}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}}.wide{{grid-column:1 / -1}}section.panel{{background:linear-gradient(180deg,var(--surface),var(--surface-soft));border:1px solid var(--border);border-radius:28px;padding:24px;box-shadow:var(--shadow)}}section.panel h2{{margin:0 0 8px;font-size:1.45rem;letter-spacing:-.03em}}.section-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}label{{display:grid;gap:6px;font-size:.92rem;font-weight:600}}input,select,textarea,button{{font:inherit}}input,select,textarea{{width:100%;padding:12px 14px;border-radius:16px;border:1px solid var(--border);background:#fff;color:var(--ink)}}textarea{{min-height:132px;resize:vertical}}button{{padding:12px 16px;border:none;border-radius:999px;background:linear-gradient(135deg,var(--accent),var(--accent-strong));color:#fff;font-weight:700;cursor:pointer;box-shadow:0 12px 28px rgba(29,78,216,.22)}}button.secondary{{background:#e8eefc;color:var(--accent-strong);box-shadow:none}}button.danger{{background:linear-gradient(135deg,#d13a2e,var(--danger));box-shadow:0 12px 28px rgba(180,35,24,.18)}}button:disabled{{opacity:.55;cursor:not-allowed;box-shadow:none}}button:hover:not(:disabled){{transform:translateY(-1px)}}form{{display:grid;gap:14px}}pre{{margin:0;padding:14px 16px;border-radius:18px;background:#0f172a;color:#e2e8f0;overflow:auto;min-height:120px}}.muted{{color:var(--muted)}}.toolbar{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto;gap:14px;align-items:end}}.wide-field{{grid-column:auto}}.actions{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}}.summary-grid.compact{{margin:12px 0 0}}.stat{{padding:16px;border:1px solid var(--border);border-radius:20px;background:#fff}}.stat-label{{display:block;margin-bottom:8px;color:var(--muted);font-size:.88rem}}.badge{{display:inline-flex;align-items:center;justify-content:center;padding:8px 12px;border-radius:999px;background:var(--accent-soft);color:var(--accent-strong);font-size:.82rem;font-weight:700}}.badge.success{{background:var(--success-soft);color:#166534}}.badge.warning{{background:var(--warning-soft);color:#9a5b00}}.status-note{{margin:0;padding:14px 16px;border-radius:18px;border:1px solid var(--border);background:#fff}}.status-note.info{{background:#eef4ff;border-color:#d3e1ff;color:#173f8a}}.status-note.success{{background:#ecfdf3;border-color:#b7ebca;color:#166534}}.status-note.error{{background:#fff1f2;border-color:#fecdd3;color:#9f1239}}.user-list{{display:grid;gap:14px}}.user-card{{border:1px solid var(--border);border-radius:22px;padding:18px;background:#fff}}.card-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:8px}}.inline-form{{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));align-items:end;margin-top:12px}}.text-link{{color:var(--accent-strong);font-weight:600;text-decoration:none}}summary{{cursor:pointer;color:var(--muted);font-weight:600}}details pre{{margin-top:10px;min-height:0}}@media (max-width:800px){{main{{padding:28px 16px 48px}}.toolbar{{grid-template-columns:1fr}}.section-head{{flex-direction:column}}.card-head{{flex-direction:column;align-items:flex-start}}}}</style></head><body><main><header class="hero"><p class="kicker">Built-in Auth</p><h1>{}</h1><p>{}</p></header><div class="grid">{}</div></main><script>{}</script></body></html>"#,
        escape_html(title),
        escape_html(title),
        escape_html(subtitle),
        body,
        script,
    )
}
