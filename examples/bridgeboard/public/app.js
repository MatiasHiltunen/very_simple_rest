const API_BASE = "/api";
const CSRF_COOKIE_NAME = "vsr_csrf";

const DEMO_DATA = {
  organizations: [
    {
      slug: "nordic-mobility-lab",
      name: "Nordic Mobility Lab",
      country: "Finland",
      city: "Oulu",
      website_url: "https://mobility.example",
      contact_email: "partnerships@nordic-mobility.example",
      collaboration_stage: "Pilot-ready",
      summary:
        "Builds applied mobility pilots with universities and vocational institutes around inclusive transit, data-sharing, and service design.",
    },
    {
      slug: "tallinn-robotics-cluster",
      name: "Tallinn Robotics Cluster",
      country: "Estonia",
      city: "Tallinn",
      website_url: "https://robotics.example",
      contact_email: "hello@tallinn-robotics.example",
      collaboration_stage: "Consortium scouting",
      summary:
        "Connects port logistics companies, engineering schools, and robotics teams to scope thesis-ready experiments with short industrial feedback cycles.",
    },
    {
      slug: "circular-materials-network",
      name: "Circular Materials Network",
      country: "Germany",
      city: "Hamburg",
      website_url: "https://circular.example",
      contact_email: "bridge@circular-materials.example",
      collaboration_stage: "Open call",
      summary:
        "Coordinates cross-border projects on circular manufacturing, lab reuse, and material traceability between campuses, SMEs, and regional industry clusters.",
    },
  ],
  interests: [
    {
      organization_slug: "nordic-mobility-lab",
      title: "Accessibility data exchange pilot",
      work_mode: "Hybrid sprint",
      desired_start_on: "2026-09-01",
      summary:
        "Looking for a thesis partnership on how campuses and public transport operators can share accessibility observations without losing local context.",
    },
    {
      organization_slug: "tallinn-robotics-cluster",
      title: "Port-side robotics validation",
      work_mode: "On-site residency",
      desired_start_on: "2026-10-05",
      summary:
        "Seeking engineering teams to define thesis topics around safe robot navigation, operator trust, and mixed-reality maintenance workflows in maritime logistics.",
    },
    {
      organization_slug: "circular-materials-network",
      title: "SME materials traceability",
      work_mode: "Remote-first supervision",
      desired_start_on: "2026-11-15",
      summary:
        "Invites applied research groups to scope thesis work on low-friction traceability models that smaller manufacturing partners can actually adopt.",
    },
  ],
  thesisTopics: [
    {
      organization_slug: "nordic-mobility-lab",
      title: "Cross-border trust layer for apprenticeship mobility data",
      discipline: "Service design and data governance",
      location: "Oulu + remote",
      contact_email: "thesis@nordic-mobility.example",
      application_deadline: "2026-08-20",
      summary:
        "Frame a thesis that maps how education providers and mobility operators can share apprenticeship journey data while preserving consent, accessibility context, and usable feedback loops.",
    },
    {
      organization_slug: "tallinn-robotics-cluster",
      title: "Human-in-the-loop robotics for safer port operations",
      discipline: "Robotics and human factors",
      location: "Tallinn",
      contact_email: "mentor@tallinn-robotics.example",
      application_deadline: "2026-09-10",
      summary:
        "Design and test an evaluation model for human-supervised robotic movement around container yards, with a focus on operator confidence and scenario replay.",
    },
    {
      organization_slug: "circular-materials-network",
      title: "Re-use pathways for technical training batteries",
      discipline: "Circular economy and industrial systems",
      location: "Hamburg + remote",
      contact_email: "projects@circular-materials.example",
      application_deadline: "2026-10-01",
      summary:
        "Investigate how training labs, suppliers, and local recyclers can structure a battery re-use pipeline that is practical for vocational campuses and SMEs.",
    },
  ],
};

const state = {
  csrfToken: "",
  currentUser: null,
  account: null,
  organizations: [],
  topics: [],
  requests: [],
  interestCache: new Map(),
  expandedOrganizations: new Set(),
};

const elements = {
  statusBar: document.getElementById("statusBar"),
  organizationCount: document.getElementById("organizationCount"),
  topicCount: document.getElementById("topicCount"),
  requestCount: document.getElementById("requestCount"),
  authForm: document.getElementById("authForm"),
  registerBtn: document.getElementById("registerBtn"),
  loginBtn: document.getElementById("loginBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  resetLinkBtn: document.getElementById("resetLinkBtn"),
  resendVerificationBtn: document.getElementById("resendVerificationBtn"),
  refreshSessionBtn: document.getElementById("refreshSessionBtn"),
  emailInput: document.getElementById("emailInput"),
  passwordInput: document.getElementById("passwordInput"),
  sessionHeading: document.getElementById("sessionHeading"),
  sessionSummary: document.getElementById("sessionSummary"),
  sessionEmail: document.getElementById("sessionEmail"),
  sessionRole: document.getElementById("sessionRole"),
  sessionVerified: document.getElementById("sessionVerified"),
  adminLink: document.getElementById("adminLink"),
  portalLink: document.getElementById("portalLink"),
  searchForm: document.getElementById("searchForm"),
  clearFiltersBtn: document.getElementById("clearFiltersBtn"),
  orgSearchInput: document.getElementById("orgSearchInput"),
  countrySearchInput: document.getElementById("countrySearchInput"),
  interestSearchInput: document.getElementById("interestSearchInput"),
  topicSearchInput: document.getElementById("topicSearchInput"),
  organizationsGrid: document.getElementById("organizationsGrid"),
  topicsGrid: document.getElementById("topicsGrid"),
  requestForm: document.getElementById("requestForm"),
  requestOrganizationInput: document.getElementById("requestOrganizationInput"),
  requestTitleInput: document.getElementById("requestTitleInput"),
  requestPreferredDateInput: document.getElementById("requestPreferredDateInput"),
  requestMessageInput: document.getElementById("requestMessageInput"),
  requestsHeading: document.getElementById("requestsHeading"),
  requestsList: document.getElementById("requestsList"),
  adminStudio: document.getElementById("adminStudio"),
  loadDemoBtn: document.getElementById("loadDemoBtn"),
  organizationForm: document.getElementById("organizationForm"),
  organizationSlugInput: document.getElementById("organizationSlugInput"),
  organizationNameInput: document.getElementById("organizationNameInput"),
  organizationCountryInput: document.getElementById("organizationCountryInput"),
  organizationCityInput: document.getElementById("organizationCityInput"),
  organizationWebsiteInput: document.getElementById("organizationWebsiteInput"),
  organizationEmailInput: document.getElementById("organizationEmailInput"),
  organizationStageInput: document.getElementById("organizationStageInput"),
  organizationSummaryInput: document.getElementById("organizationSummaryInput"),
  interestForm: document.getElementById("interestForm"),
  interestOrganizationInput: document.getElementById("interestOrganizationInput"),
  interestTitleInput: document.getElementById("interestTitleInput"),
  interestWorkModeInput: document.getElementById("interestWorkModeInput"),
  interestStartInput: document.getElementById("interestStartInput"),
  interestSummaryInput: document.getElementById("interestSummaryInput"),
  topicForm: document.getElementById("topicForm"),
  topicOrganizationInput: document.getElementById("topicOrganizationInput"),
  topicTitleInput: document.getElementById("topicTitleInput"),
  topicDisciplineInput: document.getElementById("topicDisciplineInput"),
  topicLocationInput: document.getElementById("topicLocationInput"),
  topicEmailInput: document.getElementById("topicEmailInput"),
  topicDeadlineInput: document.getElementById("topicDeadlineInput"),
  topicSummaryInput: document.getElementById("topicSummaryInput"),
};

bindEvents();
initialize();

function bindEvents() {
  elements.authForm.addEventListener("submit", handleRegister);
  elements.loginBtn.addEventListener("click", loginUser);
  elements.logoutBtn.addEventListener("click", logoutUser);
  elements.resetLinkBtn.addEventListener("click", requestPasswordReset);
  elements.resendVerificationBtn.addEventListener("click", resendVerificationEmail);
  elements.refreshSessionBtn.addEventListener("click", refreshSession);
  elements.searchForm.addEventListener("submit", applyFilters);
  elements.clearFiltersBtn.addEventListener("click", clearFilters);
  elements.requestForm.addEventListener("submit", submitCollaborationRequest);
  elements.loadDemoBtn.addEventListener("click", loadDemoDataset);
  elements.organizationForm.addEventListener("submit", createOrganization);
  elements.interestForm.addEventListener("submit", createInterest);
  elements.topicForm.addEventListener("submit", createThesisTopic);
}

async function initialize() {
  syncCsrfToken();
  await Promise.all([loadOrganizations(), loadTopics(), refreshSession()]);
}

function setStatus(message, kind = "info") {
  elements.statusBar.textContent = message;
  elements.statusBar.className = `status ${kind}`;
}

function syncCounts() {
  elements.organizationCount.textContent = String(state.organizations.length);
  elements.topicCount.textContent = String(state.topics.length);
  elements.requestCount.textContent = String(state.requests.length);
}

function syncCsrfToken() {
  state.csrfToken = readCookie(CSRF_COOKIE_NAME) || state.csrfToken;
}

function requestNeedsCsrf(method) {
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes((method || "GET").toUpperCase());
}

async function apiFetch(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});

  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (requestNeedsCsrf(method) && state.csrfToken && !headers.has("x-csrf-token")) {
    headers.set("x-csrf-token", state.csrfToken);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    method,
    credentials: "same-origin",
    headers,
  });

  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (response.status !== 204) {
    payload = contentType.includes("application/json")
      ? await response.json()
      : await response.text();
  }

  syncCsrfToken();

  if (!response.ok) {
    const message = typeof payload === "string"
      ? payload || `HTTP ${response.status}`
      : payload?.message || payload?.code || `HTTP ${response.status}`;
    const error = new Error(message);
    error.code = payload?.code || null;
    throw error;
  }

  return payload;
}

async function handleRegister(event) {
  event.preventDefault();

  const email = elements.emailInput.value.trim();
  const password = elements.passwordInput.value;
  if (!email || !password) {
    setStatus("Email and password are required.", "error");
    return;
  }

  try {
    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setStatus(
      "Registration created. Verify the email before logging in. In local capture mode, open the newest file under VSR_AUTH_EMAIL_CAPTURE_DIR.",
      "success",
    );
  } catch (error) {
    setStatus(`Registration failed: ${error.message}`, "error");
  }
}

async function loginUser() {
  const email = elements.emailInput.value.trim();
  const password = elements.passwordInput.value;
  if (!email || !password) {
    setStatus("Email and password are required.", "error");
    return;
  }

  try {
    const data = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    state.csrfToken = data?.csrf_token || readCookie(CSRF_COOKIE_NAME) || "";
    await refreshSession();
    setStatus("Signed in. Your collaboration pipeline is ready.", "success");
  } catch (error) {
    setStatus(`Login failed: ${error.message}`, "error");
  }
}

async function logoutUser() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch (error) {
    setStatus(`Logout failed: ${error.message}`, "error");
    return;
  }

  clearSession();
  renderSession();
  renderRequests();
  setStatus("Logged out.", "success");
}

async function requestPasswordReset() {
  const email = elements.emailInput.value.trim();
  if (!email) {
    setStatus("Enter an email address first.", "error");
    return;
  }

  try {
    await apiFetch("/auth/password-reset/request", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
    setStatus(
      "If that account exists, a reset link has been sent. The built-in portal also supports the reset flow.",
      "success",
    );
  } catch (error) {
    setStatus(`Reset request failed: ${error.message}`, "error");
  }
}

async function resendVerificationEmail() {
  try {
    if (state.currentUser) {
      await apiFetch("/auth/account/verification", { method: "POST" });
    } else {
      const email = elements.emailInput.value.trim();
      if (!email) {
        setStatus("Enter an email address first.", "error");
        return;
      }
      await apiFetch("/auth/verification/resend", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
    }
    setStatus(
      "If the account is still unverified, a new verification link has been sent.",
      "success",
    );
  } catch (error) {
    setStatus(`Verification resend failed: ${error.message}`, "error");
  }
}

async function refreshSession() {
  syncCsrfToken();
  if (!state.csrfToken) {
    clearSession();
    renderSession();
    renderRequests();
    return;
  }

  try {
    const [currentUser, account] = await Promise.all([
      apiFetch("/auth/me"),
      apiFetch("/auth/account"),
    ]);
    state.currentUser = currentUser;
    state.account = account;
    await loadRequests();
  } catch (error) {
    clearSession();
    renderRequests();
    if (!String(error.message || "").includes("Missing token")) {
      setStatus(`Session refresh failed: ${error.message}`, "error");
    }
  }

  renderSession();
}

function clearSession() {
  state.csrfToken = "";
  state.currentUser = null;
  state.account = null;
  state.requests = [];
  syncCounts();
}

function renderSession() {
  const account = state.account;
  const isAdminUser = isAdmin();

  elements.adminLink.hidden = !isAdminUser;
  elements.portalLink.hidden = false;
  elements.adminStudio.hidden = !isAdminUser;

  if (!account) {
    elements.sessionHeading.textContent = "Not signed in";
    elements.sessionSummary.textContent =
      "Register with a verified email to submit collaboration requests and use the built-in account portal.";
    elements.sessionEmail.textContent = "-";
    elements.sessionRole.textContent = "-";
    elements.sessionVerified.textContent = "-";
    elements.requestsHeading.textContent = "Sign in to load your requests";
    updateRequestFormState();
    return;
  }

  const verifiedLabel = account.email_verified ? "Verified" : "Pending verification";
  elements.sessionHeading.textContent = account.email_verified
    ? `Signed in as ${account.email}`
    : `Signed in as ${account.email} (verification pending)`;
  elements.sessionSummary.textContent =
    "Use the account portal to change your password, resend verification, and review your account metadata.";
  elements.sessionEmail.textContent = account.email;
  elements.sessionRole.textContent = (account.roles || []).join(", ") || account.role || "user";
  elements.sessionVerified.textContent = verifiedLabel;
  elements.requestsHeading.textContent = isAdminUser
    ? "Admin pipeline review"
    : "Your collaboration requests";
  updateRequestFormState();
}

async function applyFilters(event) {
  event.preventDefault();
  state.interestCache.clear();
  state.expandedOrganizations.clear();
  await Promise.all([loadOrganizations(), loadTopics()]);
}

async function clearFilters() {
  elements.orgSearchInput.value = "";
  elements.countrySearchInput.value = "";
  elements.interestSearchInput.value = "";
  elements.topicSearchInput.value = "";
  state.interestCache.clear();
  state.expandedOrganizations.clear();
  await Promise.all([loadOrganizations(), loadTopics()]);
  setStatus("Filters cleared.", "success");
}

async function loadOrganizations() {
  const params = new URLSearchParams({
    limit: "24",
    sort: "name",
    order: "asc",
  });
  if (elements.orgSearchInput.value.trim()) {
    params.set("filter_name_contains", elements.orgSearchInput.value.trim());
  }
  if (elements.countrySearchInput.value.trim()) {
    params.set("filter_country_contains", elements.countrySearchInput.value.trim());
  }

  try {
    const response = await apiFetch(`/organization?${params.toString()}`);
    state.organizations = response?.items || [];
    syncOrganizationSelects();
    renderOrganizations();
    renderTopics();
    syncCounts();
  } catch (error) {
    elements.organizationsGrid.innerHTML = renderEmpty(
      `Could not load organizations: ${escapeHtml(error.message)}`,
    );
    setStatus(`Organization search failed: ${error.message}`, "error");
  }
}

async function loadTopics() {
  const params = new URLSearchParams({
    limit: "48",
    sort: "title",
    order: "asc",
  });
  if (elements.topicSearchInput.value.trim()) {
    params.set("filter_title_contains", elements.topicSearchInput.value.trim());
  }

  try {
    const response = await apiFetch(`/thesis_topic?${params.toString()}`);
    state.topics = response?.items || [];
    renderTopics();
    syncCounts();
  } catch (error) {
    elements.topicsGrid.innerHTML = renderEmpty(
      `Could not load thesis topics: ${escapeHtml(error.message)}`,
    );
    setStatus(`Topic search failed: ${error.message}`, "error");
  }
}

async function loadRequests() {
  if (!state.currentUser) {
    state.requests = [];
    syncCounts();
    return;
  }

  const params = new URLSearchParams({
    limit: "50",
    sort: "created_at",
    order: "desc",
  });

  try {
    const response = await apiFetch(`/collaboration_request?${params.toString()}`);
    state.requests = response?.items || [];
    renderRequests();
    syncCounts();
  } catch (error) {
    elements.requestsList.innerHTML = renderEmpty(
      `Could not load requests: ${escapeHtml(error.message)}`,
    );
    setStatus(`Request pipeline failed to load: ${error.message}`, "error");
  }
}

function renderOrganizations() {
  if (state.organizations.length === 0) {
    elements.organizationsGrid.innerHTML = renderEmpty(
      "No organizations match the current search.",
    );
    return;
  }

  elements.organizationsGrid.innerHTML = "";
  for (const organization of state.organizations) {
    const card = document.createElement("article");
    card.className = "org-card";

    const expanded = state.expandedOrganizations.has(organization.id);
    const cacheKey = interestCacheKey(organization.id);
    const interestState = state.interestCache.get(cacheKey);

    card.innerHTML = `
      <div class="eyebrow">Organization</div>
      <h3 class="org-title">${escapeHtml(organization.name)}</h3>
      <div class="org-meta">
        <span class="pill">${escapeHtml(organization.country)}</span>
        <span class="pill">${escapeHtml(organization.city)}</span>
        <span class="pill signal">${escapeHtml(organization.collaboration_stage)}</span>
      </div>
      <p class="card-subtitle">${escapeHtml(organization.summary)}</p>
      <p class="card-subtitle">
        <a class="website-link" href="${escapeAttribute(organization.website_url)}" target="_blank" rel="noreferrer">
          ${escapeHtml(organization.website_url)}
        </a>
      </p>
      <div class="button-row wrap">
        <button class="button secondary" type="button" data-action="interests">
          ${expanded ? "Hide interest signals" : "Show interest signals"}
        </button>
        <button class="button ghost anchor-button" type="button" data-action="request">
          Propose collaboration
        </button>
      </div>
      <div class="interest-list">
        ${expanded ? renderInterestState(interestState) : ""}
      </div>
    `;

    card.querySelector('[data-action="interests"]').addEventListener("click", async () => {
      if (expanded) {
        state.expandedOrganizations.delete(organization.id);
        renderOrganizations();
        return;
      }
      state.expandedOrganizations.add(organization.id);
      renderOrganizations();
      await loadOrganizationInterests(organization.id);
    });

    card.querySelector('[data-action="request"]').addEventListener("click", () => {
      focusRequestComposer(organization.id);
    });

    elements.organizationsGrid.appendChild(card);
  }
}

function renderInterestState(interestState) {
  if (!interestState || interestState.loading) {
    return renderEmpty("Loading interest signals...");
  }
  if (interestState.items.length === 0) {
    return renderEmpty("No interest signals match the current filter.");
  }
  return interestState.items
    .map(
      (interest) => `
        <article class="interest-card">
          <h4 class="interest-title">${escapeHtml(interest.title)}</h4>
          <div class="org-meta">
            <span class="pill">${escapeHtml(interest.work_mode)}</span>
            <span class="pill">${escapeHtml(formatDate(interest.desired_start_on) || "Flexible start")}</span>
          </div>
          <p class="card-subtitle">${escapeHtml(interest.summary)}</p>
        </article>
      `,
    )
    .join("");
}

async function loadOrganizationInterests(organizationId) {
  const cacheKey = interestCacheKey(organizationId);
  state.interestCache.set(cacheKey, { loading: true, items: [] });
  renderOrganizations();

  const params = new URLSearchParams({
    limit: "12",
    sort: "title",
    order: "asc",
  });
  if (elements.interestSearchInput.value.trim()) {
    params.set("filter_title_contains", elements.interestSearchInput.value.trim());
  }

  try {
    const response = await apiFetch(`/organization/${organizationId}/interest?${params.toString()}`);
    state.interestCache.set(cacheKey, {
      loading: false,
      items: response?.items || [],
    });
    renderOrganizations();
  } catch (error) {
    state.interestCache.set(cacheKey, {
      loading: false,
      items: [],
    });
    setStatus(`Interest lookup failed: ${error.message}`, "error");
    renderOrganizations();
  }
}

function renderTopics() {
  if (state.topics.length === 0) {
    elements.topicsGrid.innerHTML = renderEmpty("No thesis topics match the current search.");
    return;
  }

  elements.topicsGrid.innerHTML = "";
  for (const topic of state.topics) {
    const organization = organizationById(topic.organization_id);
    const card = document.createElement("article");
    card.className = "topic-card";
    card.innerHTML = `
      <div class="eyebrow">Thesis topic</div>
      <h3 class="topic-title">${escapeHtml(topic.title)}</h3>
      <div class="topic-meta">
        <span class="pill">${escapeHtml(topic.discipline)}</span>
        <span class="pill">${escapeHtml(topic.location)}</span>
        <span class="pill signal">${escapeHtml(formatDate(topic.application_deadline) || "Open")}</span>
      </div>
      <p class="card-subtitle">${escapeHtml(topic.summary)}</p>
      <p class="card-subtitle">
        Hosted by <strong>${escapeHtml(organization?.name || "Unknown organization")}</strong><br>
        Contact: ${escapeHtml(topic.contact_email)}
      </p>
    `;
    elements.topicsGrid.appendChild(card);
  }
}

async function submitCollaborationRequest(event) {
  event.preventDefault();
  if (!state.currentUser) {
    setStatus("Sign in before sending a collaboration request.", "error");
    return;
  }

  const payload = {
    organization_id: Number(elements.requestOrganizationInput.value),
    title: elements.requestTitleInput.value.trim(),
    message: elements.requestMessageInput.value.trim(),
    status: "submitted",
    preferred_start_on: elements.requestPreferredDateInput.value || null,
  };

  if (!payload.organization_id || !payload.title || !payload.message) {
    setStatus("Organization, title, and message are required.", "error");
    return;
  }

  try {
    await apiFetch("/collaboration_request", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    elements.requestForm.reset();
    updateRequestFormState();
    await loadRequests();
    setStatus("Collaboration request sent.", "success");
  } catch (error) {
    setStatus(`Could not send request: ${error.message}`, "error");
  }
}

function renderRequests() {
  if (!state.currentUser) {
    elements.requestsList.innerHTML = renderEmpty(
      "Sign in to manage your collaboration pipeline.",
    );
    syncCounts();
    return;
  }

  if (state.requests.length === 0) {
    elements.requestsList.innerHTML = renderEmpty(
      isAdmin()
        ? "No collaboration requests are in the admin pipeline yet."
        : "You have not submitted any collaboration requests yet.",
    );
    syncCounts();
    return;
  }

  elements.requestsList.innerHTML = "";
  for (const request of state.requests) {
    const card = document.createElement("article");
    card.className = "request-card";
    const organization = organizationById(request.organization_id);

    card.innerHTML = `
      <div class="eyebrow">Request</div>
      <h3 class="request-title">${escapeHtml(request.title)}</h3>
      <div class="request-meta">
        <span class="pill">${escapeHtml(organization?.name || "Unknown organization")}</span>
        <span class="pill">${escapeHtml(request.status)}</span>
        <span class="pill signal">${escapeHtml(formatDate(request.preferred_start_on) || "Flexible start")}</span>
      </div>
      <p class="card-subtitle">${escapeHtml(request.message)}</p>
      <p class="card-subtitle">Created ${escapeHtml(formatDateTime(request.created_at) || request.created_at || "-")}</p>
      <div class="request-actions">
        <button class="button ghost" type="button" data-action="delete">Delete</button>
        ${isAdmin() ? `
          <button class="button secondary" type="button" data-status="reviewing">Mark reviewing</button>
          <button class="button secondary" type="button" data-status="matched">Mark matched</button>
          <button class="button secondary" type="button" data-status="archived">Archive</button>
        ` : ""}
      </div>
    `;

    card.querySelector('[data-action="delete"]').addEventListener("click", async () => {
      await deleteRequest(request);
    });

    if (isAdmin()) {
      for (const button of card.querySelectorAll("[data-status]")) {
        button.addEventListener("click", async () => {
          await updateRequestStatus(request, button.dataset.status);
        });
      }
    }

    elements.requestsList.appendChild(card);
  }
}

async function updateRequestStatus(request, status) {
  try {
    await apiFetch(`/collaboration_request/${request.id}`, {
      method: "PUT",
      body: JSON.stringify({
        organization_id: request.organization_id,
        title: request.title,
        message: request.message,
        status,
        preferred_start_on: request.preferred_start_on || null,
      }),
    });
    await loadRequests();
    setStatus(`Request marked as ${status}.`, "success");
  } catch (error) {
    setStatus(`Could not update request: ${error.message}`, "error");
  }
}

async function deleteRequest(request) {
  try {
    await apiFetch(`/collaboration_request/${request.id}`, { method: "DELETE" });
    await loadRequests();
    setStatus("Request deleted.", "success");
  } catch (error) {
    setStatus(`Could not delete request: ${error.message}`, "error");
  }
}

async function loadDemoDataset() {
  if (!isAdmin()) {
    setStatus("Admin access is required to seed demo content.", "error");
    return;
  }

  try {
    const existingOrganizations = await apiFetch("/organization?limit=100&sort=name&order=asc");
    const bySlug = new Map((existingOrganizations?.items || []).map((item) => [item.slug, item]));

    for (const organization of DEMO_DATA.organizations) {
      if (!bySlug.has(organization.slug)) {
        await apiFetch("/organization", {
          method: "POST",
          body: JSON.stringify(organization),
        });
      }
    }

    const refreshedOrganizations = await apiFetch("/organization?limit=100&sort=name&order=asc");
    state.organizations = refreshedOrganizations?.items || [];
    syncOrganizationSelects();

    const slugToId = new Map(state.organizations.map((organization) => [organization.slug, organization.id]));
    const existingInterests = await apiFetch("/interest?limit=200&sort=title&order=asc");
    const existingInterestKeys = new Set(
      (existingInterests?.items || []).map((interest) => `${interest.organization_id}:${interest.title}`),
    );
    for (const interest of DEMO_DATA.interests) {
      const organizationId = slugToId.get(interest.organization_slug);
      const key = `${organizationId}:${interest.title}`;
      if (organizationId && !existingInterestKeys.has(key)) {
        await apiFetch("/interest", {
          method: "POST",
          body: JSON.stringify({
            organization_id: organizationId,
            title: interest.title,
            work_mode: interest.work_mode,
            summary: interest.summary,
            desired_start_on: interest.desired_start_on,
          }),
        });
      }
    }

    const existingTopics = await apiFetch("/thesis_topic?limit=200&sort=title&order=asc");
    const existingTopicKeys = new Set(
      (existingTopics?.items || []).map((topic) => `${topic.organization_id}:${topic.title}`),
    );
    for (const topic of DEMO_DATA.thesisTopics) {
      const organizationId = slugToId.get(topic.organization_slug);
      const key = `${organizationId}:${topic.title}`;
      if (organizationId && !existingTopicKeys.has(key)) {
        await apiFetch("/thesis_topic", {
          method: "POST",
          body: JSON.stringify({
            organization_id: organizationId,
            title: topic.title,
            discipline: topic.discipline,
            location: topic.location,
            contact_email: topic.contact_email,
            summary: topic.summary,
            application_deadline: topic.application_deadline,
          }),
        });
      }
    }

    state.interestCache.clear();
    await Promise.all([loadOrganizations(), loadTopics(), loadRequests()]);
    setStatus("Demo dataset is ready.", "success");
  } catch (error) {
    setStatus(`Demo dataset failed: ${error.message}`, "error");
  }
}

async function createOrganization(event) {
  event.preventDefault();

  const payload = {
    slug: elements.organizationSlugInput.value.trim(),
    name: elements.organizationNameInput.value.trim(),
    country: elements.organizationCountryInput.value.trim(),
    city: elements.organizationCityInput.value.trim(),
    website_url: elements.organizationWebsiteInput.value.trim(),
    contact_email: elements.organizationEmailInput.value.trim(),
    collaboration_stage: elements.organizationStageInput.value.trim(),
    summary: elements.organizationSummaryInput.value.trim(),
  };

  if (Object.values(payload).some((value) => !value)) {
    setStatus("All organization fields are required.", "error");
    return;
  }

  try {
    await apiFetch("/organization", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    elements.organizationForm.reset();
    await loadOrganizations();
    setStatus("Organization created.", "success");
  } catch (error) {
    setStatus(`Could not create organization: ${error.message}`, "error");
  }
}

async function createInterest(event) {
  event.preventDefault();

  const payload = {
    organization_id: Number(elements.interestOrganizationInput.value),
    title: elements.interestTitleInput.value.trim(),
    work_mode: elements.interestWorkModeInput.value.trim(),
    summary: elements.interestSummaryInput.value.trim(),
    desired_start_on: elements.interestStartInput.value || null,
  };

  if (!payload.organization_id || !payload.title || !payload.work_mode || !payload.summary) {
    setStatus("All interest fields except the start date are required.", "error");
    return;
  }

  try {
    await apiFetch("/interest", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    elements.interestForm.reset();
    await loadOrganizations();
    setStatus("Interest signal created.", "success");
  } catch (error) {
    setStatus(`Could not create interest: ${error.message}`, "error");
  }
}

async function createThesisTopic(event) {
  event.preventDefault();

  const payload = {
    organization_id: Number(elements.topicOrganizationInput.value),
    title: elements.topicTitleInput.value.trim(),
    discipline: elements.topicDisciplineInput.value.trim(),
    location: elements.topicLocationInput.value.trim(),
    contact_email: elements.topicEmailInput.value.trim(),
    summary: elements.topicSummaryInput.value.trim(),
    application_deadline: elements.topicDeadlineInput.value || null,
  };

  if (
    !payload.organization_id ||
    !payload.title ||
    !payload.discipline ||
    !payload.location ||
    !payload.contact_email ||
    !payload.summary
  ) {
    setStatus("All thesis topic fields except the deadline are required.", "error");
    return;
  }

  try {
    await apiFetch("/thesis_topic", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    elements.topicForm.reset();
    await loadTopics();
    setStatus("Thesis topic created.", "success");
  } catch (error) {
    setStatus(`Could not create thesis topic: ${error.message}`, "error");
  }
}

function updateRequestFormState() {
  const enabled = Boolean(state.currentUser);
  for (const control of [
    elements.requestOrganizationInput,
    elements.requestTitleInput,
    elements.requestPreferredDateInput,
    elements.requestMessageInput,
  ]) {
    control.disabled = !enabled;
  }
}

function syncOrganizationSelects() {
  const options = state.organizations.length === 0
    ? '<option value="">No organizations yet</option>'
    : state.organizations
      .map(
        (organization) =>
          `<option value="${organization.id}">${escapeHtml(organization.name)} (${escapeHtml(organization.country)})</option>`,
      )
      .join("");

  for (const select of [
    elements.requestOrganizationInput,
    elements.interestOrganizationInput,
    elements.topicOrganizationInput,
  ]) {
    select.innerHTML = options;
    select.disabled = state.organizations.length === 0;
  }
  updateRequestFormState();
}

function focusRequestComposer(organizationId) {
  if (organizationId) {
    elements.requestOrganizationInput.value = String(organizationId);
  }
  document.getElementById("requestForm").scrollIntoView({ behavior: "smooth", block: "start" });
  elements.requestTitleInput.focus();
}

function interestCacheKey(organizationId) {
  return `${organizationId}:${elements.interestSearchInput.value.trim().toLowerCase()}`;
}

function organizationById(id) {
  return state.organizations.find((organization) => Number(organization.id) === Number(id));
}

function isAdmin() {
  return Boolean(state.account?.roles?.includes("admin"));
}

function renderEmpty(message) {
  return `<div class="empty">${escapeHtml(message)}</div>`;
}

function formatDate(value) {
  if (!value) {
    return "";
  }
  const parsed = new Date(`${value}T00:00:00`);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDateTime(value) {
  if (!value) {
    return "";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function readCookie(name) {
  return document.cookie
    .split(";")
    .map((segment) => segment.trim())
    .find((segment) => segment.startsWith(`${name}=`))
    ?.slice(name.length + 1) || "";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#96;");
}
