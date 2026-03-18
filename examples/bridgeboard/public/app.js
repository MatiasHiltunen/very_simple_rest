const API_BASE = "/api";
const AUTH_PORTAL_URL = "/api/auth/portal";
const AUTH_ADMIN_URL = "/api/auth/admin";
const CSRF_COOKIE_NAME = "vsr_csrf";
const MOBILE_NAV_BREAKPOINT = 980;

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
  organizationOptions: [],
  mobileNavOpen: false,
  route: null,
  view: null,
};

const elements = {
  siteHeader: document.getElementById("siteHeader"),
  app: document.getElementById("app"),
  noticeBar: document.getElementById("noticeBar"),
  sessionChip: document.getElementById("sessionChip"),
  navAdminContent: document.getElementById("navAdminContent"),
  navAdminUsers: document.getElementById("navAdminUsers"),
  mobileSessionChip: document.getElementById("mobileSessionChip"),
  mobileSessionHint: document.getElementById("mobileSessionHint"),
  mobileNavAdminContent: document.getElementById("mobileNavAdminContent"),
  mobileNavAdminUsers: document.getElementById("mobileNavAdminUsers"),
  builtinAdminLink: document.getElementById("builtinAdminLink"),
  mobileBuiltinAdminLink: document.getElementById("mobileBuiltinAdminLink"),
  portalLink: document.getElementById("portalLink"),
  mobilePortalLink: document.getElementById("mobilePortalLink"),
  accountShortcut: document.getElementById("accountShortcut"),
  mobileAccountShortcut: document.getElementById("mobileAccountShortcut"),
  mobileDrawerAccountButton: document.getElementById("mobileDrawerAccountButton"),
  mobileMenuButton: document.getElementById("mobileMenuButton"),
  mobileNavTray: document.getElementById("mobileNavTray"),
};

document.addEventListener("click", handleClick);
document.addEventListener("submit", handleSubmit);
document.addEventListener("keydown", handleKeydown);
window.addEventListener("popstate", () => {
  void navigateToCurrentLocation({ preserveScroll: true });
});
window.addEventListener("resize", handleResize);
elements.accountShortcut.addEventListener("click", () => {
  closeMobileNav();
  navigate("/account");
});
elements.mobileAccountShortcut.addEventListener("click", () => {
  closeMobileNav();
  navigate("/account");
});
elements.mobileDrawerAccountButton.addEventListener("click", () => {
  closeMobileNav();
  navigate("/account");
});
elements.mobileMenuButton.addEventListener("click", () => {
  toggleMobileNav();
});

bootstrap();

async function bootstrap() {
  syncHeader();
  setNotice("Loading Bridgeboard…", "info");
  await refreshSession({ silent: true });
  await navigateToCurrentLocation({ preserveScroll: true });
}

function isMobileShell() {
  return window.innerWidth <= MOBILE_NAV_BREAKPOINT;
}

function openMobileNav() {
  if (!isMobileShell()) {
    return;
  }
  state.mobileNavOpen = true;
  syncHeader();
}

function closeMobileNav() {
  if (!state.mobileNavOpen) {
    return;
  }
  state.mobileNavOpen = false;
  syncHeader();
}

function toggleMobileNav() {
  if (state.mobileNavOpen) {
    closeMobileNav();
  } else {
    openMobileNav();
  }
}

function handleKeydown(event) {
  if (event.key === "Escape") {
    closeMobileNav();
  }
}

function handleResize() {
  if (!isMobileShell()) {
    closeMobileNav();
  } else {
    syncHeader();
  }
}

async function navigateToCurrentLocation({ preserveScroll = false } = {}) {
  closeMobileNav();
  state.route = parseRoute(window.location.pathname, window.location.search);
  syncHeader();
  renderLoading(state.route.title, state.route.description);

  try {
    state.view = await loadView(state.route);
    renderView();
    if (!preserveScroll) {
      window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    }
  } catch (error) {
    const message = error.message || "Something went wrong while loading the page.";
    state.view = {
      kind: "error",
      title: "Could not load Bridgeboard",
      detail: message,
    };
    renderView();
    setNotice(message, "error");
  }
}

function navigate(path) {
  const target = new URL(path, window.location.origin);
  const next = `${target.pathname}${target.search}`;
  const current = `${window.location.pathname}${window.location.search}`;
  if (next === current) {
    void navigateToCurrentLocation({ preserveScroll: true });
    return;
  }
  window.history.pushState({}, "", next);
  void navigateToCurrentLocation({ preserveScroll: false });
}

function parseRoute(pathname, search) {
  const cleanPath = normalizePath(pathname);
  const searchParams = new URLSearchParams(search);

  if (cleanPath === "/") {
    return {
      name: "home",
      title: "Bridgeboard overview",
      description: "Loading platform overview…",
      searchParams,
      params: {},
    };
  }

  if (cleanPath === "/organizations") {
    return {
      name: "organizations",
      title: "Organizations",
      description: "Loading organizations…",
      searchParams,
      params: {},
    };
  }

  const organizationMatch = cleanPath.match(/^\/organizations\/([^/]+)$/);
  if (organizationMatch) {
    return {
      name: "organization-detail",
      title: "Organization",
      description: "Loading organization profile…",
      searchParams,
      params: { slug: decodeURIComponent(organizationMatch[1]) },
    };
  }

  if (cleanPath === "/topics") {
    return {
      name: "topics",
      title: "Thesis topics",
      description: "Loading thesis topics…",
      searchParams,
      params: {},
    };
  }

  const topicMatch = cleanPath.match(/^\/topics\/([^/]+)$/);
  if (topicMatch) {
    return {
      name: "topic-detail",
      title: "Topic",
      description: "Loading thesis topic…",
      searchParams,
      params: { id: decodeURIComponent(topicMatch[1]) },
    };
  }

  if (cleanPath === "/requests") {
    return {
      name: "requests",
      title: "Requests",
      description: "Loading collaboration requests…",
      searchParams,
      params: {},
    };
  }

  if (cleanPath === "/account") {
    return {
      name: "account",
      title: "Account",
      description: "Loading account workspace…",
      searchParams,
      params: {},
    };
  }

  if (cleanPath === "/admin/content") {
    return {
      name: "admin-content",
      title: "Admin content",
      description: "Loading content administration…",
      searchParams,
      params: {},
    };
  }

  if (cleanPath === "/admin/users") {
    return {
      name: "admin-users",
      title: "Admin users",
      description: "Loading user administration…",
      searchParams,
      params: {},
    };
  }

  return {
    name: "not-found",
    title: "Not found",
    description: "Loading page…",
    searchParams,
    params: {},
  };
}

function normalizePath(pathname) {
  if (!pathname || pathname === "/") {
    return "/";
  }
  if (pathname === "/index.html") {
    return "/";
  }
  return pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

async function loadView(route) {
  switch (route.name) {
    case "home":
      return loadHomeView();
    case "organizations":
      return loadOrganizationsView(route.searchParams);
    case "organization-detail":
      return loadOrganizationDetailView(route.params.slug);
    case "topics":
      return loadTopicsView(route.searchParams);
    case "topic-detail":
      return loadTopicDetailView(route.params.id);
    case "requests":
      return loadRequestsView(route.searchParams);
    case "account":
      return loadAccountView();
    case "admin-content":
      return loadAdminContentView();
    case "admin-users":
      return loadAdminUsersView(route.searchParams);
    default:
      return {
        kind: "not-found",
        title: "Page not found",
        detail:
          "That route is not part of the Bridgeboard workspace. Return to the overview and continue from there.",
      };
  }
}

async function loadHomeView() {
  await ensureOrganizationOptions();
  const [organizations, interests, topics, requests] = await Promise.all([
    fetchOrganizations({}, { limit: 4, sort: "name", order: "asc" }),
    fetchInterests({}, { limit: 4, sort: "desired_start_on", order: "asc" }),
    fetchTopics({}, { limit: 4, sort: "application_deadline", order: "asc" }),
    state.currentUser
      ? fetchRequests({ limit: 6, sort: "created_at", order: "desc" })
      : Promise.resolve(null),
  ]);

  return {
    kind: "home",
    organizations: organizations.items || [],
    interests: interests.items || [],
    topics: topics.items || [],
    requests: requests?.items || [],
    metrics: {
      organizations: organizations.total ?? (organizations.items || []).length,
      interests: interests.total ?? (interests.items || []).length,
      topics: topics.total ?? (topics.items || []).length,
      requests: requests?.total ?? 0,
    },
  };
}

async function loadOrganizationsView(searchParams) {
  const filters = {
    q: searchParams.get("q") || "",
    country: searchParams.get("country") || "",
    interest: searchParams.get("interest") || "",
  };

  const [organizations, interestMatches] = await Promise.all([
    fetchOrganizations(
      { name: filters.q, country: filters.country },
      { limit: 100, sort: "name", order: "asc" },
    ),
    filters.interest
      ? fetchInterests(
          { title: filters.interest },
          { limit: 100, sort: "desired_start_on", order: "asc" },
        )
      : Promise.resolve({ items: [], total: 0 }),
  ]);

  const matchMap = new Map();
  for (const interest of interestMatches.items || []) {
    const organizationId = Number(interest.organization_id);
    if (!matchMap.has(organizationId)) {
      matchMap.set(organizationId, []);
    }
    matchMap.get(organizationId).push(interest);
  }

  let items = organizations.items || [];
  if (filters.interest) {
    items = items.filter((organization) => matchMap.has(Number(organization.id)));
  }

  return {
    kind: "organizations",
    items,
    filters,
    interestMatches: matchMap,
  };
}

async function loadOrganizationDetailView(slug) {
  const organizationResponse = await fetchOrganizations(
    { slug },
    { limit: 1, sort: "name", order: "asc" },
  );
  const organization = (organizationResponse.items || [])[0];
  if (!organization) {
    return {
      kind: "not-found",
      title: "Organization not found",
      detail: "That organization is not currently published on Bridgeboard.",
    };
  }

  const [interests, topics] = await Promise.all([
    apiFetch(
      buildListPath(`/organization/${organization.id}/interest`, {
        limit: 24,
        sort: "desired_start_on",
        order: "asc",
      }),
    ),
    fetchTopics(
      { organizationId: organization.id },
      { limit: 24, sort: "application_deadline", order: "asc" },
    ),
  ]);

  return {
    kind: "organization-detail",
    organization,
    interests: interests.items || [],
    topics: topics.items || [],
  };
}

async function loadTopicsView(searchParams) {
  await ensureOrganizationOptions();
  const filters = {
    q: searchParams.get("q") || "",
    discipline: searchParams.get("discipline") || "",
    location: searchParams.get("location") || "",
  };
  const topics = await fetchTopics(
    {
      title: filters.q,
      discipline: filters.discipline,
      location: filters.location,
    },
    { limit: 100, sort: "application_deadline", order: "asc" },
  );

  return {
    kind: "topics",
    items: topics.items || [],
    filters,
  };
}

async function loadTopicDetailView(id) {
  await ensureOrganizationOptions();
  const topic = await apiFetch(`/thesis_topic/${encodeURIComponent(id)}`);
  const organization = await apiFetch(
    `/organization/${encodeURIComponent(String(topic.organization_id))}`,
  );
  const relatedTopics = await fetchTopics(
    { organizationId: topic.organization_id },
    { limit: 6, sort: "application_deadline", order: "asc" },
  );

  return {
    kind: "topic-detail",
    topic,
    organization,
    relatedTopics: (relatedTopics.items || []).filter(
      (candidate) => Number(candidate.id) !== Number(topic.id),
    ),
  };
}

async function loadRequestsView(searchParams) {
  await ensureOrganizationOptions();
  const organizationId = searchParams.get("organization") || "";
  const requests = state.currentUser
    ? await fetchRequests({ limit: 50, sort: "created_at", order: "desc" })
    : { items: [], total: 0 };

  return {
    kind: "requests",
    requests: requests.items || [],
    total: requests.total ?? (requests.items || []).length,
    organizationId,
  };
}

async function loadAccountView() {
  return {
    kind: "account",
  };
}

async function loadAdminContentView() {
  if (!isAdmin()) {
    return forbiddenView(
      "Admin content requires an admin session.",
      "Sign in as an administrator to curate organizations, interest signals, and thesis topics.",
    );
  }

  await ensureOrganizationOptions();
  const requests = await fetchRequests({ limit: 16, sort: "created_at", order: "desc" });
  return {
    kind: "admin-content",
    requests: requests.items || [],
  };
}

async function loadAdminUsersView(searchParams) {
  if (!isAdmin()) {
    return forbiddenView(
      "Admin users requires an admin session.",
      "Sign in as an administrator to create accounts, adjust roles, or remove access.",
    );
  }

  const email = searchParams.get("email") || "";
  const users = await fetchManagedUsers(email);
  return {
    kind: "admin-users",
    search: email,
    users: users.items || [],
    total: users.total ?? (users.items || []).length,
  };
}

function forbiddenView(title, detail) {
  return {
    kind: "forbidden",
    title,
    detail,
  };
}

function renderLoading(title, detail) {
  document.title = `Bridgeboard · ${title}`;
  elements.app.innerHTML = `
    <div class="page loading-shell">
      <section class="empty-state">
        <p class="eyebrow">Bridgeboard</p>
        <strong>${escapeHtml(title)}</strong>
        <p>${escapeHtml(detail)}</p>
      </section>
    </div>
  `;
}

function renderView() {
  syncHeader();
  switch (state.view.kind) {
    case "home":
      document.title = "Bridgeboard";
      elements.app.innerHTML = renderHomeView(state.view);
      return;
    case "organizations":
      document.title = "Bridgeboard · Organizations";
      elements.app.innerHTML = renderOrganizationsView(state.view);
      return;
    case "organization-detail":
      document.title = `Bridgeboard · ${state.view.organization.name}`;
      elements.app.innerHTML = renderOrganizationDetailView(state.view);
      return;
    case "topics":
      document.title = "Bridgeboard · Thesis topics";
      elements.app.innerHTML = renderTopicsView(state.view);
      return;
    case "topic-detail":
      document.title = `Bridgeboard · ${state.view.topic.title}`;
      elements.app.innerHTML = renderTopicDetailView(state.view);
      return;
    case "requests":
      document.title = "Bridgeboard · Requests";
      elements.app.innerHTML = renderRequestsView(state.view);
      return;
    case "account":
      document.title = "Bridgeboard · Account";
      elements.app.innerHTML = renderAccountView();
      return;
    case "admin-content":
      document.title = "Bridgeboard · Admin content";
      elements.app.innerHTML = renderAdminContentView(state.view);
      return;
    case "admin-users":
      document.title = "Bridgeboard · Admin users";
      elements.app.innerHTML = renderAdminUsersView(state.view);
      return;
    case "forbidden":
      document.title = "Bridgeboard · Access required";
      elements.app.innerHTML = renderEmptyPage("Access required", state.view.detail, {
        primaryHref: "/account",
        primaryLabel: "Open account",
        secondaryHref: "/",
        secondaryLabel: "Return to overview",
      });
      return;
    case "not-found":
      document.title = "Bridgeboard · Not found";
      elements.app.innerHTML = renderEmptyPage(state.view.title, state.view.detail, {
        primaryHref: "/",
        primaryLabel: "Return to overview",
        secondaryHref: "/organizations",
        secondaryLabel: "Browse organizations",
      });
      return;
    default:
      document.title = "Bridgeboard · Error";
      elements.app.innerHTML = renderEmptyPage(
        state.view.title || "Something went wrong",
        state.view.detail || "The page could not be rendered.",
        {
          primaryHref: "/",
          primaryLabel: "Return to overview",
        },
      );
  }
}

function renderHomeView(view) {
  return `
    <div class="page">
      <section class="hero-panel">
        <div class="hero-grid">
          <div>
            <p class="eyebrow">Bridgeboard</p>
            <h1>Cross-border thesis collaboration, finally legible.</h1>
            <p class="lead">
              Bridgeboard brings universities, applied sciences campuses, labs, and industry
              partners into one shared operating surface for collaboration signals, thesis topics,
              and live request pipelines.
            </p>
            <div class="page-actions">
              <a class="button primary" href="/organizations" data-link>Explore organizations</a>
              <a class="button ghost" href="/topics" data-link>Review thesis topics</a>
              <a class="button secondary" href="/requests" data-link>
                ${state.currentUser ? "Open request workspace" : "See request flow"}
              </a>
            </div>
          </div>
          <div class="metric-grid">
            <article class="metric-card">
              <span>Organizations</span>
              <strong>${view.metrics.organizations}</strong>
            </article>
            <article class="metric-card">
              <span>Interest signals</span>
              <strong>${view.metrics.interests}</strong>
            </article>
            <article class="metric-card">
              <span>Thesis topics</span>
              <strong>${view.metrics.topics}</strong>
            </article>
          </div>
        </div>
      </section>

      <div class="page-grid-two">
        <section class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Featured organizations</p>
              <h2>Where collaboration is active right now</h2>
              <p class="muted">Public partner profiles make current intent visible before outreach starts.</p>
            </div>
            <a class="text-link" href="/organizations" data-link>Open the full directory</a>
          </div>
          <div class="card-grid">
            ${renderCollection(
              view.organizations,
              (organization) => renderOrganizationCard(organization, { compact: true }),
              "No organizations have been published yet.",
            )}
          </div>
        </section>

        <aside class="aside-stack">
          <section class="panel">
            <p class="eyebrow">Session</p>
            <h2>${state.account ? "Your workspace is active" : "Sign in to start building requests"}</h2>
            <p class="muted">
              ${
                state.account
                  ? `Signed in as ${escapeHtml(state.account.email)} with ${escapeHtml(state.account.role)} access.`
                  : "Register with a verified email to submit requests, manage your password, and open the built-in account portal."
              }
            </p>
            <div class="summary-grid">
              <article class="summary-item">
                <span>Email</span>
                <strong>${escapeHtml(state.account?.email || "Guest session")}</strong>
              </article>
              <article class="summary-item">
                <span>Role</span>
                <strong>${escapeHtml(state.account?.role || "guest")}</strong>
              </article>
              <article class="summary-item">
                <span>Verification</span>
                <strong>${state.account?.email_verified ? "Verified" : "Pending"}</strong>
              </article>
            </div>
            <div class="page-actions">
              <a class="button primary" href="/account" data-link>Manage account</a>
              ${
                isAdmin()
                  ? '<a class="button ghost" href="/admin/content" data-link>Open admin studio</a>'
                  : `<a class="button ghost" href="${AUTH_PORTAL_URL}" target="_blank" rel="noreferrer">Open built-in portal</a>`
              }
            </div>
          </section>

          <section class="panel">
            <p class="eyebrow">Operating model</p>
            <h2>Designed for real collaboration programs</h2>
            <div class="data-list">
              <article class="data-block">
                <h4>Public signal layer</h4>
                <p class="muted">Organizations can publish current interests and thesis-ready opportunities without exposing private pipeline data.</p>
              </article>
              <article class="data-block">
                <h4>Owner-scoped proposals</h4>
                <p class="muted">Collaboration requests remain private to the requester by default while admins can review the shared pipeline.</p>
              </article>
              <article class="data-block">
                <h4>Built-in auth workflows</h4>
                <p class="muted">Registration, verification, password reset, and account management already ship with the generated API.</p>
              </article>
            </div>
          </section>
        </aside>
      </div>

      <section class="panel">
        <div class="panel-header">
          <div>
            <p class="eyebrow">Interest signals</p>
            <h2>What organizations want to build next</h2>
          </div>
          <a class="text-link" href="/organizations" data-link>Browse partner profiles</a>
        </div>
        <div class="card-grid">
          ${renderCollection(
            view.interests,
            (interest) => renderInterestCard(interest),
            "No interest signals are published yet.",
          )}
        </div>
      </section>

      <section class="panel">
        <div class="panel-header">
          <div>
            <p class="eyebrow">Thesis topics</p>
            <h2>Opportunities ready for outreach</h2>
          </div>
          <a class="text-link" href="/topics" data-link>Open the topics view</a>
        </div>
        <div class="card-grid topics">
          ${renderCollection(
            view.topics,
            (topic) => renderTopicCard(topic),
            "No thesis topics are available yet.",
          )}
        </div>
      </section>

      ${
        state.currentUser
          ? `
            <section class="panel">
              <div class="panel-header">
                <div>
                  <p class="eyebrow">Request pipeline</p>
                  <h2>${isAdmin() ? "Latest requests in the admin pipeline" : "Your latest proposals"}</h2>
                </div>
                <a class="text-link" href="/requests" data-link>Open requests</a>
              </div>
              <div class="list-stack">
                ${renderCollection(
                  view.requests,
                  (request) => renderRequestCard(request),
                  isAdmin()
                    ? "No collaboration requests are in the admin pipeline yet."
                    : "You have not submitted any collaboration requests yet.",
                )}
              </div>
            </section>
          `
          : ""
      }
    </div>
  `;
}

function renderOrganizationsView(view) {
  return `
    <div class="page">
      <section class="panel">
        <div class="panel-header">
          <div>
            <p class="eyebrow">Organizations</p>
            <h1 class="page-heading">Discover collaboration-ready partners</h1>
            <p class="lead">Filter by organization, geography, or the type of interest currently being signaled into the network.</p>
          </div>
          <div class="summary-item">
            <span>Visible results</span>
            <strong>${view.items.length}</strong>
          </div>
        </div>

        <form id="organizations-filter-form" class="form-grid three">
          <label>
            <span>Organization or cluster</span>
            <input id="organizationsQuery" name="q" type="search" value="${escapeAttribute(view.filters.q)}" placeholder="Mobility lab, robotics, circular">
          </label>
          <label>
            <span>Country</span>
            <input id="organizationsCountry" name="country" type="search" value="${escapeAttribute(view.filters.country)}" placeholder="Finland, Estonia, Germany">
          </label>
          <label>
            <span>Interest signal</span>
            <input id="organizationsInterest" name="interest" type="search" value="${escapeAttribute(view.filters.interest)}" placeholder="AI, mobility, traceability">
          </label>
          <div class="button-row wide-field">
            <button type="submit">Apply filters</button>
            <a class="button ghost" href="/organizations" data-link>Clear filters</a>
          </div>
        </form>
      </section>

      <section class="panel">
        <div class="card-grid">
          ${renderCollection(
            view.items,
            (organization) =>
              renderOrganizationCard(organization, {
                compact: false,
                matchingInterests: view.interestMatches.get(Number(organization.id)) || [],
              }),
            "No organizations match the current filters.",
          )}
        </div>
      </section>
    </div>
  `;
}

function renderOrganizationDetailView(view) {
  const organization = view.organization;
  return `
    <div class="page">
      <section class="detail-card">
        <div class="detail-header">
          <div>
            <p class="eyebrow">Organization profile</p>
            <h1>${escapeHtml(organization.name)}</h1>
            <p class="detail-copy">${escapeHtml(organization.summary)}</p>
          </div>
          <div class="detail-rail">
            <div class="detail-stat">
              <span>Stage</span>
              <strong>${escapeHtml(organization.collaboration_stage)}</strong>
            </div>
          </div>
        </div>
        <div class="pill-row">
          <span class="pill">${escapeHtml(organization.country)}</span>
          <span class="pill">${escapeHtml(organization.city)}</span>
          <span class="pill accent">${escapeHtml(organization.slug)}</span>
        </div>
        <div class="page-actions">
          <a class="button primary" href="/requests?organization=${encodeURIComponent(String(organization.id))}" data-link>Propose collaboration</a>
          <a class="button ghost" href="${escapeAttribute(organization.website_url)}" target="_blank" rel="noreferrer">Visit website</a>
          <a class="button ghost" href="/organizations" data-link>Back to organizations</a>
        </div>
      </section>

      <div class="detail-grid">
        <section class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Current interests</p>
              <h2>Signals from this organization</h2>
            </div>
            <span class="badge">${view.interests.length} items</span>
          </div>
          <div class="list-stack">
            ${renderCollection(
              view.interests,
              (interest) => renderInterestCard(interest),
              "No interest signals have been published for this organization yet.",
            )}
          </div>
        </section>

        <aside class="aside-stack">
          <section class="panel">
            <p class="eyebrow">Profile details</p>
            <h2>Contact and location</h2>
            <dl class="meta-list">
              <div>
                <dt>Country</dt>
                <dd>${escapeHtml(organization.country)}</dd>
              </div>
              <div>
                <dt>City</dt>
                <dd>${escapeHtml(organization.city)}</dd>
              </div>
              <div>
                <dt>Contact</dt>
                <dd>${escapeHtml(organization.contact_email)}</dd>
              </div>
              <div>
                <dt>Website</dt>
                <dd><a class="text-link" href="${escapeAttribute(organization.website_url)}" target="_blank" rel="noreferrer">Open site</a></dd>
              </div>
            </dl>
          </section>

          <section class="panel">
            <p class="eyebrow">Thesis topics</p>
            <h2>Open opportunities from this partner</h2>
            <div class="list-stack">
              ${renderCollection(
                view.topics,
                (topic) => renderTopicCompact(topic),
                "No thesis topics are listed for this organization yet.",
              )}
            </div>
          </section>
        </aside>
      </div>
    </div>
  `;
}

function renderTopicsView(view) {
  return `
    <div class="page">
      <section class="panel">
        <div class="panel-header">
          <div>
            <p class="eyebrow">Thesis topics</p>
            <h1 class="page-heading">Scope thesis work with real partner demand</h1>
            <p class="lead">Search by topic title, discipline, or delivery location and move directly into outreach.</p>
          </div>
          <div class="summary-item">
            <span>Visible topics</span>
            <strong>${view.items.length}</strong>
          </div>
        </div>

        <form id="topics-filter-form" class="form-grid three">
          <label>
            <span>Topic search</span>
            <input name="q" type="search" value="${escapeAttribute(view.filters.q)}" placeholder="Trust layer, robotics, circular economy">
          </label>
          <label>
            <span>Discipline</span>
            <input name="discipline" type="search" value="${escapeAttribute(view.filters.discipline)}" placeholder="Service design, robotics, data governance">
          </label>
          <label>
            <span>Location</span>
            <input name="location" type="search" value="${escapeAttribute(view.filters.location)}" placeholder="Oulu, Tallinn, remote">
          </label>
          <div class="button-row wide-field">
            <button type="submit">Apply filters</button>
            <a class="button ghost" href="/topics" data-link>Clear filters</a>
          </div>
        </form>
      </section>

      <section class="panel">
        <div class="card-grid topics">
          ${renderCollection(
            view.items,
            (topic) => renderTopicCard(topic),
            "No thesis topics match the current filters.",
          )}
        </div>
      </section>
    </div>
  `;
}

function renderTopicDetailView(view) {
  const topic = view.topic;
  const organization = view.organization;
  return `
    <div class="page">
      <section class="detail-card">
        <div class="detail-header">
          <div>
            <p class="eyebrow">Thesis topic</p>
            <h1>${escapeHtml(topic.title)}</h1>
            <p class="detail-copy">${escapeHtml(topic.summary)}</p>
          </div>
          <div class="detail-rail">
            <div class="detail-stat">
              <span>Deadline</span>
              <strong>${escapeHtml(formatDate(topic.application_deadline) || "Open")}</strong>
            </div>
          </div>
        </div>
        <div class="pill-row">
          <span class="pill">${escapeHtml(topic.discipline)}</span>
          <span class="pill">${escapeHtml(topic.location)}</span>
          <span class="pill accent">${escapeHtml(organization.name)}</span>
        </div>
        <div class="page-actions">
          <a class="button primary" href="/requests?organization=${encodeURIComponent(String(organization.id))}" data-link>Start collaboration request</a>
          <a class="button ghost" href="/organizations/${encodeURIComponent(organization.slug)}" data-link>Open organization profile</a>
          <a class="button ghost" href="/topics" data-link>Back to topics</a>
        </div>
      </section>

      <div class="detail-grid">
        <section class="panel">
          <p class="eyebrow">Topic brief</p>
          <h2>Delivery details</h2>
          <div class="summary-grid">
            <article class="summary-item">
              <span>Organization</span>
              <strong>${escapeHtml(organization.name)}</strong>
            </article>
            <article class="summary-item">
              <span>Location</span>
              <strong>${escapeHtml(topic.location)}</strong>
            </article>
            <article class="summary-item">
              <span>Application deadline</span>
              <strong>${escapeHtml(formatDate(topic.application_deadline) || "Open")}</strong>
            </article>
            <article class="summary-item">
              <span>Contact</span>
              <strong>${escapeHtml(topic.contact_email)}</strong>
            </article>
          </div>
          <div class="data-block">
            <h4>Why it matters</h4>
            <p class="muted">${escapeHtml(topic.summary)}</p>
          </div>
        </section>

        <aside class="aside-stack">
          <section class="panel">
            <p class="eyebrow">Organization context</p>
            <h2>${escapeHtml(organization.name)}</h2>
            <p class="muted">${escapeHtml(organization.summary)}</p>
            <div class="page-actions">
              <a class="button ghost" href="/organizations/${encodeURIComponent(organization.slug)}" data-link>Open organization</a>
              <a class="button ghost" href="${escapeAttribute(organization.website_url)}" target="_blank" rel="noreferrer">Visit site</a>
            </div>
          </section>

          <section class="panel">
            <p class="eyebrow">Related topics</p>
            <h2>More from this partner</h2>
            <div class="list-stack">
              ${renderCollection(
                view.relatedTopics.slice(0, 3),
                (relatedTopic) => renderTopicCompact(relatedTopic),
                "No additional topics are currently listed.",
              )}
            </div>
          </section>
        </aside>
      </div>
    </div>
  `;
}

function renderRequestsView(view) {
  if (!state.currentUser) {
    return `
      <div class="page">
        <section class="hero-panel">
          <div class="hero-grid">
            <div>
              <p class="eyebrow">Requests</p>
              <h1>Private proposal flow for real collaboration work.</h1>
              <p class="lead">
                Collaboration requests are tied to verified accounts so proposals stay owner-scoped
                for regular users and visible to administrators for shared review.
              </p>
              <div class="page-actions">
                <a class="button primary" href="/account" data-link>Register or sign in</a>
                <a class="button ghost" href="/organizations" data-link>Browse organizations first</a>
              </div>
            </div>
            <div class="metric-grid">
              <article class="metric-card">
                <span>Privacy model</span>
                <strong>Owner scoped</strong>
              </article>
              <article class="metric-card">
                <span>Verification</span>
                <strong>Email first</strong>
              </article>
              <article class="metric-card">
                <span>Admin review</span>
                <strong>Built in</strong>
              </article>
            </div>
          </div>
        </section>
      </div>
    `;
  }

  return `
    <div class="page">
      <section class="hero-panel">
        <div class="hero-grid">
          <div>
            <p class="eyebrow">Requests</p>
            <h1>${isAdmin() ? "Run the shared collaboration pipeline." : "Turn discovery into a real proposal."}</h1>
            <p class="lead">
              ${
                isAdmin()
                  ? "As an administrator, you can review every collaboration request and move proposals through review, matching, and archival states."
                  : "Requests are private to you and administrators. Use them to frame supervision models, desired start dates, and partner expectations."
              }
            </p>
          </div>
          <div class="metric-grid">
            <article class="metric-card">
              <span>Visible requests</span>
              <strong>${view.total}</strong>
            </article>
            <article class="metric-card">
              <span>Session</span>
              <strong>${escapeHtml(state.account.role)}</strong>
            </article>
            <article class="metric-card">
              <span>Email status</span>
              <strong>${state.account.email_verified ? "Verified" : "Pending"}</strong>
            </article>
          </div>
        </div>
      </section>

      <div class="request-layout">
        <section class="panel">
          <p class="eyebrow">Compose request</p>
          <h2>Submit a collaboration proposal</h2>
          <form id="request-form">
            <label>
              <span>Organization</span>
              <select name="organization_id">
                ${renderOrganizationOptions(view.organizationId)}
              </select>
            </label>
            <label>
              <span>Proposal title</span>
              <input name="title" type="text" maxlength="160" placeholder="Joint supervision for applied AI thesis" required>
            </label>
            <label>
              <span>Preferred start date</span>
              <input name="preferred_start_on" type="date">
            </label>
            <label>
              <span>Proposal summary</span>
              <textarea name="message" placeholder="Describe the challenge, expected student profile, and what success should look like." required></textarea>
            </label>
            <div class="form-actions">
              <button type="submit">Send request</button>
              <a class="button ghost" href="/organizations" data-link>Browse organizations</a>
            </div>
          </form>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">Pipeline</p>
              <h2>${isAdmin() ? "Admin review queue" : "Your submitted requests"}</h2>
            </div>
            <button class="button ghost" data-action="refresh-session" type="button">Refresh session</button>
          </div>
          <div class="list-stack">
            ${renderCollection(
              view.requests,
              (request) => renderRequestCard(request),
              isAdmin()
                ? "No collaboration requests are in the admin pipeline yet."
                : "You have not submitted any collaboration requests yet.",
            )}
          </div>
        </section>
      </div>
    </div>
  `;
}

function renderAccountView() {
  return `
    <div class="page">
      <section class="hero-panel">
        <div class="hero-grid">
          <div>
            <p class="eyebrow">Account</p>
            <h1>${state.account ? "Manage a verified collaboration identity." : "Create the account layer for your collaboration work."}</h1>
            <p class="lead">
              Bridgeboard uses built-in auth for registration, verification, password reset, and account administration. The generated API already handles the heavy lifting.
            </p>
            <div class="page-actions">
              <a class="button primary" href="${AUTH_PORTAL_URL}" target="_blank" rel="noreferrer">Open built-in portal</a>
              ${
                isAdmin()
                  ? `<a class="button ghost" href="${AUTH_ADMIN_URL}" target="_blank" rel="noreferrer">Open built-in admin</a>`
                  : `<a class="button ghost" href="/requests" data-link>Open requests</a>`
              }
            </div>
          </div>
          <div class="metric-grid">
            <article class="metric-card">
              <span>Email</span>
              <strong>${escapeHtml(state.account?.email || "Guest")}</strong>
            </article>
            <article class="metric-card">
              <span>Role</span>
              <strong>${escapeHtml(state.account?.role || "guest")}</strong>
            </article>
            <article class="metric-card">
              <span>Verification</span>
              <strong>${state.account?.email_verified ? "Verified" : "Pending"}</strong>
            </article>
          </div>
        </div>
      </section>

      <div class="page-grid-two">
        <section class="panel">
          <p class="eyebrow">Authentication</p>
          <h2>Register or sign in</h2>
          <form id="account-auth-form">
            <label>
              <span>Email</span>
              <input id="accountEmail" name="email" type="email" autocomplete="email" value="${escapeAttribute(state.account?.email || "")}" placeholder="name@campus.example" required>
            </label>
            <label>
              <span>Password</span>
              <input id="accountPassword" name="password" type="password" autocomplete="current-password" placeholder="At least 8 characters" required>
            </label>
            <div class="button-row">
              <button type="submit" name="intent" value="register">Register</button>
              <button class="secondary" type="submit" name="intent" value="login">Log in</button>
              <button class="ghost" type="button" data-action="logout">Log out</button>
            </div>
            <div class="button-row">
              <button class="ghost" type="button" data-action="request-reset">Email reset link</button>
              <button class="ghost" type="button" data-action="resend-verification">Resend verification</button>
              <button class="ghost" type="button" data-action="refresh-session">Refresh session</button>
            </div>
          </form>
          <p class="footer-note">
            In local capture mode, verification and reset emails are written to the configured capture directory.
          </p>
        </section>

        <section class="panel">
          <p class="eyebrow">Session record</p>
          <h2>${state.account ? "Current account context" : "No active session"}</h2>
          <div class="summary-grid">
            <article class="summary-item">
              <span>Email</span>
              <strong>${escapeHtml(state.account?.email || "Guest session")}</strong>
            </article>
            <article class="summary-item">
              <span>Roles</span>
              <strong>${escapeHtml((state.account?.roles || ["guest"]).join(", "))}</strong>
            </article>
            <article class="summary-item">
              <span>Email verification</span>
              <strong>${state.account?.email_verified ? "Verified" : "Pending"}</strong>
            </article>
          </div>
          <pre class="code-block">${escapeHtml(JSON.stringify(state.account || { status: "guest" }, null, 2))}</pre>
          <div class="page-actions">
            <a class="button ghost" href="${AUTH_PORTAL_URL}" target="_blank" rel="noreferrer">Open portal page</a>
            ${
              isAdmin()
                ? `<a class="button ghost" href="/admin/users" data-link>Open admin users</a>`
                : ""
            }
          </div>
        </section>
      </div>
    </div>
  `;
}

function renderAdminContentView(view) {
  return `
    <div class="page">
      <section class="hero-panel">
        <div class="hero-grid">
          <div>
            <p class="eyebrow">Admin content</p>
            <h1>Operate the public catalog like a real product surface.</h1>
            <p class="lead">
              Curate organizations, interest signals, and thesis topics directly inside Bridgeboard,
              then hand off user lifecycle management to the built-in admin dashboard or the
              dedicated user workspace.
            </p>
            <div class="page-actions">
              <button type="button" data-action="load-demo">Load demo dataset</button>
              <a class="button ghost" href="/admin/users" data-link>Open admin users</a>
              <a class="button ghost" href="${AUTH_ADMIN_URL}" target="_blank" rel="noreferrer">Built-in admin dashboard</a>
            </div>
          </div>
          <div class="metric-grid">
            <article class="metric-card">
              <span>Organizations</span>
              <strong>${state.organizationOptions.length}</strong>
            </article>
            <article class="metric-card">
              <span>Requests visible</span>
              <strong>${view.requests.length}</strong>
            </article>
            <article class="metric-card">
              <span>Admin role</span>
              <strong>Enabled</strong>
            </article>
          </div>
        </div>
      </section>

      <section class="admin-grid">
        <article class="admin-card">
          <p class="eyebrow">Create organization</p>
          <h3>Publish a new partner profile</h3>
          <form id="organization-form">
            <label><span>Slug</span><input name="slug" type="text" placeholder="nordic-systems-lab" required></label>
            <label><span>Name</span><input name="name" type="text" placeholder="Nordic Systems Lab" required></label>
            <div class="form-grid two">
              <label><span>Country</span><input name="country" type="text" placeholder="Finland" required></label>
              <label><span>City</span><input name="city" type="text" placeholder="Oulu" required></label>
            </div>
            <label><span>Website</span><input name="website_url" type="url" placeholder="https://example.org" required></label>
            <label><span>Contact email</span><input name="contact_email" type="email" placeholder="partnerships@example.org" required></label>
            <label><span>Collaboration stage</span><input name="collaboration_stage" type="text" placeholder="Open call" required></label>
            <label><span>Summary</span><textarea name="summary" placeholder="Describe what this organization wants to build across borders." required></textarea></label>
            <button type="submit">Create organization</button>
          </form>
        </article>

        <article class="admin-card">
          <p class="eyebrow">Create interest signal</p>
          <h3>Surface near-term partner intent</h3>
          <form id="interest-form">
            <label>
              <span>Organization</span>
              <select name="organization_id">${renderOrganizationOptions("")}</select>
            </label>
            <label><span>Title</span><input name="title" type="text" placeholder="Shared supervision model for AI pilots" required></label>
            <label><span>Work mode</span><input name="work_mode" type="text" placeholder="Hybrid sprint" required></label>
            <label><span>Desired start date</span><input name="desired_start_on" type="date"></label>
            <label><span>Summary</span><textarea name="summary" placeholder="Describe the signal in a way that helps schools or labs react quickly." required></textarea></label>
            <button type="submit">Create interest</button>
          </form>
        </article>

        <article class="admin-card">
          <p class="eyebrow">Create thesis topic</p>
          <h3>Publish a thesis-ready opportunity</h3>
          <form id="topic-form">
            <label>
              <span>Organization</span>
              <select name="organization_id">${renderOrganizationOptions("")}</select>
            </label>
            <label><span>Title</span><input name="title" type="text" placeholder="Cross-border data trust for apprenticeships" required></label>
            <div class="form-grid two">
              <label><span>Discipline</span><input name="discipline" type="text" placeholder="Data governance" required></label>
              <label><span>Location</span><input name="location" type="text" placeholder="Oulu + remote" required></label>
            </div>
            <label><span>Contact email</span><input name="contact_email" type="email" placeholder="mentor@example.org" required></label>
            <label><span>Application deadline</span><input name="application_deadline" type="date"></label>
            <label><span>Summary</span><textarea name="summary" placeholder="Frame the scope, expected methods, and intended impact." required></textarea></label>
            <button type="submit">Create thesis topic</button>
          </form>
        </article>
      </section>

      <section class="panel">
        <div class="panel-header">
          <div>
            <p class="eyebrow">Pipeline review</p>
            <h2>Latest collaboration requests</h2>
          </div>
          <a class="text-link" href="/requests" data-link>Open request workspace</a>
        </div>
        <div class="list-stack">
          ${renderCollection(
            view.requests,
            (request) => renderRequestCard(request),
            "No collaboration requests are currently available for review.",
          )}
        </div>
      </section>
    </div>
  `;
}

function renderAdminUsersView(view) {
  return `
    <div class="page">
      <section class="hero-panel">
        <div class="hero-grid">
          <div>
            <p class="eyebrow">Admin users</p>
            <h1>Manage built-in auth users without leaving the app.</h1>
            <p class="lead">
              Create accounts, change roles, resend verification, trigger password reset, and
              remove access. The built-in admin dashboard remains available as a companion tool.
            </p>
            <div class="page-actions">
              <a class="button ghost" href="${AUTH_ADMIN_URL}" target="_blank" rel="noreferrer">Open built-in admin</a>
              <a class="button ghost" href="/admin/content" data-link>Back to admin content</a>
            </div>
          </div>
          <div class="metric-grid">
            <article class="metric-card">
              <span>Visible users</span>
              <strong>${view.total}</strong>
            </article>
            <article class="metric-card">
              <span>Admin session</span>
              <strong>${escapeHtml(state.account.email)}</strong>
            </article>
            <article class="metric-card">
              <span>Role</span>
              <strong>${escapeHtml(state.account.role)}</strong>
            </article>
          </div>
        </div>
      </section>

      <div class="page-grid-two">
        <section class="panel">
          <p class="eyebrow">Create user</p>
          <h2>Provision a new account</h2>
          <form id="admin-user-create-form">
            <label><span>Email</span><input name="email" type="email" placeholder="user@example.com" required></label>
            <label><span>Initial password</span><input name="password" type="password" placeholder="Temporary password" required></label>
            <label><span>Role</span><input name="role" type="text" value="user" required></label>
            <div class="form-grid two">
              <label>
                <span>Verification state</span>
                <select name="email_verified">
                  <option value="false">Pending verification</option>
                  <option value="true">Verified immediately</option>
                </select>
              </label>
              <label>
                <span>Verification email</span>
                <select name="send_verification_email">
                  <option value="true">Send verification email</option>
                  <option value="false">Do not send</option>
                </select>
              </label>
            </div>
            <button type="submit">Create user</button>
          </form>
        </section>

        <section class="panel">
          <p class="eyebrow">Search</p>
          <h2>Filter the directory</h2>
          <form id="admin-user-search-form">
            <label><span>Email search</span><input name="email" type="search" value="${escapeAttribute(view.search)}" placeholder="jane@example.com"></label>
            <div class="button-row">
              <button type="submit">Apply search</button>
              <a class="button ghost" href="/admin/users" data-link>Clear</a>
            </div>
          </form>
          <div class="summary-grid">
            <article class="summary-item">
              <span>Users loaded</span>
              <strong>${view.users.length}</strong>
            </article>
            <article class="summary-item">
              <span>Search term</span>
              <strong>${escapeHtml(view.search || "All users")}</strong>
            </article>
          </div>
        </section>
      </div>

      <section class="panel">
        <div class="panel-header">
          <div>
            <p class="eyebrow">Directory</p>
            <h2>Built-in auth users</h2>
          </div>
        </div>
        <div class="card-grid">
          ${renderCollection(
            view.users,
            (user) => renderManagedUserCard(user),
            "No users match the current search.",
          )}
        </div>
      </section>
    </div>
  `;
}

function renderEmptyPage(title, detail, actions = {}) {
  const primaryAction = actions.primaryHref
    ? `<a class="button primary" href="${escapeAttribute(actions.primaryHref)}" data-link>${escapeHtml(actions.primaryLabel)}</a>`
    : "";
  const secondaryAction = actions.secondaryHref
    ? `<a class="button ghost" href="${escapeAttribute(actions.secondaryHref)}" data-link>${escapeHtml(actions.secondaryLabel)}</a>`
    : "";

  return `
    <div class="page">
      <section class="empty-state">
        <p class="eyebrow">Bridgeboard</p>
        <strong>${escapeHtml(title)}</strong>
        <p>${escapeHtml(detail)}</p>
        <div class="page-actions">
          ${primaryAction}
          ${secondaryAction}
        </div>
      </section>
    </div>
  `;
}

function renderOrganizationCard(organization, options = {}) {
  const matchingInterests = options.matchingInterests || [];
  const matchedInterestMarkup =
    matchingInterests.length > 0
      ? `
        <div class="data-block">
          <h4>Matching interest signals</h4>
          <div class="pill-row">
            ${matchingInterests
              .slice(0, 3)
              .map((interest) => `<span class="pill accent">${escapeHtml(interest.title)}</span>`)
              .join("")}
          </div>
        </div>
      `
      : "";

  return `
    <article class="catalog-card">
      <div class="card-top">
        <div>
          <p class="eyebrow">Organization</p>
          <h3>${escapeHtml(organization.name)}</h3>
        </div>
        <span class="badge">${escapeHtml(organization.country)}</span>
      </div>
      <div class="pill-row">
        <span class="pill">${escapeHtml(organization.city)}</span>
        <span class="pill accent">${escapeHtml(organization.collaboration_stage)}</span>
      </div>
      <p class="card-copy">${escapeHtml(organization.summary)}</p>
      ${options.compact ? "" : matchedInterestMarkup}
      <div class="card-actions">
        <a class="button ghost" href="/organizations/${encodeURIComponent(organization.slug)}" data-link>Open profile</a>
        <a class="button secondary" href="/requests?organization=${encodeURIComponent(String(organization.id))}" data-link>Propose collaboration</a>
        <a class="text-link" href="${escapeAttribute(organization.website_url)}" target="_blank" rel="noreferrer">Visit website</a>
      </div>
    </article>
  `;
}

function renderInterestCard(interest) {
  const organization = organizationById(interest.organization_id);
  return `
    <article class="catalog-card">
      <div class="card-top">
        <div>
          <p class="eyebrow">Interest signal</p>
          <h3>${escapeHtml(interest.title)}</h3>
        </div>
        <span class="badge warning">${escapeHtml(interest.work_mode)}</span>
      </div>
      <div class="pill-row">
        <span class="pill">${escapeHtml(organization?.name || "Unknown organization")}</span>
        <span class="pill">${escapeHtml(formatDate(interest.desired_start_on) || "Flexible start")}</span>
      </div>
      <p class="card-copy">${escapeHtml(interest.summary)}</p>
      ${
        organization
          ? `<div class="card-actions"><a class="button ghost" href="/organizations/${encodeURIComponent(organization.slug)}" data-link>Open organization</a></div>`
          : ""
      }
    </article>
  `;
}

function renderTopicCard(topic) {
  const organization = organizationById(topic.organization_id);
  return `
    <article class="catalog-card">
      <div class="card-top">
        <div>
          <p class="eyebrow">Thesis topic</p>
          <h3>${escapeHtml(topic.title)}</h3>
        </div>
        <span class="badge">${escapeHtml(formatDate(topic.application_deadline) || "Open")}</span>
      </div>
      <div class="pill-row">
        <span class="pill">${escapeHtml(topic.discipline)}</span>
        <span class="pill">${escapeHtml(topic.location)}</span>
      </div>
      <p class="card-copy">${escapeHtml(topic.summary)}</p>
      <p class="muted">
        Hosted by <strong>${escapeHtml(organization?.name || "Unknown organization")}</strong>
      </p>
      <div class="card-actions">
        <a class="button ghost" href="/topics/${encodeURIComponent(String(topic.id))}" data-link>Open topic</a>
        <a class="button secondary" href="/requests?organization=${encodeURIComponent(String(topic.organization_id))}" data-link>Start request</a>
      </div>
    </article>
  `;
}

function renderTopicCompact(topic) {
  return `
    <article class="data-block">
      <h4>${escapeHtml(topic.title)}</h4>
      <p class="muted">${escapeHtml(topic.discipline)} · ${escapeHtml(formatDate(topic.application_deadline) || "Open")}</p>
      <a class="text-link" href="/topics/${encodeURIComponent(String(topic.id))}" data-link>Open topic</a>
    </article>
  `;
}

function renderRequestCard(request) {
  const organization = organizationById(request.organization_id);
  return `
    <article class="request-card" data-status="${escapeAttribute(request.status)}">
      <div class="card-top">
        <div>
          <p class="eyebrow">Request</p>
          <h3>${escapeHtml(request.title)}</h3>
        </div>
        <span class="badge ${statusBadgeClass(request.status)}">${escapeHtml(request.status)}</span>
      </div>
      <div class="pill-row">
        <span class="pill">${escapeHtml(organization?.name || "Unknown organization")}</span>
        <span class="pill">${escapeHtml(formatDate(request.preferred_start_on) || "Flexible start")}</span>
        <span class="pill">${escapeHtml(formatDateTime(request.created_at) || request.created_at || "-")}</span>
      </div>
      <p class="card-copy">${escapeHtml(request.message)}</p>
      <div class="request-actions">
        <button class="ghost" type="button" data-action="delete-request" data-request-id="${escapeAttribute(request.id)}">Delete</button>
        ${
          isAdmin()
            ? `
              <button class="secondary" type="button" data-action="set-request-status" data-request-id="${escapeAttribute(request.id)}" data-status="reviewing">Mark reviewing</button>
              <button class="secondary" type="button" data-action="set-request-status" data-request-id="${escapeAttribute(request.id)}" data-status="matched">Mark matched</button>
              <button class="secondary" type="button" data-action="set-request-status" data-request-id="${escapeAttribute(request.id)}" data-status="archived">Archive</button>
            `
            : ""
        }
      </div>
    </article>
  `;
}

function renderManagedUserCard(user) {
  const isCurrentUser = Number(user.id) === Number(state.account?.id);
  return `
    <article class="user-card">
      <div class="card-top">
        <div>
          <p class="eyebrow">Built-in user</p>
          <h3>${escapeHtml(user.email)}</h3>
        </div>
        <span class="badge ${user.email_verified ? "success" : "warning"}">${user.email_verified ? "Verified" : "Pending"}</span>
      </div>
      <div class="summary-grid">
        <article class="summary-item">
          <span>Role</span>
          <strong>${escapeHtml(user.role)}</strong>
        </article>
        <article class="summary-item">
          <span>Created</span>
          <strong>${escapeHtml(formatDateTime(user.created_at) || user.created_at || "-")}</strong>
        </article>
        <article class="summary-item">
          <span>Updated</span>
          <strong>${escapeHtml(formatDateTime(user.updated_at) || user.updated_at || "-")}</strong>
        </article>
      </div>
      <div class="inline-form">
        <label>
          <span>Role</span>
          <input id="adminUserRole-${escapeAttribute(user.id)}" type="text" value="${escapeAttribute(user.role)}">
        </label>
        <label>
          <span>Verification</span>
          <select id="adminUserVerified-${escapeAttribute(user.id)}">
            <option value="false"${user.email_verified ? "" : " selected"}>Pending verification</option>
            <option value="true"${user.email_verified ? " selected" : ""}>Verified</option>
          </select>
        </label>
      </div>
      <div class="request-actions">
        <button type="button" data-action="admin-user-save" data-user-id="${escapeAttribute(user.id)}">Save changes</button>
        <button class="secondary" type="button" data-action="admin-user-verify" data-user-id="${escapeAttribute(user.id)}">Resend verification</button>
        <button class="secondary" type="button" data-action="admin-user-reset" data-user-id="${escapeAttribute(user.id)}" data-user-email="${escapeAttribute(user.email)}">Send reset email</button>
        <button class="danger" type="button" data-action="admin-user-delete" data-user-id="${escapeAttribute(user.id)}"${isCurrentUser ? " disabled" : ""}>Delete user</button>
      </div>
    </article>
  `;
}

function renderCollection(items, renderItem, emptyMessage) {
  if (!items || items.length === 0) {
    return `
      <article class="empty-state">
        <strong>${escapeHtml(emptyMessage)}</strong>
      </article>
    `;
  }
  return items.map((item) => renderItem(item)).join("");
}

async function handleClick(event) {
  if (
    state.mobileNavOpen &&
    elements.siteHeader &&
    !elements.siteHeader.contains(event.target)
  ) {
    closeMobileNav();
  }

  const link = event.target.closest("a[data-link]");
  if (link) {
    const targetUrl = new URL(link.href, window.location.origin);
    if (
      targetUrl.origin === window.location.origin &&
      link.target !== "_blank" &&
      !event.metaKey &&
      !event.ctrlKey &&
      !event.shiftKey &&
      !event.altKey
    ) {
      event.preventDefault();
      navigate(`${targetUrl.pathname}${targetUrl.search}`);
      return;
    }
  }

  const actionTarget = event.target.closest("[data-action]");
  if (!actionTarget) {
    return;
  }

  const action = actionTarget.dataset.action;
  try {
    switch (action) {
      case "logout":
        await logoutUser();
        break;
      case "request-reset":
        await requestPasswordReset();
        break;
      case "resend-verification":
        await resendVerificationEmail();
        break;
      case "refresh-session":
        await refreshSession({ silent: false });
        await reloadCurrentRoute();
        setNotice("Session refreshed.", "success");
        break;
      case "delete-request":
        await deleteRequest(actionTarget.dataset.requestId);
        break;
      case "set-request-status":
        await updateRequestStatus(
          actionTarget.dataset.requestId,
          actionTarget.dataset.status,
        );
        break;
      case "load-demo":
        await loadDemoDataset();
        break;
      case "admin-user-save":
        await saveManagedUser(actionTarget.dataset.userId);
        break;
      case "admin-user-delete":
        await deleteManagedUser(actionTarget.dataset.userId);
        break;
      case "admin-user-verify":
        await resendManagedUserVerification(actionTarget.dataset.userId);
        break;
      case "admin-user-reset":
        await sendManagedUserReset(actionTarget.dataset.userEmail);
        break;
      default:
        break;
    }
  } catch (error) {
    setNotice(error.message || "That action could not be completed.", "error");
  }
}

async function handleSubmit(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  try {
    switch (form.id) {
      case "organizations-filter-form":
        event.preventDefault();
        submitOrganizationFilters(form);
        break;
      case "topics-filter-form":
        event.preventDefault();
        submitTopicFilters(form);
        break;
      case "account-auth-form":
        event.preventDefault();
        await submitAccountAuth(form, event.submitter);
        break;
      case "request-form":
        event.preventDefault();
        await submitCollaborationRequest(form);
        break;
      case "organization-form":
        event.preventDefault();
        await createOrganization(form);
        break;
      case "interest-form":
        event.preventDefault();
        await createInterest(form);
        break;
      case "topic-form":
        event.preventDefault();
        await createThesisTopic(form);
        break;
      case "admin-user-search-form":
        event.preventDefault();
        submitManagedUserSearch(form);
        break;
      case "admin-user-create-form":
        event.preventDefault();
        await createManagedUser(form);
        break;
      default:
        break;
    }
  } catch (error) {
    setNotice(error.message || "Form submission failed.", "error");
  }
}

function submitOrganizationFilters(form) {
  const params = new URLSearchParams();
  const q = form.elements.namedItem("q").value.trim();
  const country = form.elements.namedItem("country").value.trim();
  const interest = form.elements.namedItem("interest").value.trim();
  if (q) {
    params.set("q", q);
  }
  if (country) {
    params.set("country", country);
  }
  if (interest) {
    params.set("interest", interest);
  }
  const query = params.toString();
  navigate(query ? `/organizations?${query}` : "/organizations");
}

function submitTopicFilters(form) {
  const params = new URLSearchParams();
  const q = form.elements.namedItem("q").value.trim();
  const discipline = form.elements.namedItem("discipline").value.trim();
  const location = form.elements.namedItem("location").value.trim();
  if (q) {
    params.set("q", q);
  }
  if (discipline) {
    params.set("discipline", discipline);
  }
  if (location) {
    params.set("location", location);
  }
  const query = params.toString();
  navigate(query ? `/topics?${query}` : "/topics");
}

async function submitAccountAuth(form, submitter) {
  const intent = submitter?.value || "login";
  const email = form.elements.namedItem("email").value.trim();
  const password = form.elements.namedItem("password").value;

  if (!email || !password) {
    throw new Error("Email and password are required.");
  }

  if (intent === "register") {
    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setNotice(
      "Registration created. Verify the email before signing in. In local capture mode, open the newest email capture file.",
      "success",
    );
    return;
  }

  const payload = await apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  state.csrfToken = payload?.csrf_token || readCookie(CSRF_COOKIE_NAME) || "";
  await refreshSession({ silent: true });
  setNotice("Signed in successfully.", "success");
  navigate("/requests");
}

async function submitCollaborationRequest(form) {
  if (!state.currentUser) {
    throw new Error("Sign in before sending a collaboration request.");
  }

  const payload = {
    organization_id: Number(form.elements.namedItem("organization_id").value),
    title: form.elements.namedItem("title").value.trim(),
    message: form.elements.namedItem("message").value.trim(),
    status: "submitted",
    preferred_start_on:
      form.elements.namedItem("preferred_start_on").value || null,
  };

  if (!payload.organization_id || !payload.title || !payload.message) {
    throw new Error("Organization, title, and message are required.");
  }

  await apiFetch("/collaboration_request", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  setNotice("Collaboration request submitted.", "success");
  await reloadCurrentRoute();
}

async function createOrganization(form) {
  const payload = {
    slug: form.elements.namedItem("slug").value.trim(),
    name: form.elements.namedItem("name").value.trim(),
    country: form.elements.namedItem("country").value.trim(),
    city: form.elements.namedItem("city").value.trim(),
    website_url: form.elements.namedItem("website_url").value.trim(),
    contact_email: form.elements.namedItem("contact_email").value.trim(),
    collaboration_stage:
      form.elements.namedItem("collaboration_stage").value.trim(),
    summary: form.elements.namedItem("summary").value.trim(),
  };

  if (Object.values(payload).some((value) => !value)) {
    throw new Error("All organization fields are required.");
  }

  await apiFetch("/organization", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  invalidateOrganizationOptions();
  setNotice("Organization created.", "success");
  await reloadCurrentRoute();
}

async function createInterest(form) {
  const payload = {
    organization_id: Number(form.elements.namedItem("organization_id").value),
    title: form.elements.namedItem("title").value.trim(),
    work_mode: form.elements.namedItem("work_mode").value.trim(),
    desired_start_on:
      form.elements.namedItem("desired_start_on").value || null,
    summary: form.elements.namedItem("summary").value.trim(),
  };

  if (!payload.organization_id || !payload.title || !payload.work_mode || !payload.summary) {
    throw new Error("All interest fields except the start date are required.");
  }

  await apiFetch("/interest", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  setNotice("Interest signal created.", "success");
  await reloadCurrentRoute();
}

async function createThesisTopic(form) {
  const payload = {
    organization_id: Number(form.elements.namedItem("organization_id").value),
    title: form.elements.namedItem("title").value.trim(),
    discipline: form.elements.namedItem("discipline").value.trim(),
    location: form.elements.namedItem("location").value.trim(),
    contact_email: form.elements.namedItem("contact_email").value.trim(),
    application_deadline:
      form.elements.namedItem("application_deadline").value || null,
    summary: form.elements.namedItem("summary").value.trim(),
  };

  if (
    !payload.organization_id ||
    !payload.title ||
    !payload.discipline ||
    !payload.location ||
    !payload.contact_email ||
    !payload.summary
  ) {
    throw new Error("All thesis topic fields except the deadline are required.");
  }

  await apiFetch("/thesis_topic", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  setNotice("Thesis topic created.", "success");
  await reloadCurrentRoute();
}

function submitManagedUserSearch(form) {
  const email = form.elements.namedItem("email").value.trim();
  const params = new URLSearchParams();
  if (email) {
    params.set("email", email);
  }
  const query = params.toString();
  navigate(query ? `/admin/users?${query}` : "/admin/users");
}

async function createManagedUser(form) {
  const emailVerified =
    form.elements.namedItem("email_verified").value === "true";
  const payload = {
    email: form.elements.namedItem("email").value.trim(),
    password: form.elements.namedItem("password").value,
    role: form.elements.namedItem("role").value.trim(),
    email_verified: emailVerified,
    send_verification_email:
      !emailVerified &&
      form.elements.namedItem("send_verification_email").value === "true",
  };

  if (!payload.email || !payload.password || !payload.role) {
    throw new Error("Email, password, and role are required.");
  }

  await apiFetch("/auth/admin/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  setNotice(`Created ${payload.email}.`, "success");
  await reloadCurrentRoute();
}

async function saveManagedUser(userId) {
  const role = document.getElementById(`adminUserRole-${userId}`).value.trim();
  const emailVerified =
    document.getElementById(`adminUserVerified-${userId}`).value === "true";
  if (!role) {
    throw new Error("Role cannot be empty.");
  }

  await apiFetch(`/auth/admin/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    body: JSON.stringify({ role, email_verified: emailVerified }),
  });
  setNotice("User updated.", "success");
  await reloadCurrentRoute();
}

async function deleteManagedUser(userId) {
  if (!window.confirm("Delete this user and remove built-in auth access?")) {
    return;
  }

  await apiFetch(`/auth/admin/users/${encodeURIComponent(userId)}`, {
    method: "DELETE",
  });
  setNotice("User deleted.", "success");
  await reloadCurrentRoute();
}

async function resendManagedUserVerification(userId) {
  await apiFetch(`/auth/admin/users/${encodeURIComponent(userId)}/verification`, {
    method: "POST",
  });
  setNotice("Verification email queued.", "success");
}

async function sendManagedUserReset(email) {
  await apiFetch("/auth/password-reset/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  setNotice("Password reset email queued.", "success");
}

async function requestPasswordReset() {
  const emailField = document.getElementById("accountEmail");
  const email = emailField?.value.trim() || state.account?.email || "";
  if (!email) {
    throw new Error("Enter an email address first.");
  }

  await apiFetch("/auth/password-reset/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  setNotice(
    "If that account exists, a password reset link has been sent.",
    "success",
  );
}

async function resendVerificationEmail() {
  if (state.currentUser) {
    await apiFetch("/auth/account/verification", { method: "POST" });
  } else {
    const emailField = document.getElementById("accountEmail");
    const email = emailField?.value.trim() || "";
    if (!email) {
      throw new Error("Enter an email address first.");
    }
    await apiFetch("/auth/verification/resend", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }
  setNotice(
    "If the account is still unverified, a new verification link has been sent.",
    "success",
  );
}

async function logoutUser() {
  await apiFetch("/auth/logout", { method: "POST" });
  clearSession();
  setNotice("Logged out.", "success");
  navigate("/account");
}

async function deleteRequest(requestId) {
  if (!window.confirm("Delete this collaboration request?")) {
    return;
  }
  await apiFetch(`/collaboration_request/${encodeURIComponent(requestId)}`, {
    method: "DELETE",
  });
  setNotice("Request deleted.", "success");
  await reloadCurrentRoute();
}

async function updateRequestStatus(requestId, status) {
  const request = findRequestById(requestId);
  if (!request) {
    throw new Error("Request record could not be found.");
  }

  await apiFetch(`/collaboration_request/${encodeURIComponent(requestId)}`, {
    method: "PUT",
    body: JSON.stringify({
      organization_id: request.organization_id,
      title: request.title,
      message: request.message,
      status,
      preferred_start_on: request.preferred_start_on || null,
    }),
  });
  setNotice(`Request moved to ${status}.`, "success");
  await reloadCurrentRoute();
}

async function loadDemoDataset() {
  if (!isAdmin()) {
    throw new Error("Admin role is required to load demo data.");
  }

  await ensureOrganizationOptions();

  for (const organization of DEMO_DATA.organizations) {
    try {
      await apiFetch("/organization", {
        method: "POST",
        body: JSON.stringify(organization),
      });
    } catch (error) {
      if (!String(error.message).includes("duplicate")) {
        throw error;
      }
    }
  }

  invalidateOrganizationOptions();
  await ensureOrganizationOptions();

  for (const interest of DEMO_DATA.interests) {
    const organization = state.organizationOptions.find(
      (candidate) => candidate.slug === interest.organization_slug,
    );
    if (!organization) {
      continue;
    }
    try {
      await apiFetch("/interest", {
        method: "POST",
        body: JSON.stringify({
          organization_id: organization.id,
          title: interest.title,
          work_mode: interest.work_mode,
          desired_start_on: interest.desired_start_on,
          summary: interest.summary,
        }),
      });
    } catch (error) {
      if (!String(error.message).includes("duplicate")) {
        throw error;
      }
    }
  }

  for (const topic of DEMO_DATA.thesisTopics) {
    const organization = state.organizationOptions.find(
      (candidate) => candidate.slug === topic.organization_slug,
    );
    if (!organization) {
      continue;
    }
    try {
      await apiFetch("/thesis_topic", {
        method: "POST",
        body: JSON.stringify({
          organization_id: organization.id,
          title: topic.title,
          discipline: topic.discipline,
          location: topic.location,
          contact_email: topic.contact_email,
          application_deadline: topic.application_deadline,
          summary: topic.summary,
        }),
      });
    } catch (error) {
      if (!String(error.message).includes("duplicate")) {
        throw error;
      }
    }
  }

  setNotice("Demo dataset loaded.", "success");
  await reloadCurrentRoute();
}

async function reloadCurrentRoute() {
  await navigateToCurrentLocation({ preserveScroll: true });
}

async function refreshSession({ silent = false } = {}) {
  syncCsrfToken();

  try {
    const [currentUser, account] = await Promise.all([
      apiFetch("/auth/me"),
      apiFetch("/auth/account"),
    ]);
    state.currentUser = currentUser;
    state.account = account;
    syncHeader();
    return true;
  } catch (error) {
    clearSession();
    if (!silent && !isMissingTokenError(error)) {
      setNotice(error.message || "Could not refresh the session.", "error");
    }
    return false;
  }
}

function clearSession() {
  state.csrfToken = "";
  state.currentUser = null;
  state.account = null;
  syncHeader();
}

function syncHeader() {
  const activeKey = activeNavKey(state.route?.name || "home");
  for (const link of document.querySelectorAll("[data-nav]")) {
    link.classList.toggle("is-active", link.dataset.nav === activeKey);
  }

  const authenticated = Boolean(state.account);
  const admin = isAdmin();
  const sessionLabel = authenticated
    ? `${state.account.email} · ${state.account.role}`
    : "Guest session";
  const sessionHint = authenticated
    ? state.account.email_verified
      ? "Your account is verified and ready for collaboration workflows."
      : "Your account is signed in, but email verification is still pending."
    : "Browse the public catalog or open account tools to sign in.";

  elements.sessionChip.textContent = sessionLabel;
  elements.mobileSessionChip.textContent = sessionLabel;
  elements.sessionChip.classList.toggle("is-authenticated", authenticated);
  elements.mobileSessionChip.classList.toggle("is-authenticated", authenticated);
  elements.mobileSessionHint.textContent = sessionHint;

  elements.navAdminContent.hidden = !admin;
  elements.navAdminUsers.hidden = !admin;
  elements.mobileNavAdminContent.hidden = !admin;
  elements.mobileNavAdminUsers.hidden = !admin;
  elements.builtinAdminLink.hidden = !admin;
  elements.mobileBuiltinAdminLink.hidden = !admin;
  elements.portalLink.href = AUTH_PORTAL_URL;
  elements.mobilePortalLink.href = AUTH_PORTAL_URL;
  elements.accountShortcut.textContent = authenticated
    ? "Account workspace"
    : "Open account";
  elements.mobileAccountShortcut.textContent = authenticated
    ? "Workspace"
    : "Account";
  elements.mobileDrawerAccountButton.textContent = authenticated
    ? "Open account workspace"
    : "Open account";

  const mobileNavOpen = state.mobileNavOpen && isMobileShell();
  elements.siteHeader.classList.toggle("is-mobile-nav-open", mobileNavOpen);
  elements.mobileMenuButton.setAttribute(
    "aria-expanded",
    mobileNavOpen ? "true" : "false",
  );
  elements.mobileMenuButton.setAttribute(
    "aria-label",
    mobileNavOpen ? "Close navigation menu" : "Open navigation menu",
  );
  elements.mobileNavTray.hidden = !mobileNavOpen;
  document.body.classList.toggle("mobile-nav-open", mobileNavOpen);
}

function activeNavKey(routeName) {
  switch (routeName) {
    case "home":
      return "home";
    case "organizations":
    case "organization-detail":
      return "organizations";
    case "topics":
    case "topic-detail":
      return "topics";
    case "requests":
      return "requests";
    case "account":
      return "account";
    case "admin-content":
      return "admin-content";
    case "admin-users":
      return "admin-users";
    default:
      return "";
  }
}

function setNotice(message, kind = "info") {
  elements.noticeBar.textContent = message;
  elements.noticeBar.className = `notice-bar ${kind}`;
}

function syncCsrfToken() {
  state.csrfToken = readCookie(CSRF_COOKIE_NAME) || state.csrfToken;
}

function requestNeedsCsrf(method) {
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes(
    (method || "GET").toUpperCase(),
  );
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

  syncCsrfToken();

  const contentType = response.headers.get("content-type") || "";
  let payload = null;
  if (response.status !== 204 && response.status !== 205) {
    const text = await response.text();
    if (text) {
      payload = contentType.includes("application/json")
        ? JSON.parse(text)
        : text;
    }
  }

  if (!response.ok) {
    const message =
      typeof payload === "string"
        ? payload || `HTTP ${response.status}`
        : payload?.message || payload?.code || `HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.code = payload?.code || null;
    error.payload = payload;
    throw error;
  }

  return payload;
}

async function fetchOrganizations(filters = {}, options = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(options.limit || 24));
  params.set("sort", options.sort || "name");
  params.set("order", options.order || "asc");
  if (filters.name) {
    params.set("filter_name_contains", filters.name);
  }
  if (filters.country) {
    params.set("filter_country_contains", filters.country);
  }
  if (filters.slug) {
    params.set("filter_slug", filters.slug);
  }
  return apiFetch(buildListPath("/organization", params));
}

async function fetchInterests(filters = {}, options = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(options.limit || 24));
  params.set("sort", options.sort || "title");
  params.set("order", options.order || "asc");
  if (filters.title) {
    params.set("filter_title_contains", filters.title);
  }
  if (filters.organizationId) {
    params.set("filter_organization_id", String(filters.organizationId));
  }
  return apiFetch(buildListPath("/interest", params));
}

async function fetchTopics(filters = {}, options = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(options.limit || 24));
  params.set("sort", options.sort || "title");
  params.set("order", options.order || "asc");
  if (filters.title) {
    params.set("filter_title_contains", filters.title);
  }
  if (filters.discipline) {
    params.set("filter_discipline_contains", filters.discipline);
  }
  if (filters.location) {
    params.set("filter_location_contains", filters.location);
  }
  if (filters.organizationId) {
    params.set("filter_organization_id", String(filters.organizationId));
  }
  return apiFetch(buildListPath("/thesis_topic", params));
}

async function fetchRequests(options = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(options.limit || 50));
  params.set("sort", options.sort || "created_at");
  params.set("order", options.order || "desc");
  return apiFetch(buildListPath("/collaboration_request", params));
}

async function fetchManagedUsers(email = "") {
  const params = new URLSearchParams();
  if (email) {
    params.set("email", email);
  }
  return apiFetch(buildListPath("/auth/admin/users", params));
}

function buildListPath(basePath, params) {
  const search = params instanceof URLSearchParams ? params.toString() : new URLSearchParams(params).toString();
  return search ? `${basePath}?${search}` : basePath;
}

async function ensureOrganizationOptions() {
  if (state.organizationOptions.length > 0) {
    return;
  }
  const payload = await fetchOrganizations({}, { limit: 100, sort: "name", order: "asc" });
  state.organizationOptions = payload.items || [];
}

function invalidateOrganizationOptions() {
  state.organizationOptions = [];
}

function renderOrganizationOptions(selectedValue) {
  if (state.organizationOptions.length === 0) {
    return '<option value="">No organizations available</option>';
  }
  return state.organizationOptions
    .map((organization) => {
      const selected =
        String(selectedValue || "") === String(organization.id) ? " selected" : "";
      return `<option value="${escapeAttribute(organization.id)}"${selected}>${escapeHtml(organization.name)} (${escapeHtml(organization.country)})</option>`;
    })
    .join("");
}

function organizationById(id) {
  return state.organizationOptions.find(
    (organization) => Number(organization.id) === Number(id),
  );
}

function findRequestById(requestId) {
  const requestCollections = [
    state.view?.requests || [],
    state.view?.items || [],
  ];
  for (const collection of requestCollections) {
    const request = collection.find(
      (candidate) => Number(candidate.id) === Number(requestId),
    );
    if (request) {
      return request;
    }
  }
  return null;
}

function isAdmin() {
  return Boolean(state.account?.roles?.includes("admin"));
}

function isMissingTokenError(error) {
  return (
    error?.code === "missing_token" ||
    error?.code === "invalid_token" ||
    String(error?.message || "").toLowerCase().includes("missing token")
  );
}

function statusBadgeClass(status) {
  if (status === "matched") {
    return "success";
  }
  if (status === "reviewing") {
    return "";
  }
  if (status === "archived") {
    return "";
  }
  return "warning";
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
  return (
    document.cookie
      .split(";")
      .map((segment) => segment.trim())
      .find((segment) => segment.startsWith(`${name}=`))
      ?.slice(name.length + 1) || ""
  );
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
