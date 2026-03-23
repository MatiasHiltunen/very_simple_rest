const API_BASE = "/api";
const STORAGE_KEY = "vsr_family_atlas_state_v1";
const ASSIGNMENT_CATALOG = {
  template: [
    {
      name: "Guardian",
      scopes: ["Family"],
      summary: "Family-wide read, shopping contribution, and child-care management.",
    },
    {
      name: "Caregiver",
      scopes: ["Family"],
      summary: "Family-wide read, shopping contribution, and child-care read.",
    },
    {
      name: "ChildViewer",
      scopes: ["Family"],
      summary: "Family-wide read-only access.",
    },
    {
      name: "HouseholdModerator",
      scopes: ["Household"],
      summary: "Household-scoped calendar moderation with family read.",
    },
  ],
  permission: [
    {
      name: "FamilyRead",
      scopes: ["Family"],
      summary: "Read access to shared family resources.",
    },
    {
      name: "FamilyContribute",
      scopes: ["Family"],
      summary: "Family-scoped read, update, and delete for shared shopping items.",
    },
    {
      name: "ChildCareRead",
      scopes: ["Family"],
      summary: "Read child care plans and guardian notes.",
    },
    {
      name: "ChildCareManage",
      scopes: ["Family"],
      summary: "Read, update, and delete child care plans and guardian notes.",
    },
    {
      name: "HouseholdModerate",
      scopes: ["Household"],
      summary: "Household-scoped read, update, and delete for calendar events.",
    },
  ],
};

const state = {
  token: "",
  currentUser: null,
  families: [],
  selectedFamilyId: null,
  familyMembers: [],
  familyMembersError: "",
  households: [],
  householdsError: "",
  selectedHouseholdId: null,
  shoppingItems: [],
  shoppingError: "",
  calendarEvents: [],
  calendarError: "",
  adminUsers: [],
  adminUsersError: "",
  runtimeAssignments: [],
  runtimeAssignmentsError: "",
  runtimeEvents: [],
  runtimeEventsError: "",
  runtimeEvaluation: null,
  activity: [],
};

const refs = {
  statusBanner: document.getElementById("statusBanner"),
  sessionSummary: document.getElementById("sessionSummary"),
  selectedFamilyChip: document.getElementById("selectedFamilyChip"),
  selectedHouseholdChip: document.getElementById("selectedHouseholdChip"),
  tokenState: document.getElementById("tokenState"),
  sessionClaims: document.getElementById("sessionClaims"),
  activityLog: document.getElementById("activityLog"),
  authEmail: document.getElementById("authEmail"),
  authPassword: document.getElementById("authPassword"),
  loginBtn: document.getElementById("loginBtn"),
  refreshSessionBtn: document.getElementById("refreshSessionBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  familySlug: document.getElementById("familySlug"),
  familyName: document.getElementById("familyName"),
  familyTimezone: document.getElementById("familyTimezone"),
  familiesList: document.getElementById("familiesList"),
  reloadFamiliesBtn: document.getElementById("reloadFamiliesBtn"),
  memberFamilyPreview: document.getElementById("memberFamilyPreview"),
  memberUserId: document.getElementById("memberUserId"),
  memberDisplayName: document.getElementById("memberDisplayName"),
  memberRoleLabel: document.getElementById("memberRoleLabel"),
  memberIsChild: document.getElementById("memberIsChild"),
  familyMembersList: document.getElementById("familyMembersList"),
  reloadMembersBtn: document.getElementById("reloadMembersBtn"),
  householdFamilyPreview: document.getElementById("householdFamilyPreview"),
  householdSlug: document.getElementById("householdSlug"),
  householdLabel: document.getElementById("householdLabel"),
  householdTimezone: document.getElementById("householdTimezone"),
  householdsList: document.getElementById("householdsList"),
  reloadHouseholdsBtn: document.getElementById("reloadHouseholdsBtn"),
  shoppingHouseholdPreview: document.getElementById("shoppingHouseholdPreview"),
  shoppingTitle: document.getElementById("shoppingTitle"),
  shoppingCompleted: document.getElementById("shoppingCompleted"),
  shoppingList: document.getElementById("shoppingList"),
  reloadShoppingBtn: document.getElementById("reloadShoppingBtn"),
  calendarHouseholdPreview: document.getElementById("calendarHouseholdPreview"),
  calendarTitle: document.getElementById("calendarTitle"),
  calendarStartsAt: document.getElementById("calendarStartsAt"),
  calendarEndsAt: document.getElementById("calendarEndsAt"),
  calendarList: document.getElementById("calendarList"),
  reloadCalendarBtn: document.getElementById("reloadCalendarBtn"),
  reloadAdminUsersBtn: document.getElementById("reloadAdminUsersBtn"),
  adminUserSearch: document.getElementById("adminUserSearch"),
  adminUsersList: document.getElementById("adminUsersList"),
  assignmentUserId: document.getElementById("assignmentUserId"),
  assignmentKind: document.getElementById("assignmentKind"),
  assignmentName: document.getElementById("assignmentName"),
  assignmentScope: document.getElementById("assignmentScope"),
  assignmentScopeValue: document.getElementById("assignmentScopeValue"),
  assignmentExpiresAt: document.getElementById("assignmentExpiresAt"),
  runtimeAssignmentsList: document.getElementById("runtimeAssignmentsList"),
  runtimeEventsList: document.getElementById("runtimeEventsList"),
  reloadAssignmentsBtn: document.getElementById("reloadAssignmentsBtn"),
  evaluateUserId: document.getElementById("evaluateUserId"),
  evaluateResource: document.getElementById("evaluateResource"),
  evaluateAction: document.getElementById("evaluateAction"),
  evaluateScope: document.getElementById("evaluateScope"),
  evaluateScopeValue: document.getElementById("evaluateScopeValue"),
  runtimeEvaluateResult: document.getElementById("runtimeEvaluateResult"),
};

document.addEventListener("click", handleActionClick);
document.getElementById("registerForm").addEventListener("submit", handleRegister);
document.getElementById("familyCreateForm").addEventListener("submit", handleCreateFamily);
document.getElementById("familyMemberForm").addEventListener("submit", handleCreateFamilyMember);
document.getElementById("householdForm").addEventListener("submit", handleCreateHousehold);
document.getElementById("shoppingForm").addEventListener("submit", handleCreateShoppingItem);
document.getElementById("calendarForm").addEventListener("submit", handleCreateCalendarEvent);
document
  .getElementById("runtimeAssignmentForm")
  .addEventListener("submit", handleCreateRuntimeAssignment);
document
  .getElementById("runtimeEvaluateForm")
  .addEventListener("submit", handleEvaluateRuntimeAccess);
refs.loginBtn.addEventListener("click", handleLogin);
refs.refreshSessionBtn.addEventListener("click", () => {
  void refreshSession({ silent: false });
});
refs.logoutBtn.addEventListener("click", handleLogout);
refs.reloadFamiliesBtn.addEventListener("click", () => {
  void loadFamilies({ announce: true });
});
refs.reloadMembersBtn.addEventListener("click", () => {
  void loadFamilyMembers({ announce: true });
});
refs.reloadHouseholdsBtn.addEventListener("click", () => {
  void loadHouseholds({ announce: true });
});
refs.reloadShoppingBtn.addEventListener("click", () => {
  void loadShoppingItems({ announce: true });
});
refs.reloadCalendarBtn.addEventListener("click", () => {
  void loadCalendarEvents({ announce: true });
});
refs.reloadAdminUsersBtn.addEventListener("click", () => {
  void loadAdminUsers({ announce: true });
});
refs.reloadAssignmentsBtn.addEventListener("click", () => {
  void loadRuntimeAssignmentWorkspace({ announce: true });
});
refs.assignmentKind.addEventListener("change", syncAssignmentNameOptions);
refs.assignmentName.addEventListener("change", syncAssignmentScopeDefaults);
refs.assignmentScope.addEventListener("change", syncAssignmentScopeDefaults);
refs.evaluateScope.addEventListener("change", syncEvaluationScopeDefaults);
refs.adminUserSearch.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    void loadAdminUsers({ announce: true });
  }
});

bootstrap();

async function bootstrap() {
  loadPersistedState();
  seedDefaultDatetimes();
  syncAssignmentNameOptions();
  setBanner("Loading Family Atlas...", "info");
  pushActivity("The SPA booted and is checking for a stored bearer token.");
  renderAll();
  await refreshSession({ silent: true });
}

function loadPersistedState() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return;
    }
    const parsed = JSON.parse(raw);
    state.token = typeof parsed.token === "string" ? parsed.token : "";
    state.selectedFamilyId = toNullableInt(parsed.selectedFamilyId);
    state.selectedHouseholdId = toNullableInt(parsed.selectedHouseholdId);
  } catch (error) {
    console.warn("Failed to load Family Atlas state.", error);
  }
}

function persistState() {
  window.localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      token: state.token,
      selectedFamilyId: state.selectedFamilyId,
      selectedHouseholdId: state.selectedHouseholdId,
    }),
  );
}

function renderAll() {
  renderSession();
  renderActivity();
  renderFamilies();
  renderFamilyMembers();
  renderHouseholds();
  renderShoppingItems();
  renderCalendarEvents();
  renderAdminUsers();
  renderRuntimeAssignments();
  renderRuntimeEvents();
  renderRuntimeEvaluation();
  syncPreviews();
}

function setBanner(message, kind = "info") {
  refs.statusBanner.textContent = message;
  refs.statusBanner.className = `status-banner ${kind}`;
}

function pushActivity(message, kind = "info") {
  state.activity.unshift({
    id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`,
    message,
    kind,
    occurredAt: new Date().toISOString(),
  });
  state.activity = state.activity.slice(0, 18);
  renderActivity();
}

function renderActivity() {
  if (state.activity.length === 0) {
    refs.activityLog.innerHTML =
      '<div class="empty-state">Requests, selections, and policy hints will appear here.</div>';
    return;
  }

  refs.activityLog.innerHTML = state.activity
    .map(
      (entry) => `
        <article class="activity-entry ${entry.kind}">
          <strong>${escapeHtml(activityLabel(entry.kind))}</strong>
          <div>${escapeHtml(entry.message)}</div>
          <time datetime="${escapeHtml(entry.occurredAt)}">${escapeHtml(
            formatTimestamp(entry.occurredAt),
          )}</time>
        </article>
      `,
    )
    .join("");
}

function activityLabel(kind) {
  if (kind === "success") {
    return "Success";
  }
  if (kind === "error") {
    return "Error";
  }
  return "Event";
}

function renderSession() {
  if (!state.currentUser) {
    refs.sessionSummary.textContent = "No active session.";
    refs.selectedFamilyChip.textContent = "No family selected";
    refs.selectedFamilyChip.className = "chip muted";
    refs.selectedHouseholdChip.textContent = "No household selected";
    refs.selectedHouseholdChip.className = "chip muted";
    refs.tokenState.textContent = state.token ? "Stored token will be revalidated on refresh" : "No bearer token loaded";
    refs.sessionClaims.textContent = "Log in to inspect roles and the current session payload.";
    return;
  }

  const roles = Array.isArray(state.currentUser.roles) && state.currentUser.roles.length > 0
    ? state.currentUser.roles.join(", ")
    : "none";
  refs.sessionSummary.innerHTML = `
    <strong>User #${escapeHtml(state.currentUser.id)}</strong><br>
    Roles: ${escapeHtml(roles)}
  `;
  const selectedFamily = getSelectedFamily();
  const selectedHousehold = getSelectedHousehold();
  refs.selectedFamilyChip.textContent = selectedFamily
    ? `Family ${selectedFamily.id}: ${selectedFamily.name}`
    : "No family selected";
  refs.selectedFamilyChip.className = selectedFamily ? "chip active" : "chip muted";
  refs.selectedHouseholdChip.textContent = selectedHousehold
    ? `Household ${selectedHousehold.id}: ${selectedHousehold.label}`
    : "No household selected";
  refs.selectedHouseholdChip.className = selectedHousehold ? "chip active" : "chip muted";
  refs.tokenState.textContent = "Using bearer token from /api/auth/login";
  refs.sessionClaims.textContent = formatJson(state.currentUser);
}

function renderFamilies() {
  if (!state.currentUser) {
    refs.familiesList.innerHTML = '<div class="empty-state">Log in to load families.</div>';
    return;
  }
  if (state.families.length === 0) {
    refs.familiesList.innerHTML =
      '<div class="empty-state">No family rows are visible in this session yet.</div>';
    return;
  }

  refs.familiesList.innerHTML = state.families
    .map((family) => {
      const isSelected = Number(family.id) === Number(state.selectedFamilyId);
      return `
        <article class="card${isSelected ? " is-selected" : ""}">
          <header>
            <div>
              <h3>${escapeHtml(family.name)}</h3>
              <div class="meta-row">
                <span>ID ${escapeHtml(family.id)}</span>
                <span>owner ${escapeHtml(family.owner_user_id)}</span>
                <span>${escapeHtml(family.timezone)}</span>
              </div>
            </div>
          </header>
          <div class="meta-row">
            <span>slug ${escapeHtml(family.slug)}</span>
          </div>
          <div class="button-row">
            <button class="button ${isSelected ? "subtle" : "primary"}" type="button" data-action="select-family" data-family-id="${escapeHtml(family.id)}">
              ${isSelected ? "Selected" : "Use family"}
            </button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderFamilyMembers() {
  if (!state.currentUser) {
    refs.familyMembersList.innerHTML = '<div class="empty-state">Log in to inspect members.</div>';
    return;
  }
  if (state.familyMembersError) {
    refs.familyMembersList.innerHTML = renderErrorState(state.familyMembersError);
    return;
  }
  if (!state.selectedFamilyId) {
    refs.familyMembersList.innerHTML = '<div class="empty-state">Select a family to load members.</div>';
    return;
  }
  if (state.familyMembers.length === 0) {
    refs.familyMembersList.innerHTML =
      '<div class="empty-state">No visible membership rows for the selected family.</div>';
    return;
  }

  refs.familyMembersList.innerHTML = state.familyMembers
    .map((member) => `
      <article class="card">
        <header>
          <div>
            <h3>${escapeHtml(member.display_name)}</h3>
            <div class="meta-row">
              <span>user ${escapeHtml(member.user_id)}</span>
              <span>created by ${escapeHtml(member.created_by_user_id)}</span>
            </div>
          </div>
          <span class="badge${member.is_child ? " warning" : " success"}">
            ${member.is_child ? "child" : escapeHtml(member.role_label)}
          </span>
        </header>
        <div class="meta-row">
          <span>row ${escapeHtml(member.id)}</span>
          <span>family ${escapeHtml(member.family_id)}</span>
        </div>
      </article>
    `)
    .join("");
}

function renderHouseholds() {
  if (!state.currentUser) {
    refs.householdsList.innerHTML = '<div class="empty-state">Log in to inspect households.</div>';
    return;
  }
  if (state.householdsError) {
    refs.householdsList.innerHTML = renderErrorState(state.householdsError);
    return;
  }
  if (!state.selectedFamilyId) {
    refs.householdsList.innerHTML = '<div class="empty-state">Select a family first.</div>';
    return;
  }
  if (state.households.length === 0) {
    refs.householdsList.innerHTML =
      '<div class="empty-state">No household rows are visible for the selected family yet.</div>';
    return;
  }

  refs.householdsList.innerHTML = state.households
    .map((household) => {
      const isSelected = Number(household.id) === Number(state.selectedHouseholdId);
      return `
        <article class="card${isSelected ? " is-selected" : ""}">
          <header>
            <div>
              <h3>${escapeHtml(household.label)}</h3>
              <div class="meta-row">
                <span>ID ${escapeHtml(household.id)}</span>
                <span>family ${escapeHtml(household.family_id)}</span>
              </div>
            </div>
          </header>
          <div class="meta-row">
            <span>slug ${escapeHtml(household.slug)}</span>
            <span>${escapeHtml(household.timezone)}</span>
            <span>created by ${escapeHtml(household.created_by_user_id)}</span>
          </div>
          <div class="button-row">
            <button class="button ${isSelected ? "subtle" : "primary"}" type="button" data-action="select-household" data-household-id="${escapeHtml(household.id)}">
              ${isSelected ? "Selected" : "Use household"}
            </button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderShoppingItems() {
  if (!state.currentUser) {
    refs.shoppingList.innerHTML = '<div class="empty-state">Log in to inspect shopping items.</div>';
    return;
  }
  if (state.shoppingError) {
    refs.shoppingList.innerHTML = renderErrorState(state.shoppingError);
    return;
  }
  if (!state.selectedFamilyId) {
    refs.shoppingList.innerHTML = '<div class="empty-state">Select a family or household to load shopping items.</div>';
    return;
  }
  if (state.shoppingItems.length === 0) {
    refs.shoppingList.innerHTML =
      '<div class="empty-state">No visible shopping items for the current selection yet.</div>';
    return;
  }

  refs.shoppingList.innerHTML = state.shoppingItems
    .map((item) => `
      <article class="card${item.completed ? " is-selected" : ""}">
        <header>
          <div>
            <h3>${escapeHtml(item.title)}</h3>
            <div class="meta-row">
              <span>row ${escapeHtml(item.id)}</span>
              <span>family ${escapeHtml(item.family_id)}</span>
              <span>household ${escapeHtml(item.household_id)}</span>
            </div>
          </div>
          <span class="badge${item.completed ? " success" : ""}">
            ${item.completed ? "completed" : "open"}
          </span>
        </header>
        <div class="meta-row">
          <span>created by ${escapeHtml(item.created_by_user_id)}</span>
        </div>
        <div class="button-row">
          <button class="button secondary" type="button" data-action="toggle-shopping" data-item-id="${escapeHtml(item.id)}">
            ${item.completed ? "Mark open" : "Mark done"}
          </button>
          <button class="button danger" type="button" data-action="delete-shopping" data-item-id="${escapeHtml(item.id)}">
            Delete
          </button>
        </div>
      </article>
    `)
    .join("");
}

function renderCalendarEvents() {
  if (!state.currentUser) {
    refs.calendarList.innerHTML = '<div class="empty-state">Log in to inspect events.</div>';
    return;
  }
  if (state.calendarError) {
    refs.calendarList.innerHTML = renderErrorState(state.calendarError);
    return;
  }
  if (!state.selectedHouseholdId) {
    refs.calendarList.innerHTML = '<div class="empty-state">Select a household to load events.</div>';
    return;
  }
  if (state.calendarEvents.length === 0) {
    refs.calendarList.innerHTML =
      '<div class="empty-state">No visible calendar events for the selected household.</div>';
    return;
  }

  refs.calendarList.innerHTML = state.calendarEvents
    .map((event) => `
      <article class="card">
        <header>
          <div>
            <h3>${escapeHtml(event.title)}</h3>
            <div class="meta-row">
              <span>row ${escapeHtml(event.id)}</span>
              <span>created by ${escapeHtml(event.created_by_user_id)}</span>
            </div>
          </div>
          <span class="badge success">${escapeHtml(formatDateRange(event.starts_at, event.ends_at))}</span>
        </header>
        <div class="meta-row">
          <span>family ${escapeHtml(event.family_id)}</span>
          <span>household ${escapeHtml(event.household_id)}</span>
        </div>
        <div class="button-row">
          <button class="button danger" type="button" data-action="delete-calendar" data-event-id="${escapeHtml(event.id)}">
            Delete
          </button>
        </div>
      </article>
    `)
    .join("");
}

function renderAdminUsers() {
  if (!state.currentUser || !isAdmin()) {
    refs.adminUsersList.innerHTML =
      '<div class="empty-state">Admin login required to list users and manage runtime assignments.</div>';
    return;
  }
  if (state.adminUsersError) {
    refs.adminUsersList.innerHTML = renderErrorState(state.adminUsersError);
    return;
  }
  if (state.adminUsers.length === 0) {
    refs.adminUsersList.innerHTML =
      '<div class="empty-state">Load the user directory to target membership and runtime grants.</div>';
    return;
  }

  refs.adminUsersList.innerHTML = state.adminUsers
    .map((user) => {
      const roleList = Array.isArray(user.roles) && user.roles.length > 0 ? user.roles.join(", ") : user.role;
      return `
        <article class="card">
          <header>
            <div>
              <h3>${escapeHtml(user.email)}</h3>
              <div class="meta-row">
                <span>ID ${escapeHtml(user.id)}</span>
                <span>${escapeHtml(roleList || "user")}</span>
              </div>
            </div>
            ${user.email_verified ? '<span class="badge success">verified</span>' : '<span class="badge warning">unverified</span>'}
          </header>
          <div class="button-row">
            <button class="button ghost" type="button" data-action="seed-member-user" data-user-id="${escapeHtml(user.id)}" data-display-name="${escapeHtml(user.email.split("@")[0])}">
              Member target
            </button>
            <button class="button ghost" type="button" data-action="seed-runtime-user" data-user-id="${escapeHtml(user.id)}">
              Runtime target
            </button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderRuntimeAssignments() {
  if (!state.currentUser || !isAdmin()) {
    refs.runtimeAssignmentsList.innerHTML =
      '<div class="empty-state">Admin login required to inspect runtime assignments.</div>';
    return;
  }
  if (state.runtimeAssignmentsError) {
    refs.runtimeAssignmentsList.innerHTML = renderErrorState(state.runtimeAssignmentsError);
    return;
  }
  if (state.runtimeAssignments.length === 0) {
    refs.runtimeAssignmentsList.innerHTML =
      '<div class="empty-state">No runtime assignments loaded for the current user target.</div>';
    return;
  }

  refs.runtimeAssignmentsList.innerHTML = state.runtimeAssignments
    .map((assignment) => `
      <article class="card">
        <header>
          <div>
            <h3>${escapeHtml(renderAssignmentTarget(assignment.target))}</h3>
            <div class="meta-row">
              <span>${escapeHtml(assignment.scope.scope)} ${escapeHtml(assignment.scope.value)}</span>
              <span>user ${escapeHtml(assignment.user_id)}</span>
            </div>
          </div>
          ${assignment.expires_at ? '<span class="badge warning">expires</span>' : '<span class="badge success">active</span>'}
        </header>
        <div class="meta-row">
          <span>created ${escapeHtml(formatTimestamp(assignment.created_at))}</span>
          <span>by ${escapeHtml(assignment.created_by_user_id ?? "n/a")}</span>
          ${
            assignment.expires_at
              ? `<span>until ${escapeHtml(formatTimestamp(assignment.expires_at))}</span>`
              : ""
          }
        </div>
        <div class="button-row">
          <button class="button warning" type="button" data-action="revoke-assignment" data-assignment-id="${escapeHtml(assignment.id)}">
            Revoke now
          </button>
          <button class="button ghost" type="button" data-action="renew-assignment" data-assignment-id="${escapeHtml(assignment.id)}">
            Renew 30d
          </button>
          <button class="button danger" type="button" data-action="delete-assignment" data-assignment-id="${escapeHtml(assignment.id)}">
            Delete
          </button>
        </div>
      </article>
    `)
    .join("");
}

function renderRuntimeEvents() {
  if (!state.currentUser || !isAdmin()) {
    refs.runtimeEventsList.innerHTML =
      '<div class="empty-state">Admin login required to inspect runtime event history.</div>';
    return;
  }
  if (state.runtimeEventsError) {
    refs.runtimeEventsList.innerHTML = renderErrorState(state.runtimeEventsError);
    return;
  }
  if (state.runtimeEvents.length === 0) {
    refs.runtimeEventsList.innerHTML =
      '<div class="empty-state">No runtime assignment history loaded.</div>';
    return;
  }

  refs.runtimeEventsList.innerHTML = state.runtimeEvents
    .map((event) => `
      <article class="card">
        <header>
          <div>
            <h3>${escapeHtml(event.event)}</h3>
            <div class="meta-row">
              <span>${escapeHtml(renderAssignmentTarget(event.target))}</span>
              <span>${escapeHtml(event.scope.scope)} ${escapeHtml(event.scope.value)}</span>
            </div>
          </div>
          <span class="badge">${escapeHtml(formatTimestamp(event.occurred_at))}</span>
        </header>
        <div class="meta-row">
          <span>assignment ${escapeHtml(event.assignment_id)}</span>
          <span>user ${escapeHtml(event.user_id)}</span>
          <span>actor ${escapeHtml(event.actor_user_id ?? "n/a")}</span>
          ${event.reason ? `<span>reason ${escapeHtml(event.reason)}</span>` : ""}
        </div>
      </article>
    `)
    .join("");
}

function renderRuntimeEvaluation() {
  refs.runtimeEvaluateResult.textContent = state.runtimeEvaluation
    ? formatJson(state.runtimeEvaluation)
    : "No runtime evaluation yet.";
}

function syncPreviews() {
  const family = getSelectedFamily();
  const household = getSelectedHousehold();
  refs.memberFamilyPreview.value = family ? `#${family.id} ${family.name}` : "No family selected";
  refs.householdFamilyPreview.value = family ? `#${family.id} ${family.name}` : "No family selected";
  refs.shoppingHouseholdPreview.value = household
    ? `#${household.id} ${household.label}`
    : family
      ? `Family #${family.id} scope`
      : "No household selected";
  refs.calendarHouseholdPreview.value = household
    ? `#${household.id} ${household.label}`
    : "No household selected";

  syncAssignmentScopeDefaults();
  syncEvaluationScopeDefaults();
}

function syncAssignmentNameOptions() {
  const kind = refs.assignmentKind.value === "permission" ? "permission" : "template";
  const catalog = ASSIGNMENT_CATALOG[kind];
  const currentValue = refs.assignmentName.value;
  refs.assignmentName.innerHTML = catalog
    .map((entry) => `<option value="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}</option>`)
    .join("");
  if (catalog.some((entry) => entry.name === currentValue)) {
    refs.assignmentName.value = currentValue;
  }
  syncAssignmentScopeDefaults();
}

function syncAssignmentScopeDefaults() {
  const kind = refs.assignmentKind.value === "permission" ? "permission" : "template";
  const entry = ASSIGNMENT_CATALOG[kind].find((candidate) => candidate.name === refs.assignmentName.value);
  if (entry && entry.scopes.length === 1) {
    refs.assignmentScope.value = entry.scopes[0];
  }
  const selectedScope = refs.assignmentScope.value;
  if (!refs.assignmentScopeValue.value) {
    if (selectedScope === "Household" && state.selectedHouseholdId) {
      refs.assignmentScopeValue.value = String(state.selectedHouseholdId);
    } else if (selectedScope === "Family" && state.selectedFamilyId) {
      refs.assignmentScopeValue.value = String(state.selectedFamilyId);
    }
  }
}

function syncEvaluationScopeDefaults() {
  const selectedScope = refs.evaluateScope.value;
  if (!refs.evaluateScopeValue.value) {
    if (selectedScope === "Household" && state.selectedHouseholdId) {
      refs.evaluateScopeValue.value = String(state.selectedHouseholdId);
    } else if (selectedScope === "Family" && state.selectedFamilyId) {
      refs.evaluateScopeValue.value = String(state.selectedFamilyId);
    }
  }
}

async function handleRegister(event) {
  event.preventDefault();
  const email = refs.authEmail.value.trim();
  const password = refs.authPassword.value;
  if (!email || !password) {
    setBanner("Email and password are required.", "error");
    return;
  }

  try {
    await apiFetch("/auth/register", {
      method: "POST",
      body: { email, password },
    });
    setBanner("Registration succeeded. Log in with the same credentials.", "success");
    pushActivity(`Registered ${email}.`, "success");
  } catch (error) {
    handleRequestError(`Registration failed for ${email}.`, error);
  }
}

async function handleLogin() {
  const email = refs.authEmail.value.trim();
  const password = refs.authPassword.value;
  if (!email || !password) {
    setBanner("Email and password are required.", "error");
    return;
  }

  try {
    const response = await apiFetch("/auth/login", {
      method: "POST",
      body: { email, password },
    });
    state.token = response.token || "";
    persistState();
    pushActivity(`Logged in as ${email}.`, "success");
    setBanner("Login succeeded. Loading your workspace...", "success");
    await refreshSession({ silent: true });
  } catch (error) {
    handleRequestError(`Login failed for ${email}.`, error);
  }
}

async function handleLogout() {
  if (!state.token) {
    clearSession();
    setBanner("Local session cleared.", "info");
    return;
  }

  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch (error) {
    pushActivity(`Logout endpoint returned an error: ${error.message}`, "error");
  }

  clearSession();
  setBanner("Logged out and cleared the stored bearer token.", "success");
  pushActivity("Logged out.", "success");
}

async function refreshSession({ silent = false } = {}) {
  if (!state.token) {
    clearSession({ preserveActivity: true });
    if (!silent) {
      setBanner("No bearer token stored. Register or log in to continue.", "info");
    }
    return;
  }

  try {
    state.currentUser = await apiFetch("/auth/me");
    if (!silent) {
      setBanner("Session refreshed.", "success");
    }
    await loadWorkspace({ announce: !silent });
  } catch (error) {
    clearSession({ preserveActivity: true });
    handleRequestError("Session refresh failed.", error);
  }
}

function clearSession({ preserveActivity = false } = {}) {
  state.token = "";
  state.currentUser = null;
  state.families = [];
  state.familyMembers = [];
  state.households = [];
  state.shoppingItems = [];
  state.calendarEvents = [];
  state.adminUsers = [];
  state.runtimeAssignments = [];
  state.runtimeEvents = [];
  state.runtimeEvaluation = null;
  state.selectedFamilyId = null;
  state.selectedHouseholdId = null;
  if (!preserveActivity) {
    state.activity = [];
  }
  persistState();
  renderAll();
}

async function loadWorkspace({ announce = false } = {}) {
  await loadFamilies({ announce });
  if (state.selectedFamilyId) {
    await loadFamilyMembers();
    await loadHouseholds();
    await loadShoppingItems();
  } else {
    state.familyMembers = [];
    state.households = [];
    state.shoppingItems = [];
    state.calendarEvents = [];
    state.familyMembersError = "";
    state.householdsError = "";
    state.shoppingError = "";
    state.calendarError = "";
  }
  await loadCalendarEvents();
  if (isAdmin()) {
    await loadAdminUsers();
  } else {
    state.adminUsers = [];
    state.runtimeAssignments = [];
    state.runtimeEvents = [];
    state.adminUsersError = "";
    state.runtimeAssignmentsError = "";
    state.runtimeEventsError = "";
  }
  renderAll();
}

async function loadFamilies({ announce = false } = {}) {
  if (!state.currentUser) {
    return;
  }

  try {
    const response = await apiFetch("/family?sort=name&order=asc");
    state.families = Array.isArray(response.items) ? response.items : [];
    state.selectedFamilyId = pickFamilySelection(state.families);
    persistState();
    if (announce) {
      setBanner(`Loaded ${state.families.length} family rows.`, "success");
    }
    pushActivity(`Loaded ${state.families.length} family rows.`, "info");
  } catch (error) {
    state.families = [];
    handleRequestError("Failed to load families.", error);
  }
  renderFamilies();
  syncPreviews();
}

function pickFamilySelection(families) {
  if (families.length === 0) {
    return null;
  }
  const selected = families.find((family) => Number(family.id) === Number(state.selectedFamilyId));
  if (selected) {
    return Number(selected.id);
  }
  return Number(families[0].id);
}

async function loadFamilyMembers({ announce = false } = {}) {
  if (!state.selectedFamilyId) {
    state.familyMembers = [];
    state.familyMembersError = "";
    renderFamilyMembers();
    return;
  }
  try {
    const response = await apiFetch(`/family/${state.selectedFamilyId}/family_member?sort=display_name&order=asc`);
    state.familyMembers = Array.isArray(response.items) ? response.items : [];
    state.familyMembersError = "";
    if (announce) {
      setBanner(`Loaded ${state.familyMembers.length} visible family members.`, "success");
    }
  } catch (error) {
    state.familyMembers = [];
    state.familyMembersError = error.message;
    if (announce) {
      setBanner(`Family member load failed: ${error.message}`, "error");
    }
  }
  renderFamilyMembers();
}

async function loadHouseholds({ announce = false } = {}) {
  if (!state.selectedFamilyId) {
    state.households = [];
    state.householdsError = "";
    renderHouseholds();
    return;
  }
  try {
    const response = await apiFetch(`/family/${state.selectedFamilyId}/household?sort=label&order=asc`);
    state.households = Array.isArray(response.items) ? response.items : [];
    state.householdsError = "";
    state.selectedHouseholdId = pickHouseholdSelection(state.households);
    persistState();
    if (announce) {
      setBanner(`Loaded ${state.households.length} visible households.`, "success");
    }
  } catch (error) {
    state.households = [];
    state.selectedHouseholdId = null;
    state.householdsError = error.message;
    if (announce) {
      setBanner(`Household load failed: ${error.message}`, "error");
    }
  }
  renderHouseholds();
  syncPreviews();
}

function pickHouseholdSelection(households) {
  if (households.length === 0) {
    return null;
  }
  const selected = households.find(
    (household) => Number(household.id) === Number(state.selectedHouseholdId),
  );
  if (selected) {
    return Number(selected.id);
  }
  return Number(households[0].id);
}

async function loadShoppingItems({ announce = false } = {}) {
  if (!state.selectedFamilyId) {
    state.shoppingItems = [];
    state.shoppingError = "";
    renderShoppingItems();
    return;
  }

  const path = state.selectedHouseholdId
    ? `/household/${state.selectedHouseholdId}/shopping_item?sort=title&order=asc`
    : `/family/${state.selectedFamilyId}/shopping_item?sort=title&order=asc`;

  try {
    const response = await apiFetch(path);
    state.shoppingItems = Array.isArray(response.items) ? response.items : [];
    state.shoppingError = "";
    if (announce) {
      setBanner(`Loaded ${state.shoppingItems.length} shopping items.`, "success");
    }
  } catch (error) {
    state.shoppingItems = [];
    state.shoppingError = error.message;
    if (announce) {
      setBanner(`Shopping load failed: ${error.message}`, "error");
    }
  }
  renderShoppingItems();
}

async function loadCalendarEvents({ announce = false } = {}) {
  if (!state.selectedHouseholdId) {
    state.calendarEvents = [];
    state.calendarError = "";
    renderCalendarEvents();
    return;
  }
  try {
    const response = await apiFetch(`/household/${state.selectedHouseholdId}/calendar_event?sort=starts_at&order=asc`);
    state.calendarEvents = Array.isArray(response.items) ? response.items : [];
    state.calendarError = "";
    if (announce) {
      setBanner(`Loaded ${state.calendarEvents.length} calendar events.`, "success");
    }
  } catch (error) {
    state.calendarEvents = [];
    state.calendarError = error.message;
    if (announce) {
      setBanner(`Calendar load failed: ${error.message}`, "error");
    }
  }
  renderCalendarEvents();
}

async function loadAdminUsers({ announce = false } = {}) {
  if (!isAdmin()) {
    return;
  }
  const query = new URLSearchParams();
  query.set("limit", "50");
  if (refs.adminUserSearch.value.trim()) {
    query.set("email", refs.adminUserSearch.value.trim());
  }
  try {
    const response = await apiFetch(`/auth/admin/users?${query.toString()}`);
    state.adminUsers = Array.isArray(response.items) ? response.items : [];
    state.adminUsersError = "";
    if (announce) {
      setBanner(`Loaded ${state.adminUsers.length} auth users.`, "success");
    }
  } catch (error) {
    state.adminUsers = [];
    state.adminUsersError = error.message;
    if (announce) {
      setBanner(`Admin user load failed: ${error.message}`, "error");
    }
  }
  renderAdminUsers();
}

async function loadRuntimeAssignmentWorkspace({ announce = false } = {}) {
  if (!isAdmin()) {
    return;
  }
  const userId = toNullableInt(refs.assignmentUserId.value || refs.evaluateUserId.value);
  if (!userId) {
    setBanner("Choose a user ID before loading runtime assignments.", "error");
    return;
  }
  refs.assignmentUserId.value = userId;
  refs.evaluateUserId.value = userId;
  await Promise.all([loadRuntimeAssignments(userId, announce), loadRuntimeEvents(userId, announce)]);
}

async function loadRuntimeAssignments(userId, announce = false) {
  try {
    const response = await apiFetch(`/authz/runtime/assignments?user_id=${encodeURIComponent(userId)}`);
    state.runtimeAssignments = Array.isArray(response) ? response : [];
    state.runtimeAssignmentsError = "";
    if (announce) {
      setBanner(`Loaded ${state.runtimeAssignments.length} runtime assignments.`, "success");
    }
  } catch (error) {
    state.runtimeAssignments = [];
    state.runtimeAssignmentsError = error.message;
    if (announce) {
      setBanner(`Runtime assignment load failed: ${error.message}`, "error");
    }
  }
  renderRuntimeAssignments();
}

async function loadRuntimeEvents(userId, announce = false) {
  try {
    const response = await apiFetch(`/authz/runtime/assignment-events?user_id=${encodeURIComponent(userId)}`);
    state.runtimeEvents = Array.isArray(response) ? response : [];
    state.runtimeEventsError = "";
    if (announce) {
      setBanner(`Loaded ${state.runtimeEvents.length} assignment events.`, "success");
    }
  } catch (error) {
    state.runtimeEvents = [];
    state.runtimeEventsError = error.message;
    if (announce) {
      setBanner(`Runtime event load failed: ${error.message}`, "error");
    }
  }
  renderRuntimeEvents();
}

async function handleCreateFamily(event) {
  event.preventDefault();
  if (!state.currentUser) {
    setBanner("Log in before creating a family.", "error");
    return;
  }

  try {
    const created = await apiFetch("/family", {
      method: "POST",
      body: {
        slug: refs.familySlug.value.trim(),
        name: refs.familyName.value.trim(),
        timezone: refs.familyTimezone.value.trim(),
      },
    });
    refs.familySlug.value = "";
    refs.familyName.value = "";
    state.selectedFamilyId = toNullableInt(created.id);
    persistState();
    setBanner("Family created. Add members immediately, then use runtime templates for elevated access.", "success");
    pushActivity(`Created family ${created.name} (#${created.id}).`, "success");
    await loadFamilies();
    await Promise.all([loadFamilyMembers(), loadHouseholds(), loadShoppingItems()]);
  } catch (error) {
    handleRequestError("Family creation failed.", error);
  }
}

async function handleCreateFamilyMember(event) {
  event.preventDefault();
  if (!state.selectedFamilyId) {
    setBanner("Select a family before adding members.", "error");
    return;
  }
  try {
    const created = await apiFetch("/family_member", {
      method: "POST",
      body: {
        family_id: state.selectedFamilyId,
        user_id: Number(refs.memberUserId.value),
        role_label: refs.memberRoleLabel.value,
        display_name: refs.memberDisplayName.value.trim(),
        is_child: refs.memberIsChild.checked,
      },
    });
    refs.memberUserId.value = "";
    refs.memberDisplayName.value = "";
    refs.memberIsChild.checked = false;
    setBanner("Family member created.", "success");
    pushActivity(
      `Created family member row for user ${created.user_id} in family ${created.family_id}.`,
      "success",
    );
    await loadFamilyMembers();
  } catch (error) {
    handleRequestError("Family member creation failed.", error);
  }
}

async function handleCreateHousehold(event) {
  event.preventDefault();
  if (!state.selectedFamilyId) {
    setBanner("Select a family before creating a household.", "error");
    return;
  }
  try {
    const created = await apiFetch("/household", {
      method: "POST",
      body: {
        family_id: state.selectedFamilyId,
        slug: refs.householdSlug.value.trim(),
        label: refs.householdLabel.value.trim(),
        timezone: refs.householdTimezone.value.trim(),
      },
    });
    refs.householdSlug.value = "";
    refs.householdLabel.value = "";
    state.selectedHouseholdId = toNullableInt(created.id);
    persistState();
    setBanner("Household created for the selected family.", "success");
    pushActivity(`Created household ${created.label} (#${created.id}).`, "success");
    await loadHouseholds();
    await Promise.all([loadShoppingItems(), loadCalendarEvents()]);
  } catch (error) {
    handleRequestError("Household creation failed.", error);
  }
}

async function handleCreateShoppingItem(event) {
  event.preventDefault();
  if (!state.selectedFamilyId || !state.selectedHouseholdId) {
    setBanner("Select both a family and a household before creating shopping items.", "error");
    return;
  }
  try {
    const created = await apiFetch("/shopping_item", {
      method: "POST",
      body: {
        family_id: state.selectedFamilyId,
        household_id: state.selectedHouseholdId,
        title: refs.shoppingTitle.value.trim(),
        completed: refs.shoppingCompleted.checked,
      },
    });
    refs.shoppingTitle.value = "";
    refs.shoppingCompleted.checked = false;
    setBanner("Shopping item created.", "success");
    pushActivity(`Created shopping item "${created.title}" (#${created.id}).`, "success");
    await loadShoppingItems();
  } catch (error) {
    handleRequestError("Shopping item creation failed.", error);
  }
}

async function handleCreateCalendarEvent(event) {
  event.preventDefault();
  if (!state.selectedFamilyId || !state.selectedHouseholdId) {
    setBanner("Select both a family and a household before creating calendar events.", "error");
    return;
  }
  try {
    const created = await apiFetch("/calendar_event", {
      method: "POST",
      body: {
        family_id: state.selectedFamilyId,
        household_id: state.selectedHouseholdId,
        title: refs.calendarTitle.value.trim(),
        starts_at: localInputToIso(refs.calendarStartsAt.value),
        ends_at: localInputToIso(refs.calendarEndsAt.value),
      },
    });
    refs.calendarTitle.value = "";
    seedDefaultDatetimes();
    setBanner("Calendar event created.", "success");
    pushActivity(`Created calendar event "${created.title}" (#${created.id}).`, "success");
    await loadCalendarEvents();
  } catch (error) {
    handleRequestError("Calendar event creation failed.", error);
  }
}

async function handleCreateRuntimeAssignment(event) {
  event.preventDefault();
  if (!isAdmin()) {
    setBanner("Admin login required to create runtime assignments.", "error");
    return;
  }

  const payload = {
    user_id: Number(refs.assignmentUserId.value),
    target: {
      kind: refs.assignmentKind.value,
      name: refs.assignmentName.value,
    },
    scope: {
      scope: refs.assignmentScope.value,
      value: refs.assignmentScopeValue.value.trim(),
    },
  };
  if (refs.assignmentExpiresAt.value) {
    payload.expires_at = localInputToIso(refs.assignmentExpiresAt.value);
  }

  try {
    const created = await apiFetch("/authz/runtime/assignments", {
      method: "POST",
      body: payload,
    });
    setBanner("Runtime assignment created.", "success");
    pushActivity(
      `Created ${renderAssignmentTarget(created.target)} for user ${created.user_id} at ${created.scope.scope} ${created.scope.value}.`,
      "success",
    );
    await loadRuntimeAssignmentWorkspace();
  } catch (error) {
    handleRequestError("Runtime assignment creation failed.", error);
  }
}

async function handleEvaluateRuntimeAccess(event) {
  event.preventDefault();
  if (!isAdmin()) {
    setBanner("Admin login required to evaluate runtime access.", "error");
    return;
  }

  try {
    state.runtimeEvaluation = await apiFetch("/authz/runtime/evaluate", {
      method: "POST",
      body: {
        resource: refs.evaluateResource.value,
        action: refs.evaluateAction.value,
        scope: {
          scope: refs.evaluateScope.value,
          value: refs.evaluateScopeValue.value.trim(),
        },
        user_id: Number(refs.evaluateUserId.value),
      },
    });
    renderRuntimeEvaluation();
    setBanner("Runtime access evaluated.", "success");
    pushActivity(
      `Evaluated runtime access for user ${refs.evaluateUserId.value} on ${refs.evaluateResource.value}/${refs.evaluateAction.value}.`,
      "success",
    );
  } catch (error) {
    state.runtimeEvaluation = { error: error.message };
    renderRuntimeEvaluation();
    handleRequestError("Runtime access evaluation failed.", error);
  }
}

async function handleActionClick(event) {
  const actionTarget = event.target.closest("[data-action]");
  if (!actionTarget) {
    return;
  }

  const { action } = actionTarget.dataset;
  if (action === "select-family") {
    state.selectedFamilyId = Number(actionTarget.dataset.familyId);
    state.selectedHouseholdId = null;
    persistState();
    syncPreviews();
    renderFamilies();
    renderHouseholds();
    renderShoppingItems();
    renderCalendarEvents();
    pushActivity(`Selected family ${state.selectedFamilyId}.`);
    await loadFamilyMembers();
    await loadHouseholds();
    await loadShoppingItems();
    await loadCalendarEvents();
    return;
  }

  if (action === "select-household") {
    state.selectedHouseholdId = Number(actionTarget.dataset.householdId);
    persistState();
    syncPreviews();
    renderHouseholds();
    pushActivity(`Selected household ${state.selectedHouseholdId}.`);
    await Promise.all([loadShoppingItems(), loadCalendarEvents()]);
    return;
  }

  if (action === "seed-member-user") {
    refs.memberUserId.value = actionTarget.dataset.userId || "";
    if (!refs.memberDisplayName.value && actionTarget.dataset.displayName) {
      refs.memberDisplayName.value = actionTarget.dataset.displayName;
    }
    setBanner("Copied the selected user ID into the family member form.", "info");
    return;
  }

  if (action === "seed-runtime-user") {
    const userId = actionTarget.dataset.userId || "";
    refs.assignmentUserId.value = userId;
    refs.evaluateUserId.value = userId;
    setBanner("Copied the selected user ID into the runtime authz forms.", "info");
    return;
  }

  if (action === "toggle-shopping") {
    await toggleShoppingItem(Number(actionTarget.dataset.itemId));
    return;
  }

  if (action === "delete-shopping") {
    await deleteShoppingItem(Number(actionTarget.dataset.itemId));
    return;
  }

  if (action === "delete-calendar") {
    await deleteCalendarEvent(Number(actionTarget.dataset.eventId));
    return;
  }

  if (action === "revoke-assignment") {
    await revokeRuntimeAssignment(actionTarget.dataset.assignmentId);
    return;
  }

  if (action === "renew-assignment") {
    await renewRuntimeAssignment(actionTarget.dataset.assignmentId);
    return;
  }

  if (action === "delete-assignment") {
    await deleteRuntimeAssignment(actionTarget.dataset.assignmentId);
  }
}

async function toggleShoppingItem(itemId) {
  const item = state.shoppingItems.find((candidate) => Number(candidate.id) === Number(itemId));
  if (!item) {
    return;
  }
  try {
    await apiFetch(`/shopping_item/${itemId}`, {
      method: "PUT",
      body: {
        household_id: item.household_id,
        title: item.title,
        completed: !item.completed,
      },
    });
    setBanner("Shopping item updated.", "success");
    pushActivity(`Toggled shopping item ${itemId}.`, "success");
    await loadShoppingItems();
  } catch (error) {
    handleRequestError(`Shopping item update failed for ${itemId}.`, error);
  }
}

async function deleteShoppingItem(itemId) {
  try {
    await apiFetch(`/shopping_item/${itemId}`, { method: "DELETE" });
    setBanner("Shopping item deleted.", "success");
    pushActivity(`Deleted shopping item ${itemId}.`, "success");
    await loadShoppingItems();
  } catch (error) {
    handleRequestError(`Shopping item deletion failed for ${itemId}.`, error);
  }
}

async function deleteCalendarEvent(eventId) {
  try {
    await apiFetch(`/calendar_event/${eventId}`, { method: "DELETE" });
    setBanner("Calendar event deleted.", "success");
    pushActivity(`Deleted calendar event ${eventId}.`, "success");
    await loadCalendarEvents();
  } catch (error) {
    handleRequestError(`Calendar event deletion failed for ${eventId}.`, error);
  }
}

async function revokeRuntimeAssignment(assignmentId) {
  try {
    await apiFetch(`/authz/runtime/assignments/${assignmentId}/revoke`, {
      method: "POST",
      body: {
        reason: "revoked from Family Atlas",
      },
    });
    setBanner("Runtime assignment revoked.", "success");
    pushActivity(`Revoked runtime assignment ${assignmentId}.`, "success");
    await loadRuntimeAssignmentWorkspace();
  } catch (error) {
    handleRequestError(`Runtime assignment revoke failed for ${assignmentId}.`, error);
  }
}

async function renewRuntimeAssignment(assignmentId) {
  try {
    await apiFetch(`/authz/runtime/assignments/${assignmentId}/renew`, {
      method: "POST",
      body: {
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        reason: "renewed from Family Atlas",
      },
    });
    setBanner("Runtime assignment renewed for 30 days.", "success");
    pushActivity(`Renewed runtime assignment ${assignmentId}.`, "success");
    await loadRuntimeAssignmentWorkspace();
  } catch (error) {
    handleRequestError(`Runtime assignment renewal failed for ${assignmentId}.`, error);
  }
}

async function deleteRuntimeAssignment(assignmentId) {
  try {
    await apiFetch(`/authz/runtime/assignments/${assignmentId}`, { method: "DELETE" });
    setBanner("Runtime assignment deleted.", "success");
    pushActivity(`Deleted runtime assignment ${assignmentId}.`, "success");
    await loadRuntimeAssignmentWorkspace();
  } catch (error) {
    handleRequestError(`Runtime assignment deletion failed for ${assignmentId}.`, error);
  }
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = String(options.method || "GET").toUpperCase();
  let body = options.body;

  if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== "string") {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  } else if (typeof body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (state.token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    body,
    headers,
    credentials: "same-origin",
  });

  const contentType = response.headers.get("content-type") || "";
  const responseBody = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message = extractErrorMessage(responseBody, response.status);
    throw new Error(message);
  }

  return responseBody;
}

function extractErrorMessage(payload, status) {
  if (typeof payload === "string") {
    return payload || `HTTP ${status}`;
  }
  if (payload && typeof payload === "object") {
    if (typeof payload.message === "string") {
      return payload.message;
    }
    if (typeof payload.code === "string") {
      return payload.code;
    }
  }
  return `HTTP ${status}`;
}

function getSelectedFamily() {
  return state.families.find((family) => Number(family.id) === Number(state.selectedFamilyId)) || null;
}

function getSelectedHousehold() {
  return (
    state.households.find((household) => Number(household.id) === Number(state.selectedHouseholdId)) ||
    null
  );
}

function isAdmin() {
  return Boolean(state.currentUser && Array.isArray(state.currentUser.roles) && state.currentUser.roles.includes("admin"));
}

function handleRequestError(prefix, error) {
  const message = error instanceof Error ? error.message : String(error);
  setBanner(`${prefix} ${message}`, "error");
  pushActivity(`${prefix} ${message}`, "error");
}

function renderErrorState(message) {
  return `
    <div class="card error-card">
      <h3>Request failed</h3>
      <div class="meta-row">${escapeHtml(message)}</div>
    </div>
  `;
}

function renderAssignmentTarget(target) {
  if (!target || typeof target !== "object") {
    return "unknown";
  }
  if (target.kind && target.name) {
    return `${target.kind}:${target.name}`;
  }
  if (target.Template || target.Permission) {
    return formatJson(target);
  }
  return Object.entries(target)
    .map(([key, value]) => `${key}:${value && typeof value === "object" && "name" in value ? value.name : value}`)
    .join(", ");
}

function localInputToIso(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error("A valid date-time value is required.");
  }
  return date.toISOString();
}

function seedDefaultDatetimes() {
  const now = new Date();
  now.setSeconds(0, 0);
  const plusHour = new Date(now.getTime() + 60 * 60 * 1000);
  refs.calendarStartsAt.value = toLocalDatetimeInputValue(now);
  refs.calendarEndsAt.value = toLocalDatetimeInputValue(plusHour);
}

function toLocalDatetimeInputValue(date) {
  const copy = new Date(date.getTime() - date.getTimezoneOffset() * 60 * 1000);
  return copy.toISOString().slice(0, 16);
}

function formatDateRange(startsAt, endsAt) {
  return `${formatTimestamp(startsAt)} -> ${formatTimestamp(endsAt)}`;
}

function formatTimestamp(value) {
  if (!value) {
    return "n/a";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatJson(value) {
  return JSON.stringify(value, null, 2);
}

function toNullableInt(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
