import {
  createClient,
  createTodo,
  deleteTodo,
  getAuthenticatedAccount,
  listTodo,
  loginUser,
  logoutUser,
  registerUser,
  updateTodo,
} from "./gen/client/index.js";

const csrfCookieName = "vsr_csrf";

let csrfToken = "";
let currentUser = null;
let todos = [];

const apiClient = createClient({
  credentials: "same-origin",
  getCsrfToken: () => csrfToken || readCookie(csrfCookieName) || undefined,
});

const sessionSummary = document.getElementById("sessionSummary");
const sessionClaims = document.getElementById("sessionClaims");
const authStatus = document.getElementById("authStatus");
const todoList = document.getElementById("todoList");

const emailInput = document.getElementById("emailInput");
const passwordInput = document.getElementById("passwordInput");
const todoTitleInput = document.getElementById("todoTitleInput");
const todoCompletedInput = document.getElementById("todoCompletedInput");

document.getElementById("registerBtn").addEventListener("click", registerTodoUser);
document.getElementById("loginBtn").addEventListener("click", loginTodoUser);
document.getElementById("logoutBtn").addEventListener("click", logoutTodoUser);
document.getElementById("refreshProfileBtn").addEventListener("click", refreshSession);
document.getElementById("createTodoBtn").addEventListener("click", createTodoItem);
document.getElementById("reloadTodosBtn").addEventListener("click", loadTodos);

refreshSession();

function setStatus(message, kind = "") {
  authStatus.textContent = message;
  authStatus.className = `status-box${kind ? ` ${kind}` : ""}`;
}

function renderSession() {
  if (!currentUser) {
    sessionSummary.textContent = "Not logged in.";
    sessionClaims.textContent =
      "Register a new user here, or log in as the admin created through the CLI.";
    return;
  }

  const roleList = (currentUser.roles || []).join(", ") || "none";
  const email =
    typeof currentUser.email === "string" && currentUser.email
      ? currentUser.email
      : `user #${currentUser.id}`;
  sessionSummary.textContent = `Logged in as ${email} (${roleList})`;

  const extraClaims = Object.fromEntries(
    Object.entries(currentUser).filter(([key]) => key !== "id" && key !== "roles"),
  );
  const claims =
    Object.keys(extraClaims).length > 0
      ? JSON.stringify(extraClaims)
      : "No extra numeric claims on this account.";
  sessionClaims.textContent = claims;
}

function renderTodos() {
  if (!currentUser) {
    todoList.innerHTML = '<div class="empty">Log in to load todos.</div>';
    return;
  }

  if (todos.length === 0) {
    todoList.innerHTML = '<div class="empty">No todos yet for this current API view.</div>';
    return;
  }

  todoList.innerHTML = "";
  for (const todo of todos) {
    const card = document.createElement("article");
    card.className = `todo${todo.completed ? " done" : ""}`;

    const isOwner =
      currentUser.roles.includes("admin") || Number(todo.user_id) === Number(currentUser.id);
    const stateLabel = todo.completed ? "Completed" : "Open";

    card.innerHTML = `
      <div class="todo-top">
        <div>
          <h3 class="todo-title">${escapeHtml(todo.title)}</h3>
          <div class="todo-meta">
            <span>Status: ${stateLabel}</span>
            <span>Owner User ID: ${todo.user_id}</span>
            <span>Row ID: ${todo.id}</span>
          </div>
        </div>
      </div>
      <div class="button-row">
        <button class="secondary" data-action="toggle">${todo.completed ? "Mark Open" : "Mark Done"}</button>
        <button class="danger" data-action="delete">Delete</button>
      </div>
      <div class="muted tiny">${isOwner ? "This row is writable in your current session." : "You should not normally reach this row without admin access."}</div>
    `;

    const [toggleButton, deleteButton] = card.querySelectorAll("button");
    toggleButton.addEventListener("click", () => toggleTodoItem(todo));
    deleteButton.addEventListener("click", () => deleteTodoItem(todo));

    todoList.appendChild(card);
  }
}

async function registerTodoUser() {
  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email || !password) {
    setStatus("Email and password are required.", "error");
    return;
  }

  try {
    await registerUser(apiClient, {
      body: { email, password },
    });
    setStatus("Registration succeeded. Log in with the same credentials.", "success");
  } catch (error) {
    setStatus(getErrorMessage(error), "error");
  }
}

async function loginTodoUser() {
  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email || !password) {
    setStatus("Email and password are required.", "error");
    return;
  }

  try {
    const data = await loginUser(apiClient, {
      body: { email, password },
    });
    csrfToken = data.csrf_token || readCookie(csrfCookieName) || "";
    setStatus("Login succeeded. Loading your current API view...", "success");
    await refreshSession();
  } catch (error) {
    setStatus(getErrorMessage(error), "error");
  }
}

async function refreshSession() {
  syncCsrfToken();
  if (!csrfToken) {
    currentUser = null;
    todos = [];
    renderSession();
    renderTodos();
    return;
  }

  try {
    currentUser = await getAuthenticatedAccount(apiClient);
    syncCsrfToken();
    renderSession();
    await loadTodos();
  } catch (error) {
    csrfToken = "";
    currentUser = null;
    todos = [];
    renderSession();
    renderTodos();
    if (!isMissingTokenError(error)) {
      setStatus(`Session refresh failed: ${getErrorMessage(error)}`, "error");
    }
  }
}

async function logoutTodoUser() {
  try {
    await logoutUser(apiClient);
  } catch (error) {
    setStatus(`Logout failed: ${getErrorMessage(error)}`, "error");
    return;
  }

  csrfToken = "";
  currentUser = null;
  todos = [];
  renderSession();
  renderTodos();
  setStatus("Logged out.", "success");
}

async function loadTodos() {
  if (!currentUser) {
    renderTodos();
    return;
  }

  try {
    const response = await listTodo(apiClient);
    todos = response.items || [];
    renderTodos();
  } catch (error) {
    setStatus(`Failed to load todos: ${getErrorMessage(error)}`, "error");
  }
}

async function createTodoItem() {
  if (!currentUser) {
    setStatus("Log in before creating todos.", "error");
    return;
  }

  const title = todoTitleInput.value.trim();
  if (!title) {
    setStatus("Todo title is required.", "error");
    return;
  }

  try {
    await createTodo(apiClient, {
      body: {
        title,
        completed: todoCompletedInput.value === "true",
      },
    });
    todoTitleInput.value = "";
    todoCompletedInput.value = "false";
    setStatus("Todo created.", "success");
    await loadTodos();
  } catch (error) {
    setStatus(`Create failed: ${getErrorMessage(error)}`, "error");
  }
}

async function toggleTodoItem(todo) {
  try {
    await updateTodo(apiClient, {
      path: { id: Number(todo.id) },
      body: {
        title: todo.title,
        completed: !todo.completed,
      },
    });
    setStatus("Todo updated.", "success");
    await loadTodos();
  } catch (error) {
    setStatus(`Update failed: ${getErrorMessage(error)}`, "error");
  }
}

async function deleteTodoItem(todo) {
  try {
    await deleteTodo(apiClient, {
      path: { id: Number(todo.id) },
    });
    setStatus("Todo deleted.", "success");
    await loadTodos();
  } catch (error) {
    setStatus(`Delete failed: ${getErrorMessage(error)}`, "error");
  }
}

function getErrorMessage(error) {
  if (error && typeof error.message === "string" && error.message) {
    return error.message;
  }
  if (
    error &&
    typeof error === "object" &&
    error.body &&
    typeof error.body === "object" &&
    typeof error.body.message === "string"
  ) {
    return error.body.message;
  }
  if (
    error &&
    typeof error === "object" &&
    error.body &&
    typeof error.body === "object" &&
    typeof error.body.code === "string"
  ) {
    return error.body.code;
  }
  return "Request failed.";
}

function isMissingTokenError(error) {
  const code =
    error &&
    typeof error === "object" &&
    error.body &&
    typeof error.body === "object" &&
    typeof error.body.code === "string"
      ? error.body.code
      : "";
  return (
    code === "missing_token" ||
    code === "invalid_token" ||
    getErrorMessage(error).toLowerCase().includes("missing token")
  );
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function syncCsrfToken() {
  csrfToken = readCookie(csrfCookieName) || csrfToken;
}

function readCookie(name) {
  const parts = document.cookie
    .split(";")
    .map((value) => value.trim())
    .filter(Boolean);
  for (const part of parts) {
    if (part.startsWith(`${name}=`)) {
      return decodeURIComponent(part.slice(name.length + 1));
    }
  }
  return "";
}
