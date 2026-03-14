const API_URL = "/api";
const storageKey = "todo_app_auth_token";

let authToken = localStorage.getItem(storageKey) || "";
let currentUser = null;
let todos = [];

const sessionSummary = document.getElementById("sessionSummary");
const sessionClaims = document.getElementById("sessionClaims");
const authStatus = document.getElementById("authStatus");
const todoList = document.getElementById("todoList");

const emailInput = document.getElementById("emailInput");
const passwordInput = document.getElementById("passwordInput");
const todoTitleInput = document.getElementById("todoTitleInput");
const todoCompletedInput = document.getElementById("todoCompletedInput");

document.getElementById("registerBtn").addEventListener("click", registerUser);
document.getElementById("loginBtn").addEventListener("click", loginUser);
document.getElementById("logoutBtn").addEventListener("click", logoutUser);
document.getElementById("refreshProfileBtn").addEventListener("click", refreshSession);
document.getElementById("createTodoBtn").addEventListener("click", createTodo);
document.getElementById("reloadTodosBtn").addEventListener("click", loadTodos);

if (authToken) {
  refreshSession();
} else {
  renderSession();
  renderTodos();
}

function setStatus(message, kind = "") {
  authStatus.textContent = message;
  authStatus.className = `status-box${kind ? ` ${kind}` : ""}`;
}

function renderSession() {
  if (!currentUser) {
    sessionSummary.textContent = "Not logged in.";
    sessionClaims.textContent = "Register a new user here, or log in as the admin created through the CLI.";
    return;
  }

  const roleList = (currentUser.roles || []).join(", ") || "none";
  sessionSummary.textContent = `Logged in as user #${currentUser.id} (${roleList})`;

  const extraClaims = Object.fromEntries(
    Object.entries(currentUser).filter(([key]) => key !== "id" && key !== "roles"),
  );
  const claims = Object.keys(extraClaims).length > 0
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

    const isOwner = currentUser.roles.includes("admin") || Number(todo.user_id) === Number(currentUser.id);
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
    toggleButton.addEventListener("click", () => toggleTodo(todo));
    deleteButton.addEventListener("click", () => deleteTodo(todo));

    todoList.appendChild(card);
  }
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (authToken) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message = typeof data === "string"
      ? data
      : data.message || data.code || `HTTP ${response.status}`;
    throw new Error(message);
  }

  return data;
}

async function registerUser() {
  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email || !password) {
    setStatus("Email and password are required.", "error");
    return;
  }

  try {
    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setStatus("Registration succeeded. Log in with the same credentials.", "success");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function loginUser() {
  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email || !password) {
    setStatus("Email and password are required.", "error");
    return;
  }

  try {
    const data = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    authToken = data.token;
    localStorage.setItem(storageKey, authToken);
    setStatus("Login succeeded. Loading your current API view...", "success");
    await refreshSession();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function refreshSession() {
  if (!authToken) {
    currentUser = null;
    todos = [];
    renderSession();
    renderTodos();
    return;
  }

  try {
    currentUser = await apiFetch("/auth/me");
    renderSession();
    await loadTodos();
  } catch (error) {
    authToken = "";
    currentUser = null;
    todos = [];
    localStorage.removeItem(storageKey);
    renderSession();
    renderTodos();
    setStatus(`Session refresh failed: ${error.message}`, "error");
  }
}

function logoutUser() {
  authToken = "";
  currentUser = null;
  todos = [];
  localStorage.removeItem(storageKey);
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
    const response = await apiFetch("/todo");
    todos = response.items || [];
    renderTodos();
  } catch (error) {
    setStatus(`Failed to load todos: ${error.message}`, "error");
  }
}

async function createTodo() {
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
    await apiFetch("/todo", {
      method: "POST",
      body: JSON.stringify({
        title,
        completed: todoCompletedInput.value === "true",
      }),
    });
    todoTitleInput.value = "";
    todoCompletedInput.value = "false";
    setStatus("Todo created.", "success");
    await loadTodos();
  } catch (error) {
    setStatus(`Create failed: ${error.message}`, "error");
  }
}

async function toggleTodo(todo) {
  try {
    await apiFetch(`/todo/${todo.id}`, {
      method: "PUT",
      body: JSON.stringify({
        title: todo.title,
        completed: !todo.completed,
      }),
    });
    setStatus("Todo updated.", "success");
    await loadTodos();
  } catch (error) {
    setStatus(`Update failed: ${error.message}`, "error");
  }
}

async function deleteTodo(todo) {
  try {
    await apiFetch(`/todo/${todo.id}`, {
      method: "DELETE",
    });
    setStatus("Todo deleted.", "success");
    await loadTodos();
  } catch (error) {
    setStatus(`Delete failed: ${error.message}`, "error");
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
