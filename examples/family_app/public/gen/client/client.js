export class ApiError extends Error {
  constructor(message, status, body, headers) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }
}

const DEFAULT_SERVER_URL = "/api";

export function createClient(config = {}) {
  const resolvedConfig = {
    baseUrl: config.baseUrl ?? "",
    serverUrl: config.serverUrl ?? DEFAULT_SERVER_URL,
    fetch: bindFetch(config.fetch ?? globalThis.fetch),
    defaultHeaders: config.defaultHeaders,
    credentials: config.credentials ?? "include",
    getAccessToken: config.getAccessToken,
    getCsrfToken: config.getCsrfToken,
    csrfHeaderName: config.csrfHeaderName ?? "x-csrf-token",
  };

  return {
    config: resolvedConfig,
    async request(request) {
      const headers = new Headers(resolvedConfig.defaultHeaders ?? undefined);
      if (request.headers) {
        new Headers(request.headers).forEach((value, key) => headers.set(key, value));
      }

      if (request.requiresBearerAuth && resolvedConfig.getAccessToken) {
        const token = await resolvedConfig.getAccessToken();
        if (token) {
          headers.set("authorization", `Bearer ${token}`);
        }
      }

      let body;
      if (request.body !== undefined) {
        if (request.contentType === "multipart/form-data") {
          body = request.body instanceof FormData ? request.body : objectToFormData(request.body);
        } else if (request.contentType === "application/json") {
          headers.set("content-type", "application/json");
          body = JSON.stringify(request.body);
        } else if (request.contentType === "text/plain") {
          headers.set("content-type", "text/plain");
          body = typeof request.body === "string" ? request.body : String(request.body);
        } else {
          if (request.contentType) {
            headers.set("content-type", request.contentType);
          }
          body = request.body;
        }
      }

      if (body !== undefined && resolvedConfig.getCsrfToken) {
        const csrfToken = await resolvedConfig.getCsrfToken();
        if (csrfToken) {
          headers.set(resolvedConfig.csrfHeaderName, csrfToken);
        }
      }

      const response = await resolvedConfig.fetch(buildUrl(resolvedConfig, request.path, request.query), {
        method: request.method,
        headers,
        body,
        signal: request.signal,
        credentials: resolvedConfig.credentials,
      });

      const parsedBody = await parseResponseBody(response);
      if (!response.ok) {
        const message =
          typeof parsedBody === "object" &&
          parsedBody !== null &&
          "message" in parsedBody &&
          typeof parsedBody.message === "string"
            ? parsedBody.message
            : `${response.status} ${response.statusText}`;
        throw new ApiError(message, response.status, parsedBody, response.headers);
      }

      return parsedBody;
    },
  };
}

function bindFetch(fetchImpl) {
  if (typeof fetchImpl !== "function") {
    throw new Error("No fetch implementation is available for the generated client.");
  }
  return fetchImpl.bind(globalThis);
}

function buildUrl(config, path, query) {
  const base = `${trimTrailingSlash(config.baseUrl)}${ensureLeadingSlash(config.serverUrl)}${ensureLeadingSlash(path)}`;
  const url = new URL(base, base.startsWith("http://") || base.startsWith("https://") ? undefined : "http://localhost");
  if (query) {
    appendQuery(url.searchParams, query);
  }

  if (!config.baseUrl) {
    return `${url.pathname}${url.search}${url.hash}`;
  }

  return url.toString();
}

function trimTrailingSlash(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function ensureLeadingSlash(value) {
  if (!value) {
    return "";
  }
  return value.startsWith("/") ? value : `/${value}`;
}

export function interpolatePath(template, params) {
  return template.replace(/\{([^}]+)\}/g, (_, key) => {
    const value = params?.[key];
    if (value === undefined || value === null) {
      throw new Error(`Missing required path parameter: ${key}`);
    }
    return encodeURIComponent(String(value));
  });
}

function appendQuery(searchParams, query) {
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) {
          searchParams.append(key, stringifyQueryValue(item));
        }
      }
      continue;
    }
    if (value instanceof Blob) {
      continue;
    }
    searchParams.append(key, stringifyQueryValue(value));
  }
}

function stringifyQueryValue(value) {
  return typeof value === "string" ? value : String(value);
}

function objectToFormData(value) {
  if (value instanceof FormData) {
    return value;
  }
  const formData = new FormData();
  if (!value || typeof value !== "object") {
    return formData;
  }
  for (const [key, entry] of Object.entries(value)) {
    appendFormDataValue(formData, key, entry);
  }
  return formData;
}

function appendFormDataValue(formData, key, value) {
  if (value === undefined || value === null) {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      appendFormDataValue(formData, key, item);
    }
    return;
  }
  if (value instanceof Blob) {
    formData.append(key, value);
    return;
  }
  if (typeof value === "string") {
    formData.append(key, value);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    formData.append(key, String(value));
    return;
  }
  formData.append(key, JSON.stringify(value));
}

async function parseResponseBody(response) {
  if (response.status === 204 || response.status === 205) {
    return undefined;
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const text = await response.text();
    return text ? JSON.parse(text) : undefined;
  }
  if (contentType.startsWith("text/")) {
    return response.text();
  }
  const text = await response.text();
  return text ? text : undefined;
}
