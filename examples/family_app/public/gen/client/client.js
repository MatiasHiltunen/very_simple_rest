export class VsrDate {
  constructor(year, month, day) {
    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {
      throw new Error("VsrDate values must be integers.");
    }
    const normalized = new Date(Date.UTC(year, month - 1, day));
    if (
      normalized.getUTCFullYear() !== year ||
      normalized.getUTCMonth() !== month - 1 ||
      normalized.getUTCDate() !== day
    ) {
      throw new Error("Invalid VsrDate value.");
    }
    this.year = year;
    this.month = month;
    this.day = day;
  }

  toString() {
    return `${padNumber(this.year, 4)}-${padNumber(this.month, 2)}-${padNumber(this.day, 2)}`;
  }

  toJSON() {
    return this.toString();
  }
}

export class VsrTime {
  constructor(hour, minute, second = 0, microsecond = 0) {
    if (
      !Number.isInteger(hour) ||
      !Number.isInteger(minute) ||
      !Number.isInteger(second) ||
      !Number.isInteger(microsecond)
    ) {
      throw new Error("VsrTime values must be integers.");
    }
    if (hour < 0 || hour > 23) {
      throw new Error("VsrTime hour must be between 0 and 23.");
    }
    if (minute < 0 || minute > 59) {
      throw new Error("VsrTime minute must be between 0 and 59.");
    }
    if (second < 0 || second > 59) {
      throw new Error("VsrTime second must be between 0 and 59.");
    }
    if (microsecond < 0 || microsecond > 999999) {
      throw new Error("VsrTime microsecond must be between 0 and 999999.");
    }
    this.hour = hour;
    this.minute = minute;
    this.second = second;
    this.microsecond = microsecond;
  }

  toString() {
    return `${padNumber(this.hour, 2)}:${padNumber(this.minute, 2)}:${padNumber(this.second, 2)}.${padNumber(this.microsecond, 6)}`;
  }

  toJSON() {
    return this.toString();
  }
}

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

function requestNeedsCsrf(method) {
  const normalized = method.toUpperCase();
  return normalized === "POST" || normalized === "PUT" || normalized === "PATCH" || normalized === "DELETE";
}

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
          body = JSON.stringify(normalizeJsonValue(request.body));
        } else if (request.contentType === "text/plain") {
          headers.set("content-type", "text/plain");
          body = stringifyScalarLikeValue(request.body);
        } else {
          if (request.contentType) {
            headers.set("content-type", request.contentType);
          }
          body = request.body;
        }
      }

      if (requestNeedsCsrf(request.method) && resolvedConfig.getCsrfToken) {
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
    return encodeURIComponent(stringifyScalarValue(value));
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
          searchParams.append(key, stringifyScalarValue(item));
        }
      }
      continue;
    }
    if (value instanceof Blob) {
      continue;
    }
    searchParams.append(key, stringifyScalarValue(value));
  }
}

function stringifyScalarValue(value) {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return stringifyTemporalValue(value);
}

function stringifyScalarLikeValue(value) {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (isTemporalValue(value)) {
    return stringifyTemporalValue(value);
  }
  return String(value);
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
  if (isTemporalValue(value)) {
    formData.append(key, stringifyTemporalValue(value));
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

function normalizeJsonValue(value) {
  if (value === undefined || value === null) {
    return value;
  }
  if (isTemporalValue(value)) {
    return stringifyTemporalValue(value);
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeJsonValue(entry));
  }
  if (value instanceof Blob || value instanceof FormData || value instanceof URLSearchParams) {
    return value;
  }
  if (typeof value === "object") {
    const normalized = {};
    for (const [key, entry] of Object.entries(value)) {
      normalized[key] = normalizeJsonValue(entry);
    }
    return normalized;
  }
  return value;
}

function isTemporalValue(value) {
  return value instanceof Date || value instanceof VsrDate || value instanceof VsrTime;
}

function stringifyTemporalValue(value) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error("Invalid DateTimeInput value.");
    }
    return `${padNumber(value.getUTCFullYear(), 4)}-${padNumber(value.getUTCMonth() + 1, 2)}-${padNumber(value.getUTCDate(), 2)}T${padNumber(value.getUTCHours(), 2)}:${padNumber(value.getUTCMinutes(), 2)}:${padNumber(value.getUTCSeconds(), 2)}.${padNumber(value.getUTCMilliseconds() * 1000, 6)}+00:00`;
  }
  return value.toString();
}

function padNumber(value, width) {
  return String(value).padStart(width, "0");
}
