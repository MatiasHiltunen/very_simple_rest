export type DateTimeInput = string | Date;
export type DateInput = string | VsrDate;
export type TimeInput = string | VsrTime;

type TemporalValue = Date | VsrDate | VsrTime;
type ScalarValue = string | number | boolean | TemporalValue;

export type QueryValue =
  | ScalarValue
  | null
  | undefined
  | Blob
  | Array<ScalarValue | null | undefined>;

export type QueryParams = Record<string, QueryValue>;

export type RequestConfig = {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  query?: QueryParams;
  body?: unknown;
  contentType?: string;
  headers?: HeadersInit;
  signal?: AbortSignal;
  requiresBearerAuth?: boolean;
};

export type ClientConfig = {
  baseUrl?: string;
  serverUrl?: string;
  fetch?: typeof fetch;
  defaultHeaders?: HeadersInit;
  credentials?: RequestCredentials;
  anonKey?: string;
  anonHeaderName?: string;
  getAccessToken?: () => string | null | undefined | Promise<string | null | undefined>;
  getCsrfToken?: () => string | null | undefined | Promise<string | null | undefined>;
  csrfHeaderName?: string;
};

export type ResolvedClientConfig = {
  baseUrl: string;
  serverUrl: string;
  fetch: typeof fetch;
  defaultHeaders?: HeadersInit;
  credentials: RequestCredentials;
  anonKey?: string;
  anonHeaderName: string;
  getAccessToken?: () => string | null | undefined | Promise<string | null | undefined>;
  getCsrfToken?: () => string | null | undefined | Promise<string | null | undefined>;
  csrfHeaderName: string;
};

export class VsrDate {
  readonly year: number;
  readonly month: number;
  readonly day: number;

  constructor(year: number, month: number, day: number) {
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

  toString(): string {
    return `${padNumber(this.year, 4)}-${padNumber(this.month, 2)}-${padNumber(this.day, 2)}`;
  }

  toJSON(): string {
    return this.toString();
  }
}

export class VsrTime {
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
  readonly microsecond: number;

  constructor(hour: number, minute: number, second: number = 0, microsecond: number = 0) {
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

  toString(): string {
    return `${padNumber(this.hour, 2)}:${padNumber(this.minute, 2)}:${padNumber(this.second, 2)}.${padNumber(this.microsecond, 6)}`;
  }

  toJSON(): string {
    return this.toString();
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly headers: Headers;

  constructor(message: string, status: number, body: unknown, headers: Headers) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.headers = headers;
  }
}

export interface VsrClient {
  readonly config: ResolvedClientConfig;
  request<TResponse>(request: RequestConfig): Promise<TResponse>;
}

const DEFAULT_SERVER_URL = "/api";
const DEFAULT_ANON_HEADER_NAME = "x-vsr-anon-key";
const DEFAULT_ANON_KEY = "vsr-default-anon-client-key";

function requestNeedsCsrf(method: string): boolean {
  const normalized = method.toUpperCase();
  return normalized === "POST" || normalized === "PUT" || normalized === "PATCH" || normalized === "DELETE";
}

export function createClient(config: ClientConfig = {}): VsrClient {
  const resolvedConfig: ResolvedClientConfig = {
    baseUrl: config.baseUrl ?? "",
    serverUrl: config.serverUrl ?? DEFAULT_SERVER_URL,
    fetch: bindFetch(config.fetch ?? globalThis.fetch),
    defaultHeaders: config.defaultHeaders,
    credentials: config.credentials ?? "include",
    anonKey: config.anonKey ?? DEFAULT_ANON_KEY,
    anonHeaderName: config.anonHeaderName ?? DEFAULT_ANON_HEADER_NAME,
    getAccessToken: config.getAccessToken,
    getCsrfToken: config.getCsrfToken,
    csrfHeaderName: config.csrfHeaderName ?? "x-csrf-token",
  };

  return {
    config: resolvedConfig,
    async request<TResponse>(request: RequestConfig): Promise<TResponse> {
      const headers = new Headers(resolvedConfig.defaultHeaders ?? undefined);
      if (request.headers) {
        new Headers(request.headers).forEach((value, key) => headers.set(key, value));
      }

      if (resolvedConfig.anonKey) {
        headers.set(resolvedConfig.anonHeaderName, resolvedConfig.anonKey);
      }

      if (request.requiresBearerAuth && resolvedConfig.getAccessToken) {
        const token = await resolvedConfig.getAccessToken();
        if (token) {
          headers.set("authorization", `Bearer ${token}`);
        }
      }

      let body: BodyInit | undefined;
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
          body = request.body as BodyInit;
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
          typeof (parsedBody as { message?: unknown }).message === "string"
            ? ((parsedBody as { message: string }).message)
            : `${response.status} ${response.statusText}`;
        throw new ApiError(message, response.status, parsedBody, response.headers);
      }

      return parsedBody as TResponse;
    },
  };
}

function bindFetch(fetchImpl: typeof fetch | undefined): typeof fetch {
  if (typeof fetchImpl !== "function") {
    throw new Error("No fetch implementation is available for the generated client.");
  }
  return fetchImpl.bind(globalThis);
}

function buildUrl(config: ResolvedClientConfig, path: string, query?: QueryParams): string {
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

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function ensureLeadingSlash(value: string): string {
  if (!value) {
    return "";
  }
  return value.startsWith("/") ? value : `/${value}`;
}

export function interpolatePath(
  template: string,
  params?: Record<string, ScalarValue | null | undefined>,
): string {
  return template.replace(/\{([^}]+)\}/g, (_, key: string) => {
    const value = params?.[key];
    if (value === undefined || value === null) {
      throw new Error(`Missing required path parameter: ${key}`);
    }
    return encodeURIComponent(stringifyScalarValue(value));
  });
}

function appendQuery(searchParams: URLSearchParams, query: QueryParams): void {
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      if (key.endsWith("__in")) {
        const items = value.filter((item): item is ScalarValue => item !== undefined && item !== null);
        if (items.length > 0) {
          searchParams.append(key, items.map((item) => stringifyScalarValue(item)).join(","));
        }
        continue;
      }
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

function stringifyScalarValue(value: ScalarValue): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return stringifyTemporalValue(value);
}

function stringifyScalarLikeValue(value: unknown): string {
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

function objectToFormData(value: unknown): FormData {
  if (value instanceof FormData) {
    return value;
  }
  const formData = new FormData();
  if (!value || typeof value !== "object") {
    return formData;
  }
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    appendFormDataValue(formData, key, entry);
  }
  return formData;
}

function appendFormDataValue(formData: FormData, key: string, value: unknown): void {
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

async function parseResponseBody(response: Response): Promise<unknown> {
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

function normalizeJsonValue(value: unknown): unknown {
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
    const normalized: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      normalized[key] = normalizeJsonValue(entry);
    }
    return normalized;
  }
  return value;
}

function isTemporalValue(value: unknown): value is TemporalValue {
  return value instanceof Date || value instanceof VsrDate || value instanceof VsrTime;
}

function stringifyTemporalValue(value: TemporalValue): string {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error("Invalid DateTimeInput value.");
    }
    return `${padNumber(value.getUTCFullYear(), 4)}-${padNumber(value.getUTCMonth() + 1, 2)}-${padNumber(value.getUTCDate(), 2)}T${padNumber(value.getUTCHours(), 2)}:${padNumber(value.getUTCMinutes(), 2)}:${padNumber(value.getUTCSeconds(), 2)}.${padNumber(value.getUTCMilliseconds() * 1000, 6)}+00:00`;
  }
  return value.toString();
}

function padNumber(value: number, width: number): string {
  return String(value).padStart(width, "0");
}
