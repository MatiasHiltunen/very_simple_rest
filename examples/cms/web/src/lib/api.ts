export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface ApiErrorPayload {
  code?: string;
  field?: string | null;
  message?: string;
}

export interface AuthTokenResponse {
  token: string;
  csrf_token?: string;
}

export interface AuthMeResponse {
  id: number;
  email?: string;
  role?: string;
  roles: string[];
  workspace_id?: number;
  is_staff?: boolean;
  [key: string]: JsonValue | undefined;
}

export interface ListResponse<T> {
  items: T[];
  limit?: number;
  offset?: number;
  total?: number;
  next_cursor?: string | null;
}

export interface LocalObjectUpload {
  bucket: string;
  object_key: string;
  public_url: string;
  file_name: string;
  content_type?: string | null;
  size_bytes: number;
}

export interface ManagedUserUpdateInput {
  role?: string;
  email_verified?: boolean;
  claims?: Record<string, JsonValue>;
}

const TOKEN_STORAGE_KEY = 'modern-cms-studio.token';
const EMAIL_STORAGE_KEY = 'modern-cms-studio.email';
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';
let unauthorizedHandler: (() => void) | null = null;

export class ApiError extends Error {
  status: number;
  code?: string;
  field?: string | null;

  constructor(status: number, payload: ApiErrorPayload | null, fallbackMessage: string) {
    super(payload?.message ?? fallbackMessage);
    this.name = 'ApiError';
    this.status = status;
    this.code = payload?.code;
    this.field = payload?.field;
  }
}

function apiUrl(path: string): string {
  if (!API_BASE_URL) {
    return path;
  }
  return `${API_BASE_URL.replace(/\/$/, '')}${path}`;
}

export function readAuthToken(): string | null {
  return window.localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function readLastEmail(): string {
  return window.localStorage.getItem(EMAIL_STORAGE_KEY) ?? '';
}

export function persistAuthToken(token: string): void {
  window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function persistLastEmail(email: string): void {
  window.localStorage.setItem(EMAIL_STORAGE_KEY, email.trim());
}

export function clearAuthToken(): void {
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

async function request<T>(path: string, init: RequestInit = {}, token = readAuthToken()): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(apiUrl(path), {
    ...init,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    let payload: ApiErrorPayload | null = null;
    try {
      payload = (await response.json()) as ApiErrorPayload;
    } catch {
      payload = null;
    }
    if (response.status === 401 && token) {
      unauthorizedHandler?.();
    }
    throw new ApiError(response.status, payload, `Request failed with status ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  if (!text.trim()) {
    return undefined as T;
  }
  return JSON.parse(text) as T;
}

export async function login(email: string, password: string): Promise<AuthTokenResponse> {
  persistLastEmail(email);
  return request<AuthTokenResponse>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  }, null);
}

export async function getAuthenticatedAccount(): Promise<AuthMeResponse> {
  return request<AuthMeResponse>('/api/auth/account');
}

export async function listResource<T>(
  path: string,
  params: Record<string, string | number | undefined>,
): Promise<ListResponse<T>> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') {
      query.set(key, String(value));
    }
  }
  const suffix = query.size > 0 ? `?${query.toString()}` : '';
  return request<ListResponse<T>>(`/api/${path}${suffix}`);
}

export async function createResource<T>(path: string, body: Record<string, JsonValue>): Promise<T> {
  return request<T>(`/api/${path}`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateResource<T>(
  path: string,
  id: number,
  body: Record<string, JsonValue>,
): Promise<T> {
  return request<T>(`/api/${path}/${id}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

export async function deleteResource(path: string, id: number): Promise<void> {
  await request<void>(`/api/${path}/${id}`, {
    method: 'DELETE',
  });
}

export async function runResourceAction(
  path: string,
  id: number,
  action: string,
  body?: Record<string, JsonValue>,
): Promise<void> {
  await request<void>(`/api/${path}/${id}/${action}`, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function updateManagedUser(
  id: number,
  body: ManagedUserUpdateInput,
): Promise<AuthMeResponse> {
  return request<AuthMeResponse>(`/api/auth/admin/users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

function sanitizeObjectName(value: string): string {
  const trimmed = value.trim();
  const normalized = trimmed
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-._]+|[-._]+$/g, '');
  return normalized || 'upload.bin';
}

function encodeObjectPath(key: string): string {
  return key
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

function localS3ObjectUrl(bucket: string, key: string): string {
  return apiUrl(`/_s3/${encodeURIComponent(bucket)}/${encodeObjectPath(key)}`);
}

export async function uploadLocalObject(file: File): Promise<LocalObjectUpload> {
  const objectKey = `studio/${crypto.randomUUID()}-${sanitizeObjectName(file.name)}`;
  const response = await fetch(localS3ObjectUrl('media', objectKey), {
    method: 'PUT',
    headers: {
      'Content-Type': file.type || 'application/octet-stream',
      'x-amz-meta-original-name': file.name,
      'x-amz-meta-uploaded-via': 'studio',
    },
    body: file,
    credentials: 'include',
  });
  if (!response.ok) {
    throw new ApiError(response.status, null, `Upload failed with status ${response.status}`);
  }
  return {
    bucket: 'media',
    object_key: objectKey,
    public_url: `/uploads/assets/${objectKey}`,
    file_name: sanitizeObjectName(file.name),
    content_type: file.type || 'application/octet-stream',
    size_bytes: file.size,
  };
}

export async function deleteLocalObject(bucket: string, objectKey: string): Promise<void> {
  const response = await fetch(localS3ObjectUrl(bucket, objectKey), {
    method: 'DELETE',
    credentials: 'include',
  });
  if (response.ok || response.status === 404) {
    return;
  }
  throw new ApiError(response.status, null, `Object delete failed with status ${response.status}`);
}
