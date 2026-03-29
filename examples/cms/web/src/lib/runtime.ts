export function studioBasePath(): string {
  if (typeof window === 'undefined') {
    return '/studio/';
  }

  const pathname = window.location.pathname.replace(/\/+$/, '') || '/';
  return pathname === '/studio' || pathname.startsWith('/studio/') ? '/studio/' : '/';
}

export function resolveStudioPath(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const basePath = studioBasePath().replace(/\/$/, '');
  return basePath && basePath !== '/' ? `${basePath}${normalizedPath}` : normalizedPath;
}

export function resolveBackendPath(path: string): string {
  if (/^[a-z]+:/i.test(path)) {
    return path;
  }

  return path.startsWith('/') ? path : `/${path}`;
}

export function resolveDocsPath(): string {
  return resolveBackendPath('/docs');
}
