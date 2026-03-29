import type { ResourceRow } from './cms';
import type { DraftState } from './draft';
import { resolveStudioPath } from './runtime';

const PREVIEW_SNAPSHOT_PREFIX = 'modern-cms-studio.preview.';
const PREVIEW_SNAPSHOT_TTL_MS = 20 * 60 * 1000;

interface StoredDraftPreviewSnapshot {
  version: 1;
  created_at: number;
  preview_path: string;
  workspace: ResourceRow | null;
  draft: DraftState;
  selected_topics: ResourceRow[];
  assets: ResourceRow[];
}

export interface DraftPreviewSnapshot {
  previewPath: string;
  workspace: ResourceRow | null;
  draft: DraftState;
  selectedTopics: ResourceRow[];
  assets: ResourceRow[];
}

function canUseBrowserStorage(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
}

function normalizePreviewPath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed || trimmed === '/') {
    return '/';
  }

  const withoutQuery = trimmed.split(/[?#]/, 1)[0] ?? trimmed;
  const normalized = withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
  return normalized.replace(/\/{2,}/g, '/');
}

function pruneExpiredDraftSnapshots(): void {
  if (!canUseBrowserStorage()) {
    return;
  }

  const now = Date.now();
  for (let index = window.localStorage.length - 1; index >= 0; index -= 1) {
    const key = window.localStorage.key(index);
    if (!key || !key.startsWith(PREVIEW_SNAPSHOT_PREFIX)) {
      continue;
    }

    try {
      const raw = window.localStorage.getItem(key);
      if (!raw) {
        window.localStorage.removeItem(key);
        continue;
      }

      const parsed = JSON.parse(raw) as Partial<StoredDraftPreviewSnapshot>;
      if (
        parsed.created_at == null ||
        typeof parsed.created_at !== 'number' ||
        now - parsed.created_at > PREVIEW_SNAPSHOT_TTL_MS
      ) {
        window.localStorage.removeItem(key);
      }
    } catch {
      window.localStorage.removeItem(key);
    }
  }
}

function buildPreviewSnapshotHref(baseHref: string, snapshotId: string): string {
  if (typeof window === 'undefined') {
    return `${baseHref}${baseHref.includes('?') ? '&' : '?'}draft=${encodeURIComponent(snapshotId)}`;
  }

  const url = new URL(baseHref, window.location.origin);
  url.searchParams.set('draft', snapshotId);
  return `${url.pathname}${url.search}${url.hash}`;
}

export function resolveLocalPreviewHref(workspaceSlug: string, path = '/'): string {
  const normalizedSlug = workspaceSlug.trim();
  if (!normalizedSlug) {
    return normalizePreviewPath(path);
  }

  const normalizedPath = normalizePreviewPath(path);
  const encodedSlug = encodeURIComponent(normalizedSlug);
  const previewSuffix = normalizedPath === '/' ? '' : normalizedPath;
  return resolveStudioPath(`/preview/${encodedSlug}${previewSuffix}`);
}

export function resolvePublishedSiteHref(workspace: ResourceRow | null, path = '/'): string | null {
  const baseUrl =
    workspace && typeof workspace.public_base_url === 'string' && workspace.public_base_url.trim()
      ? workspace.public_base_url.trim()
      : null;
  if (!baseUrl) {
    return null;
  }

  return `${baseUrl.replace(/\/$/, '')}${normalizePreviewPath(path)}`;
}

export function writeDraftPreviewSnapshot(snapshot: DraftPreviewSnapshot): string | null {
  if (!canUseBrowserStorage()) {
    return null;
  }

  pruneExpiredDraftSnapshots();
  const snapshotId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  const payload: StoredDraftPreviewSnapshot = {
    version: 1,
    created_at: Date.now(),
    preview_path: normalizePreviewPath(snapshot.previewPath),
    workspace: snapshot.workspace,
    draft: snapshot.draft,
    selected_topics: snapshot.selectedTopics,
    assets: snapshot.assets,
  };

  window.localStorage.setItem(`${PREVIEW_SNAPSHOT_PREFIX}${snapshotId}`, JSON.stringify(payload));
  return snapshotId;
}

export function readDraftPreviewSnapshot(snapshotId: string | null): DraftPreviewSnapshot | null {
  if (!snapshotId || !canUseBrowserStorage()) {
    return null;
  }

  const raw = window.localStorage.getItem(`${PREVIEW_SNAPSHOT_PREFIX}${snapshotId}`);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<StoredDraftPreviewSnapshot>;
    if (
      parsed.version !== 1 ||
      parsed.created_at == null ||
      typeof parsed.created_at !== 'number' ||
      Date.now() - parsed.created_at > PREVIEW_SNAPSHOT_TTL_MS
    ) {
      window.localStorage.removeItem(`${PREVIEW_SNAPSHOT_PREFIX}${snapshotId}`);
      return null;
    }

    return {
      previewPath:
        typeof parsed.preview_path === 'string' ? normalizePreviewPath(parsed.preview_path) : '/',
      workspace: parsed.workspace ?? null,
      draft:
        parsed.draft && typeof parsed.draft === 'object' && !Array.isArray(parsed.draft)
          ? (parsed.draft as DraftState)
          : {},
      selectedTopics: Array.isArray(parsed.selected_topics) ? parsed.selected_topics : [],
      assets: Array.isArray(parsed.assets) ? parsed.assets : [],
    };
  } catch {
    window.localStorage.removeItem(`${PREVIEW_SNAPSHOT_PREFIX}${snapshotId}`);
    return null;
  }
}

export function createDraftPreviewHref(
  workspaceSlug: string,
  path: string,
  snapshot: DraftPreviewSnapshot,
): string {
  const baseHref = resolveLocalPreviewHref(workspaceSlug, path);
  const snapshotId = writeDraftPreviewSnapshot(snapshot);
  return snapshotId ? buildPreviewSnapshotHref(baseHref, snapshotId) : baseHref;
}
