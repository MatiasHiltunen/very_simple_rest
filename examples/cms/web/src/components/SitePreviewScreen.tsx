import {
  ArrowBackRounded,
  LaunchRounded,
  VisibilityRounded,
} from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Stack,
  Typography,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { listResource } from '../lib/api';
import { entryResource, type ResourceRow } from '../lib/cms';
import { formatFriendlyDate, toDraft } from '../lib/draft';
import {
  readDraftPreviewSnapshot,
  resolveLocalPreviewHref,
  resolvePublishedSiteHref,
} from '../lib/preview';
import { resolveStudioPath } from '../lib/runtime';
import { PagePreview } from './PagePreview';

function slugValue(row: ResourceRow | null | undefined): string | null {
  return row && typeof row.slug === 'string' && row.slug.trim() ? row.slug.trim() : null;
}

function previewPathFromSplat(splat: string | undefined): string {
  if (!splat || splat === '/') {
    return '/';
  }

  const trimmed = splat.replace(/^\/+|\/+$/g, '');
  return trimmed ? `/${trimmed}` : '/';
}

export function SitePreviewScreen() {
  const { workspaceSlug, '*': previewSplat } = useParams();
  const [searchParams] = useSearchParams();
  const previewPath = previewPathFromSplat(previewSplat);
  const snapshot = readDraftPreviewSnapshot(searchParams.get('draft'));
  const snapshotWorkspaceSlug = slugValue(snapshot?.workspace);
  const snapshotMatchesRoute =
    previewPath !== '/' &&
    snapshot != null &&
    snapshot.previewPath === previewPath &&
    snapshotWorkspaceSlug === workspaceSlug;

  const workspacesQuery = useQuery({
    queryKey: ['site-preview', 'workspaces'],
    queryFn: () => listResource<ResourceRow>('workspaces', { limit: 10, context: 'view' }),
  });
  const entriesQuery = useQuery({
    queryKey: ['site-preview', 'entries'],
    queryFn: () => listResource<ResourceRow>('entries', { limit: 100, context: 'edit' }),
    enabled: workspacesQuery.isSuccess,
  });
  const assetsQuery = useQuery({
    queryKey: ['site-preview', 'assets'],
    queryFn: () => listResource<ResourceRow>('assets', { limit: 100, context: 'edit' }),
    enabled: workspacesQuery.isSuccess,
  });

  const workspaceRows = workspacesQuery.data?.items ?? [];
  const resolvedWorkspace =
    workspaceRows.find((row) => slugValue(row) === workspaceSlug) ??
    (snapshotMatchesRoute ? (snapshot?.workspace ?? null) : null);
  const workspaceName =
    resolvedWorkspace && typeof resolvedWorkspace.name === 'string' && resolvedWorkspace.name.trim()
      ? resolvedWorkspace.name.trim()
      : 'Workspace preview';
  const publishedSiteHref = resolvePublishedSiteHref(resolvedWorkspace, '/');
  const entryRows = entriesQuery.data?.items ?? [];
  const entrySlug = previewPath === '/' ? null : previewPath.slice(1);
  const savedEntry =
    entrySlug != null
      ? (entryRows.find((row) => String(row.slug ?? '') === entrySlug) ?? null)
      : null;
  const rootEntries = useMemo(() => {
    if (entryRows.length === 0) {
      return [];
    }

    const published = entryRows.filter((row) => row.status === 'published');
    return (published.length > 0 ? published : entryRows).slice(0, 8);
  }, [entryRows]);
  const featuredEntry = entrySlug == null ? (rootEntries[0] ?? null) : null;
  const activeEntry = snapshotMatchesRoute ? null : (savedEntry ?? featuredEntry);
  const activeEntryId =
    activeEntry && typeof activeEntry.id === 'number' ? activeEntry.id : undefined;
  const topicsQuery = useQuery({
    queryKey: ['site-preview', 'topics', activeEntryId],
    queryFn: () =>
      listResource<ResourceRow>(`entries/${String(activeEntryId)}/topics`, {
        limit: 50,
        context: 'edit',
      }),
    enabled: activeEntryId != null,
  });

  const assets = snapshotMatchesRoute ? snapshot.assets : (assetsQuery.data?.items ?? []);
  const assetsById = new Map(
    assets
      .map((asset) => {
        const id = Number(asset.id);
        return Number.isNaN(id) ? null : ([id, asset] as const);
      })
      .filter(Boolean) as Array<readonly [number, ResourceRow]>,
  );
  const previewDraft =
    snapshotMatchesRoute
      ? snapshot.draft
      : activeEntry
        ? toDraft(entryResource, activeEntry)
        : null;
  const previewTopics = snapshotMatchesRoute
    ? snapshot.selectedTopics
    : (topicsQuery.data?.items ?? []);
  const previewError =
    workspacesQuery.error ?? entriesQuery.error ?? assetsQuery.error ?? topicsQuery.error;

  if (workspacesQuery.isLoading || (!snapshotMatchesRoute && entriesQuery.isLoading)) {
    return (
      <Box className="site-preview-loading">
        <Stack alignItems="center" spacing={2.5}>
          <CircularProgress />
          <Typography color="text.secondary">Preparing the local site preview…</Typography>
        </Stack>
      </Box>
    );
  }

  if (!workspaceSlug || !resolvedWorkspace) {
    return (
      <Box className="site-preview-shell">
        <Box className="site-preview-topbar">
          <Stack spacing={1}>
            <Typography variant="overline">Local site preview</Typography>
            <Typography variant="h3">Workspace not available</Typography>
            <Typography color="text.secondary" maxWidth={720}>
              The requested workspace slug is not visible to the current session, so the CMS cannot
              render a site preview from this route.
            </Typography>
          </Stack>
          <Button
            component="a"
            href={resolveStudioPath('/')}
            startIcon={<ArrowBackRounded />}
            variant="outlined"
          >
            Back to studio
          </Button>
        </Box>
        <Alert severity="warning" variant="outlined">
          Open the studio workspace first so the current session has access to the site data.
        </Alert>
      </Box>
    );
  }

  if (previewError) {
    return (
      <Box className="site-preview-shell">
        <Box className="site-preview-topbar">
          <Stack spacing={1}>
            <Typography variant="overline">Local site preview</Typography>
            <Typography variant="h3">Preview unavailable</Typography>
            <Typography color="text.secondary" maxWidth={720}>
              The CMS could not load one or more API resources required for the local site preview.
            </Typography>
          </Stack>
          <Button
            component="a"
            href={resolveStudioPath('/')}
            startIcon={<ArrowBackRounded />}
            variant="outlined"
          >
            Back to studio
          </Button>
        </Box>
        <Alert severity="error" variant="outlined">
          {previewError instanceof Error
            ? previewError.message
            : 'Unable to load local preview data.'}
        </Alert>
      </Box>
    );
  }

  const heroEntry = entrySlug == null ? featuredEntry : (savedEntry ?? null);
  const heroEntryHref =
    heroEntry && typeof heroEntry.slug === 'string'
      ? resolveLocalPreviewHref(workspaceSlug, `/${heroEntry.slug}`)
      : null;

  return (
    <Box className="site-preview-shell">
      <Box className="site-preview-topbar">
        <Stack spacing={1}>
          <Typography variant="overline">Local site preview</Typography>
          <Typography variant="h3">{workspaceName}</Typography>
          <Typography color="text.secondary" maxWidth={760}>
            This route previews the workspace locally from the same CMS app, so editors can open
            entry paths without inventing a fake published origin.
          </Typography>
        </Stack>

        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
          <Button
            component="a"
            href={resolveStudioPath('/')}
            startIcon={<ArrowBackRounded />}
            variant="outlined"
          >
            Back to studio
          </Button>
          {publishedSiteHref ? (
            <Button
              component="a"
              endIcon={<LaunchRounded />}
              href={publishedSiteHref}
              rel="noreferrer"
              target="_blank"
              variant="outlined"
            >
              Open published origin
            </Button>
          ) : null}
        </Stack>
      </Box>

      <Box className="site-preview-meta">
        <Box>
          <Typography className="studio-overline">Workspace slug</Typography>
          <Typography fontWeight={700}>/{workspaceSlug}</Typography>
        </Box>
        <Box>
          <Typography className="studio-overline">Preview route</Typography>
          <Typography color="text.secondary">
            {resolveLocalPreviewHref(workspaceSlug, previewPath)}
          </Typography>
        </Box>
        <Box>
          <Typography className="studio-overline">Published origin</Typography>
          <Typography color="text.secondary">
            {publishedSiteHref ?? 'Not configured'}
          </Typography>
        </Box>
      </Box>

      {previewPath !== '/' && !snapshotMatchesRoute && !savedEntry ? (
        <Alert severity="warning" variant="outlined">
          No saved entry exists yet for <code>{previewPath}</code>. Save the draft from the studio
          or open the local preview directly from the editor to include unsaved changes.
        </Alert>
      ) : null}

      {previewDraft ? (
        <PagePreview
          assetsById={assetsById}
          draft={previewDraft}
          headerAction={{
            href: resolveStudioPath('/entries'),
            label: 'Back to entries',
            target: '_self',
          }}
          mode="desktop"
          selectedTopics={previewTopics}
          standalone
          workspace={resolvedWorkspace}
        />
      ) : null}

      {previewPath === '/' ? (
        <Box className="site-preview-storyGrid">
          <Box className="site-preview-storyLead">
            <Typography variant="h4">Workspace index</Typography>
            <Typography color="text.secondary">
              Use these entry paths to inspect the current site locally. Published entries are
              prioritized first, and the studio falls back to saved drafts when nothing has been
              published yet.
            </Typography>
          </Box>

          {rootEntries.length > 0 ? (
            <Box className="site-preview-storyList">
              {rootEntries.map((entry) => {
                const entryPath = `/${String(entry.slug ?? '')}`.replace(/\/{2,}/g, '/');
                const entryHref = resolveLocalPreviewHref(workspaceSlug, entryPath);

                return (
                  <Box className="site-preview-storyCard" key={String(entry.id ?? entryPath)}>
                    <Stack spacing={0.75}>
                      <Typography variant="h5">
                        {String(entry.title ?? 'Untitled entry')}
                      </Typography>
                      <Typography color="text.secondary" variant="body2">
                        {String(
                          entry.summary ??
                            entry.permalink ??
                            'No summary yet. Open the entry to inspect the local rendering.',
                        )}
                      </Typography>
                    </Stack>

                    <Stack direction="row" flexWrap="wrap" spacing={1} useFlexGap>
                      <Typography className="studio-overline">
                        {String(entry.status ?? 'draft')}
                      </Typography>
                      <Typography color="text.secondary" variant="body2">
                        {formatFriendlyDate(entry.published_at)}
                      </Typography>
                    </Stack>

                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                      <Button
                        component="a"
                        endIcon={<VisibilityRounded />}
                        href={entryHref}
                        variant="contained"
                      >
                        Open local path
                      </Button>
                      {heroEntryHref && heroEntryHref === entryHref ? (
                        <Typography color="text.secondary" sx={{ alignSelf: 'center' }} variant="body2">
                          Featured above
                        </Typography>
                      ) : null}
                    </Stack>
                  </Box>
                );
              })}
            </Box>
          ) : (
            <Alert severity="info" variant="outlined">
              No entries are available in this workspace yet. Create a story in the studio and reopen
              the local preview route.
            </Alert>
          )}
        </Box>
      ) : null}
    </Box>
  );
}
