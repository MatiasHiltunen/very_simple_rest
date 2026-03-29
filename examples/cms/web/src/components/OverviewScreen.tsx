import { AutoAwesomeRounded, LaunchRounded } from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  Chip,
  Paper,
  Stack,
  Typography,
} from '@mui/material';
import { useMutation, useQueries } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';
import {
  createResource,
  listResource,
  updateManagedUser,
  type AuthMeResponse,
} from '../lib/api';
import { cmsResources, type ResourceRow } from '../lib/cms';
import { deriveWorkspaceSeed } from '../lib/draft';
import { formatMethodLabel, getOperationsForResource } from '../lib/openapi';

export function OverviewScreen({
  account,
  onReloginRequired,
}: {
  account: AuthMeResponse;
  onReloginRequired: (message: string) => void;
}) {
  const workspaceSeed = deriveWorkspaceSeed(account);
  const [entriesQuery, assetsQuery, topicsQuery, menusQuery, workspacesQuery] = useQueries({
    queries: [
      {
        queryKey: ['overview', 'entries'],
        queryFn: () => listResource<ResourceRow>('entries', { limit: 50, context: 'edit' }),
      },
      {
        queryKey: ['overview', 'assets'],
        queryFn: () => listResource<ResourceRow>('assets', { limit: 100, context: 'edit' }),
      },
      {
        queryKey: ['overview', 'topics'],
        queryFn: () => listResource<ResourceRow>('topics', { limit: 100, context: 'edit' }),
      },
      {
        queryKey: ['overview', 'menus'],
        queryFn: () => listResource<ResourceRow>('menus', { limit: 100, context: 'edit' }),
      },
      {
        queryKey: ['overview', 'workspaces'],
        queryFn: () => listResource<ResourceRow>('workspaces', { limit: 10, context: 'admin' }),
      },
    ],
  });

  const recentEntries = entriesQuery.data?.items ?? [];
  const publishedCount = recentEntries.filter((entry) => entry.status === 'published').length;
  const reviewCount = recentEntries.filter((entry) => entry.status === 'in_review').length;
  const scheduledCount = recentEntries.filter((entry) => entry.status === 'scheduled').length;
  const workspaceRows = workspacesQuery.data?.items ?? [];
  const claimedWorkspace =
    typeof account.workspace_id === 'number'
      ? workspaceRows.find((item) => Number(item.id) === account.workspace_id)
      : undefined;
  const workspace = claimedWorkspace ?? workspaceRows[0] ?? null;
  const needsWorkspaceBootstrap = typeof account.workspace_id !== 'number' || !claimedWorkspace;
  const canBootstrapWorkspace = account.roles.includes('admin');

  const bootstrapMutation = useMutation({
    mutationFn: async () => {
      let targetWorkspace = workspaceRows[0];

      if (!targetWorkspace) {
        targetWorkspace = await createResource<ResourceRow>('workspaces', {
          name: workspaceSeed.name,
          slug: workspaceSeed.slug,
          default_locale: workspaceSeed.defaultLocale,
          public_base_url: workspaceSeed.publicBaseUrl,
          theme_settings: {
            palette: 'linen',
            accent: 'teal',
          },
          editorial_settings: {
            review_required: true,
            preview_mode: 'live',
            created_from: 'studio-bootstrap',
          },
        });
      }

      const workspaceId = Number(targetWorkspace.id);
      if (Number.isNaN(workspaceId)) {
        throw new Error('Workspace bootstrap did not return a valid workspace id.');
      }

      await updateManagedUser(account.id, {
        claims: {
          workspace_id: workspaceId,
        },
      });

      return {
        created: !workspaceRows[0],
        workspaceId,
        workspaceName: String(targetWorkspace.name ?? workspaceSeed.name),
      };
    },
    onSuccess: ({ created, workspaceId, workspaceName }) => {
      onReloginRequired(
        created
          ? `Workspace "${workspaceName}" was created and assigned. Sign in again to refresh the workspace claim in your session token.`
          : `Your account was assigned to workspace #${workspaceId}. Sign in again to refresh the workspace claim in your session token.`,
      );
    },
  });

  return (
    <Stack spacing={2.5}>
      <Paper className="studio-panel" sx={{ p: { xs: 2.5, md: 4 } }}>
        <Stack spacing={2.5}>
          <Box className="studio-sectionHeader">
            <Typography variant="overline">Workspace command</Typography>
            <Typography variant="h2">Monitor the content graph behind the studio.</Typography>
            <Typography color="text.secondary" maxWidth={840}>
              The frontend now reflects the real API surface in <code>openapi.json</code>:
              workspace-scoped entries, assets, topics, menus, profiles, and publishing actions.
            </Typography>
          </Box>

          <Box className="metric-strip">
            {[
              ['Entries', String(entriesQuery.data?.items.length ?? 0), `${publishedCount} published`],
              ['Assets', String(assetsQuery.data?.items.length ?? 0), 'Media ready for preview'],
              ['Topics', String(topicsQuery.data?.items.length ?? 0), `${reviewCount} stories in review`],
              ['Menus', String(menusQuery.data?.items.length ?? 0), `${scheduledCount} scheduled items`],
            ].map(([label, value, description]) => (
              <Box className="studio-panelTight" key={label} sx={{ p: 2 }}>
                <Typography className="studio-overline">{label}</Typography>
                <Typography className="metric-value">{value}</Typography>
                <Typography color="text.secondary" variant="body2">
                  {description}
                </Typography>
              </Box>
            ))}
          </Box>
        </Stack>
      </Paper>

      {needsWorkspaceBootstrap ? (
        <Paper className="studio-panel" sx={{ p: { xs: 2.5, md: 3 } }}>
          <Stack direction={{ xs: 'column', lg: 'row' }} justifyContent="space-between" spacing={2.5}>
            <Stack spacing={1}>
              <Typography variant="h5">Workspace bootstrap</Typography>
              <Typography color="text.secondary">
                The API is workspace-scoped. Without a <code>workspace_id</code> claim and a matching
                workspace row, most content routes will stay empty.
              </Typography>
              <Typography color="text.secondary" variant="body2">
                {workspaceRows.length > 0
                  ? `An existing workspace is available. The bootstrap flow will assign this account to "${String(
                      workspaceRows[0]?.name ?? workspaceRows[0]?.slug ?? 'workspace',
                    )}".`
                  : `No workspace exists yet. The studio will create "${workspaceSeed.name}" and assign the current account to it.`}
              </Typography>
            </Stack>

            <Stack spacing={1.25} sx={{ minWidth: { lg: 320 } }}>
              <Alert severity="warning" variant="outlined">
                Claim changes require a fresh login so the bearer token picks up the new workspace scope.
              </Alert>
              <Button
                disabled={!canBootstrapWorkspace || bootstrapMutation.isPending}
                onClick={() => bootstrapMutation.mutate()}
                startIcon={<AutoAwesomeRounded />}
                variant="contained"
              >
                {bootstrapMutation.isPending
                  ? 'Preparing workspace…'
                  : workspaceRows.length > 0
                    ? 'Assign workspace and refresh session'
                    : 'Create workspace and refresh session'}
              </Button>
              {!canBootstrapWorkspace ? (
                <Typography color="text.secondary" variant="body2">
                  Only admin accounts can bootstrap workspace claims from the studio.
                </Typography>
              ) : null}
              {bootstrapMutation.error instanceof Error ? (
                <Alert severity="error" variant="outlined">
                  {bootstrapMutation.error.message}
                </Alert>
              ) : null}
            </Stack>
          </Stack>
        </Paper>
      ) : null}

      <Box sx={{ display: 'grid', gap: 18, gridTemplateColumns: { xs: '1fr', xl: '1.1fr 0.9fr' } }}>
        <Paper className="studio-panel" sx={{ p: { xs: 2.5, md: 3 } }}>
          <Stack spacing={2}>
            <Box className="studio-sectionHeader">
              <Typography variant="h5">Current workspace</Typography>
              <Typography color="text.secondary">
                Identity, routing, and readiness for the active publishing scope.
              </Typography>
            </Box>

            {workspace ? (
              <Box className="studio-dataList">
                <Box className="studio-dataRow">
                  <Box>
                    <Typography fontWeight={700}>{String(workspace.name ?? 'Workspace')}</Typography>
                    <Typography color="text.secondary" variant="body2">
                      /{String(workspace.slug ?? 'workspace')}
                    </Typography>
                  </Box>
                  <Chip label={`Locale: ${String(workspace.default_locale ?? 'en')}`} variant="outlined" />
                </Box>
                <Box className="studio-dataRow">
                  <Box>
                    <Typography fontWeight={700}>Public site</Typography>
                    <Typography color="text.secondary" variant="body2">
                      {String(workspace.public_base_url ?? 'Not configured')}
                    </Typography>
                  </Box>
                  {workspace.public_base_url ? (
                    <Button
                      component="a"
                      endIcon={<LaunchRounded />}
                      href={String(workspace.public_base_url)}
                      rel="noreferrer"
                      target="_blank"
                      variant="outlined"
                    >
                      Open site
                    </Button>
                  ) : null}
                </Box>
                <Box className="studio-dataRow">
                  <Box>
                    <Typography fontWeight={700}>Account scope</Typography>
                    <Typography color="text.secondary" variant="body2">
                      {account.email ?? `User #${account.id}`}
                    </Typography>
                  </Box>
                  <Chip label={account.roles.join(', ')} variant="outlined" />
                </Box>
              </Box>
            ) : (
              <Alert severity="info" variant="outlined">
                Workspace details will appear here once the current account has a valid claim or a
                workspace has been created.
              </Alert>
            )}
          </Stack>
        </Paper>

        <Paper className="studio-panel" sx={{ p: { xs: 2.5, md: 3 } }}>
          <Stack spacing={2}>
            <Box className="studio-sectionHeader">
              <Typography variant="h5">API surface</Typography>
              <Typography color="text.secondary">
                Resource routes currently exposed by the local OpenAPI document.
              </Typography>
            </Box>

            <Box className="api-list">
              {cmsResources.map((resource) => {
                const operations = getOperationsForResource(resource.path);

                return (
                  <Box className="api-item" key={resource.key}>
                    <Box>
                      <Typography fontWeight={700}>{resource.label}</Typography>
                      <Typography className="api-itemPath">
                        {operations
                          .slice(0, 3)
                          .map((operation) => `${formatMethodLabel(operation.method)} ${operation.path}`)
                          .join(' · ')}
                      </Typography>
                    </Box>
                    <Button component={NavLink} to={`/${resource.key}`} variant="text">
                      Open
                    </Button>
                  </Box>
                );
              })}
            </Box>
          </Stack>
        </Paper>
      </Box>
    </Stack>
  );
}
