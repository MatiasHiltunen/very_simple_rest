import { startTransition, useDeferredValue, useState } from 'react';
import {
  AddRounded,
  DeleteOutlineRounded,
  DesktopWindowsRounded,
  MoreHorizRounded,
  PhoneIphoneRounded,
  RefreshRounded,
  SaveRounded,
  ViewListRounded,
} from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  useMediaQuery,
  InputAdornment,
  Paper,
  Snackbar,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query';
import {
  ApiError,
  createResource,
  deleteResource,
  listResource,
  runResourceAction,
  updateResource,
  type AuthMeResponse,
  type JsonValue,
} from '../lib/api';
import { entryResource, type FieldConfig, type ResourceRow } from '../lib/cms';
import {
  buildRelationOption,
  serializeDraft,
  serializeSelectionIds,
  syncRelationSelections,
  toDraft,
  type DraftState,
  type FieldErrors,
  type Notice,
  type RelationOption,
} from '../lib/draft';
import {
  createDraftPreviewHref,
  resolveLocalPreviewHref,
  resolvePublishedSiteHref,
} from '../lib/preview';
import { FieldInput } from './FieldInput';
import { PagePreview } from './PagePreview';
import { ConfirmDialog } from './ConfirmDialog';
import { ScopeNotice } from './ScopeNotice';
import { WorkspaceDialog } from './WorkspaceDialog';

const EMPTY_ROWS: ResourceRow[] = [];

function isWideField(field: FieldConfig): boolean {
  return (
    field.kind === 'textarea' ||
    field.kind === 'json' ||
    field.kind === 'jsonArray' ||
    field.kind === 'blocks' ||
    field.kind === 'seo' ||
    field.kind === 'entrySettings'
  );
}

function draftsEqual(left: DraftState, right: DraftState): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function EntryWorkspace({ account }: { account: AuthMeResponse }) {
  const theme = useTheme();
  const compactWorkspace = useMediaQuery(theme.breakpoints.down('md'));
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [previewMode, setPreviewMode] = useState<'desktop' | 'mobile'>('desktop');
  const [notice, setNotice] = useState<Notice>(null);
  const [activeKey, setActiveKey] = useState<string>('new');
  const [selectedRow, setSelectedRow] = useState<ResourceRow | null>(null);
  const [draft, setDraft] = useState<DraftState>(() => toDraft(entryResource));
  const [baselineDraft, setBaselineDraft] = useState<DraftState>(() => toDraft(entryResource));
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [mobileListOpen, setMobileListOpen] = useState(false);
  const [mobilePreviewOpen, setMobilePreviewOpen] = useState(false);
  const [mobileActionsOpen, setMobileActionsOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState<
    | { kind: 'create' }
    | { kind: 'entry'; row: ResourceRow }
    | null
  >(null);
  const deferredSearch = useDeferredValue(search);
  const dirty = !draftsEqual(draft, baselineDraft);

  const [entriesQuery, assetsQuery, topicsQuery, reviewersQuery, workspacesQuery] = useQueries({
    queries: [
      {
        queryKey: ['entries', 'workspace'],
        queryFn: () => listResource<ResourceRow>('entries', { limit: 50, context: 'edit' }),
      },
      {
        queryKey: ['entries', 'assets'],
        queryFn: () => listResource<ResourceRow>('assets', { limit: 100, context: 'edit' }),
      },
      {
        queryKey: ['entries', 'topics'],
        queryFn: () => listResource<ResourceRow>('topics', { limit: 100, context: 'edit' }),
      },
      {
        queryKey: ['entries', 'reviewers'],
        queryFn: () => listResource<ResourceRow>('auth/admin/users', { limit: 100 }),
      },
      {
        queryKey: ['entries', 'workspaces', account.workspace_id],
        queryFn: () => listResource<ResourceRow>('workspaces', { limit: 10, context: 'admin' }),
      },
    ],
  });

  const rows = entriesQuery.data?.items ?? EMPTY_ROWS;
  const assets = assetsQuery.data?.items ?? [];
  const topics = topicsQuery.data?.items ?? [];
  const reviewers = reviewersQuery.data?.items ?? [];
  const workspaceRows = workspacesQuery.data?.items ?? [];
  const workspace =
    typeof account.workspace_id === 'number'
      ? (workspaceRows.find((row) => Number(row.id) === account.workspace_id) ?? null)
      : (workspaceRows[0] ?? null);

  const filteredRows = rows.filter((row) => {
    const searchQuery = deferredSearch.trim().toLowerCase();
    const matchesSearch =
      !searchQuery ||
      entryResource.searchKeys.some((key) =>
        String(row[key] ?? '')
          .toLowerCase()
          .includes(searchQuery),
      );
    const matchesStatus = statusFilter === 'all' || row.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const loadEntryTopics = async (entryId: number) => {
    const relationRows = await queryClient.fetchQuery({
      queryKey: ['entry-topics-for-entry', entryId],
      queryFn: () =>
        listResource<ResourceRow>(`entries/${String(entryId)}/topics`, {
          limit: 100,
          context: 'edit',
        }),
      staleTime: 30_000,
    });

    const nextTopics = serializeSelectionIds(
      relationRows.items
        .map((item) => String(item.id ?? ''))
        .filter(Boolean),
    );

    setDraft((current) => ({ ...current, topics: nextTopics }));
    setBaselineDraft((current) => ({ ...current, topics: nextTopics }));
  };

  const activateEntry = (row: ResourceRow) => {
    const nextDraft = toDraft(entryResource, row);
    startTransition(() => {
      setActiveKey(String(row.id ?? 'new'));
      setSelectedRow(row);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setMobileListOpen(false);
    });

    const entryId = Number(row.id);
    if (!Number.isNaN(entryId)) {
      void loadEntryTopics(entryId);
    }
  };

  const openEntry = (row: ResourceRow) => {
    if (dirty) {
      setPendingNavigation({ kind: 'entry', row });
      return;
    }

    activateEntry(row);
  };

  const activateCreate = () => {
    const nextDraft = toDraft(entryResource);
    startTransition(() => {
      setActiveKey('new');
      setSelectedRow(null);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setMobileListOpen(false);
    });
  };

  const openCreate = () => {
    if (dirty) {
      setPendingNavigation({ kind: 'create' });
      return;
    }

    activateCreate();
  };

  const confirmPendingNavigation = () => {
    if (!pendingNavigation) {
      return;
    }

    if (pendingNavigation.kind === 'create') {
      activateCreate();
    } else {
      activateEntry(pendingNavigation.row);
    }
    setPendingNavigation(null);
  };

  const resetDraft = () => {
    setDraft(baselineDraft);
    setFieldErrors({});
    setMobileActionsOpen(false);
  };

  const assetRelation = entryResource.fields.find((field) => field.key === 'hero_asset')?.relation;
  const topicRelation = entryResource.fields.find((field) => field.key === 'topics')?.relation;
  const reviewerRelation = entryResource.fields.find((field) => field.key === 'reviewer')?.relation;

  const relationOptions: Record<string, RelationOption[]> = {
    hero_asset: assetRelation ? assets.map((item) => buildRelationOption(item, assetRelation)) : [],
    topics: topicRelation ? topics.map((item) => buildRelationOption(item, topicRelation)) : [],
    reviewer: reviewerRelation
      ? reviewers.map((item) => buildRelationOption(item, reviewerRelation))
      : [],
  };

  const assetsById = new Map(
    assets
      .map((asset) => {
        const id = Number(asset.id);
        return Number.isNaN(id) ? null : ([id, asset] as const);
      })
      .filter(Boolean) as Array<readonly [number, ResourceRow]>,
  );

  const selectedTopics = draft.topics
    ? draft.topics
        .split(',')
        .map((id) => topics.find((topic) => String(topic.id ?? '') === id))
        .filter((topic): topic is ResourceRow => Boolean(topic))
    : [];
  const previewPath = draft.slug?.trim() ? `/${draft.slug.trim()}` : '/untitled';
  const workspaceSlug =
    typeof workspace?.slug === 'string' && workspace.slug.trim() ? workspace.slug.trim() : null;
  const previewHref = workspaceSlug
    ? resolveLocalPreviewHref(workspaceSlug, previewPath)
    : (resolvePublishedSiteHref(workspace, previewPath) ?? previewPath);

  const openPreviewWindow = () => {
    if (typeof window === 'undefined') {
      return;
    }

    const href = workspaceSlug
      ? createDraftPreviewHref(workspaceSlug, previewPath, {
          previewPath,
          workspace,
          draft,
          selectedTopics,
          assets: Array.from(assetsById.values()),
        })
      : previewHref;

    window.open(href, '_blank', 'noopener,noreferrer');
  };

  const syncedRelationFields = entryResource.fields.filter(
    (field): field is FieldConfig & { relationSync: NonNullable<FieldConfig['relationSync']> } =>
      field.kind === 'relationMulti' && Boolean(field.relationSync),
  );

  const saveMutation = useMutation({
    mutationFn: async ({
      id,
      body,
      relationDraft,
    }: {
      id?: number;
      body: Record<string, JsonValue>;
      relationDraft: DraftState;
    }) => {
      const saved =
        typeof id === 'number'
          ? await updateResource<ResourceRow>(entryResource.path, id, body)
          : await createResource<ResourceRow>(entryResource.path, body);

      const savedId = Number(saved.id);
      if (!Number.isNaN(savedId)) {
        for (const field of syncedRelationFields) {
          await syncRelationSelections(field, savedId, relationDraft[field.key] ?? '');
        }
      }

      return saved;
    },
    onSuccess: async (saved) => {
      await queryClient.invalidateQueries();
      const nextDraft = toDraft(entryResource, saved);
      nextDraft.topics = draft.topics ?? '';
      setActiveKey(String(saved.id ?? 'new'));
      setSelectedRow(saved);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setNotice({
        severity: 'success',
        message: `${selectedRow ? 'Entry updated' : 'Entry created'} successfully.`,
      });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.field) {
        setFieldErrors({ [error.field]: error.message });
      }
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to save entry.',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (row: ResourceRow) => {
      const id = Number(row.id);
      if (Number.isNaN(id)) {
        throw new Error('Unable to delete the selected entry without a valid id.');
      }

      await deleteResource(entryResource.path, id);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries();
      const emptyDraft = toDraft(entryResource);
      setActiveKey('new');
      setSelectedRow(null);
      setDraft(emptyDraft);
      setBaselineDraft(emptyDraft);
      setDeleteDialogOpen(false);
      setMobileActionsOpen(false);
      setNotice({
        severity: 'success',
        message: 'Entry deleted.',
      });
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to delete entry.',
      });
    },
  });

  const actionMutation = useMutation({
    mutationFn: ({ id, action }: { id: number; action: string }) =>
      runResourceAction(entryResource.path, id, action),
    onSuccess: async (_, variables) => {
      await queryClient.invalidateQueries();
      setNotice({
        severity: 'success',
        message: `Entry action "${variables.action}" completed.`,
      });
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to run action.',
      });
    },
  });

  const submitEditor = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFieldErrors({});
    try {
      const body = serializeDraft(entryResource, draft);
      await saveMutation.mutateAsync({
        id: typeof selectedRow?.id === 'number' ? selectedRow.id : undefined,
        body,
        relationDraft: draft,
      });
    } catch (error) {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to parse the form values.',
      });
    }
  };

  const railContent = (
    <Stack spacing={2}>
      <Stack spacing={1}>
        <Typography variant="overline">Live composer</Typography>
        <Typography variant="h5">{entryResource.description}</Typography>
      </Stack>

      {rows.length === 0 ? <ScopeNotice account={account} label="Entries" /> : null}

      <TextField
        InputProps={{
          startAdornment: <InputAdornment position="start">Search</InputAdornment>,
        }}
        label="Search entries"
        onChange={(event) => setSearch(event.target.value)}
        value={search}
      />

      <TextField
        label="Status filter"
        onChange={(event) => setStatusFilter(event.target.value)}
        select
        SelectProps={{ native: true }}
        value={statusFilter}
      >
        <option value="all">all statuses</option>
        {['draft', 'in_review', 'scheduled', 'published', 'archived'].map((status) => (
          <option key={status} value={status}>
            {status.replaceAll('_', ' ')}
          </option>
        ))}
      </TextField>

      <Button onClick={openCreate} startIcon={<AddRounded />} variant="contained">
        New entry
      </Button>

      {entriesQuery.isLoading ? (
        <Alert severity="info" variant="outlined">
          Loading entries…
        </Alert>
      ) : entriesQuery.error ? (
        <Alert severity="error" variant="outlined">
          {entriesQuery.error instanceof Error
            ? entriesQuery.error.message
            : 'Unable to load entries.'}
        </Alert>
      ) : filteredRows.length > 0 ? (
        <Box className="record-list">
          {filteredRows.map((row) => (
            <button
              className="record-item"
              data-selected={activeKey === String(row.id ?? '')}
              key={String(row.id)}
              onClick={() => openEntry(row)}
              type="button"
            >
              <Box className="record-itemHeader">
                <Box>
                  <Typography className="record-itemTitle">{entryResource.itemTitle(row)}</Typography>
                  <Typography className="record-itemMeta">{entryResource.itemSubtitle(row)}</Typography>
                </Box>
              </Box>
              <Box className="record-itemFooter">
                <Typography className="studio-overline">
                  {entryResource.itemBadge?.(row) ?? 'draft'}
                </Typography>
                <Typography className="record-itemMeta">
                  {String(row.type ?? 'article')} · {String(row.visibility ?? 'workspace')}
                </Typography>
              </Box>
            </button>
          ))}
        </Box>
      ) : (
        <Box className="empty-state">
          <Typography fontWeight={700}>No entries in this view</Typography>
          <Typography variant="body2">
            {typeof account.workspace_id !== 'number'
              ? 'Assign a workspace claim first, then create or review entries in that scope.'
              : 'Create a draft or widen the search to bring stories back into focus.'}
          </Typography>
        </Box>
      )}
    </Stack>
  );

  const previewContent = (
    <Stack spacing={2}>
      <Stack direction="row" justifyContent="space-between" spacing={1}>
        <Box className="studio-sectionHeader">
          <Typography variant="h5">Rendered page</Typography>
          <Typography color="text.secondary" variant="body2">
            Switch between desktop and mobile while editing the same draft.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Button
            onClick={() => setPreviewMode('desktop')}
            startIcon={<DesktopWindowsRounded />}
            variant={previewMode === 'desktop' ? 'contained' : 'outlined'}
          >
            Desktop
          </Button>
          <Button
            onClick={() => setPreviewMode('mobile')}
            startIcon={<PhoneIphoneRounded />}
            variant={previewMode === 'mobile' ? 'contained' : 'outlined'}
          >
            Mobile
          </Button>
        </Stack>
      </Stack>

      <PagePreview
        assetsById={assetsById}
        draft={draft}
        headerAction={{
          href: previewHref,
          label: workspaceSlug ? 'Open local preview' : 'Open path',
          onClick: openPreviewWindow,
        }}
        mode={previewMode}
        selectedTopics={selectedTopics}
        workspace={workspace}
      />
    </Stack>
  );

  const mobileActionContent = (
    <Stack spacing={1.5}>
      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={0.75}>
          <Typography fontWeight={700}>{draft.title?.trim() || 'Untitled story'}</Typography>
          <Typography color="text.secondary" variant="body2">
            {selectedRow
              ? 'Publishing actions live here so the editor can stay focused on the story.'
              : 'Save the draft first to unlock review, publish, and archive actions.'}
          </Typography>
        </Stack>
      </Paper>
      <Button fullWidth onClick={resetDraft} startIcon={<RefreshRounded />} variant="outlined">
        Reset draft
      </Button>
      {selectedRow ? (
        <Button
          color="error"
          fullWidth
          onClick={() => setDeleteDialogOpen(true)}
          startIcon={<DeleteOutlineRounded />}
          variant="outlined"
        >
          Delete entry
        </Button>
      ) : null}
      {entryResource.actions?.map((action) => (
        <Button
          color={action.tone ?? 'primary'}
          disabled={typeof selectedRow?.id !== 'number' || actionMutation.isPending}
          fullWidth
          key={action.key}
          onClick={() => {
            if (typeof selectedRow?.id === 'number') {
              actionMutation.mutate({ id: selectedRow.id, action: action.key });
              setMobileActionsOpen(false);
            }
          }}
          variant="outlined"
        >
          {action.label}
        </Button>
      ))}
    </Stack>
  );

  return (
    <Box className="workspace-grid workspace-grid--entry">
      {!compactWorkspace ? (
        <Paper className="studio-panel rail-scroll workspace-pane workspace-pane--rail" sx={{ p: 2 }}>
          {railContent}
        </Paper>
      ) : null}

      <Paper
        className="studio-panel editor-scroll workspace-pane workspace-pane--editor"
        component="form"
        onSubmit={submitEditor}
        sx={{ p: { xs: 2, md: 3 } }}
      >
        <Stack direction={{ xs: 'column', lg: 'row' }} justifyContent="space-between" spacing={2}>
          <Stack spacing={0.75}>
            <Typography variant="overline">
              {selectedRow ? `${draft.status || 'draft'} entry` : 'New entry draft'}
            </Typography>
            <Typography variant="h4">
              {draft.title?.trim() || 'Untitled story'}
            </Typography>
            <Box className="status-line">
              <span className="status-pulse" />
              <Typography color="text.secondary" variant="body2">
                {dirty ? 'Preview includes unsaved edits' : 'Preview matches the current saved draft'}
              </Typography>
            </Box>
          </Stack>

          {!compactWorkspace ? (
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
              <Button onClick={resetDraft} startIcon={<RefreshRounded />} variant="outlined">
                Reset
              </Button>
              {selectedRow ? (
                <Button
                  color="error"
                  onClick={() => setDeleteDialogOpen(true)}
                  startIcon={<DeleteOutlineRounded />}
                  variant="outlined"
                >
                  Delete
                </Button>
              ) : null}
              <Button
                disabled={saveMutation.isPending}
                startIcon={<SaveRounded />}
                type="submit"
                variant="contained"
              >
                {saveMutation.isPending ? 'Saving…' : 'Save draft'}
              </Button>
            </Stack>
          ) : null}
        </Stack>

        {compactWorkspace ? (
          <Box className="workspace-mobileToolbar">
            <Button
              onClick={() => setMobileListOpen(true)}
              size="small"
              startIcon={<ViewListRounded />}
              variant="outlined"
            >
              Records
            </Button>
            <Button
              onClick={() => setMobilePreviewOpen(true)}
              size="small"
              startIcon={<DesktopWindowsRounded />}
              variant="outlined"
            >
              Preview
            </Button>
            <Button
              onClick={() => setMobileActionsOpen(true)}
              size="small"
              startIcon={<MoreHorizRounded />}
              variant="outlined"
            >
              Actions
            </Button>
            <Button
              disabled={saveMutation.isPending}
              size="small"
              startIcon={<SaveRounded />}
              type="submit"
              variant="contained"
            >
              {saveMutation.isPending ? 'Saving…' : 'Save draft'}
            </Button>
          </Box>
        ) : (
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} flexWrap="wrap">
            {entryResource.actions?.map((action) => (
              <Button
                color={action.tone ?? 'primary'}
                disabled={typeof selectedRow?.id !== 'number' || actionMutation.isPending}
                key={action.key}
                onClick={() =>
                  typeof selectedRow?.id === 'number'
                    ? actionMutation.mutate({ id: selectedRow.id, action: action.key })
                    : undefined
                }
                variant="outlined"
              >
                {action.label}
              </Button>
            ))}
          </Stack>
        )}

        <Stack spacing={2.5}>
          {entryResource.fieldSections.map((section) => (
            <Paper className="studio-panelTight" key={section.title} sx={{ p: 2 }}>
              <Stack spacing={2}>
                <Box className="studio-sectionHeader">
                  <Typography variant="h6">{section.title}</Typography>
                  <Typography color="text.secondary" variant="body2">
                    {section.description}
                  </Typography>
                </Box>

                <Box
                  sx={{
                    display: 'grid',
                    gap: 2,
                    gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
                  }}
                >
                  {section.fields.map((fieldKey) => {
                    const field = entryResource.fields.find((item) => item.key === fieldKey);
                    if (!field) {
                      return null;
                    }

                    return (
                      <Box
                        key={field.key}
                        sx={isWideField(field) ? { gridColumn: '1 / -1' } : undefined}
                      >
                        <FieldInput
                          currentItemId={typeof selectedRow?.id === 'number' ? selectedRow.id : undefined}
                          error={fieldErrors[field.key]}
                          field={field}
                          onChange={(value) => setDraft((current) => ({ ...current, [field.key]: value }))}
                          onClearError={() =>
                            setFieldErrors((current) => {
                              if (!current[field.key]) {
                                return current;
                              }
                              const next = { ...current };
                              delete next[field.key];
                              return next;
                            })
                          }
                          relationError={undefined}
                          relationLoading={
                            field.key === 'hero_asset'
                              ? assetsQuery.isLoading
                              : field.key === 'reviewer'
                                ? reviewersQuery.isLoading
                                : field.key === 'topics'
                                  ? topicsQuery.isLoading
                                  : false
                          }
                          relationOptions={relationOptions[field.key] ?? []}
                          blockAssetOptions={relationOptions.hero_asset ?? []}
                          value={draft[field.key] ?? ''}
                        />
                      </Box>
                    );
                  })}
                </Box>
              </Stack>
            </Paper>
          ))}
        </Stack>
      </Paper>

      {!compactWorkspace ? (
        <Paper className="studio-panel preview-scroll workspace-pane workspace-pane--preview" sx={{ p: { xs: 2, md: 3 } }}>
          {previewContent}
        </Paper>
      ) : null}

      <WorkspaceDialog
        label="Entry browser"
        onClose={() => setMobileListOpen(false)}
        open={mobileListOpen}
        title="Choose or create a story"
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {railContent}
        </Paper>
      </WorkspaceDialog>

      <WorkspaceDialog
        label="Rendered page"
        onClose={() => setMobilePreviewOpen(false)}
        open={mobilePreviewOpen}
        title="Preview the current draft"
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {previewContent}
        </Paper>
      </WorkspaceDialog>

      <WorkspaceDialog
        label="Entry actions"
        onClose={() => setMobileActionsOpen(false)}
        open={mobileActionsOpen}
        title="Manage the current draft actions"
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {mobileActionContent}
        </Paper>
      </WorkspaceDialog>

      <ConfirmDialog
        body={
          selectedRow
            ? `Delete ${draft.title?.trim() || 'this entry'} from the current workspace?`
            : 'Delete this entry?'
        }
        confirmLabel={deleteMutation.isPending ? 'Deleting…' : 'Delete entry'}
        onClose={() => setDeleteDialogOpen(false)}
        onConfirm={() => (selectedRow ? deleteMutation.mutate(selectedRow) : undefined)}
        open={deleteDialogOpen}
        title="Delete entry"
      />

      <ConfirmDialog
        body="Discard the current unsaved edits and switch to another draft?"
        confirmLabel="Discard changes"
        onClose={() => setPendingNavigation(null)}
        onConfirm={confirmPendingNavigation}
        open={Boolean(pendingNavigation)}
        title="Leave current draft"
        tone="primary"
      />

      <Snackbar autoHideDuration={4200} onClose={() => setNotice(null)} open={Boolean(notice)}>
        <Alert onClose={() => setNotice(null)} severity={notice?.severity ?? 'success'} variant="filled">
          {notice?.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}
