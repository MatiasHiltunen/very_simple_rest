import { startTransition, useDeferredValue, useEffect, useRef, useState } from 'react';
import {
  AddRounded,
  CloudUploadRounded,
  DeleteOutlineRounded,
  InfoRounded,
  LaunchRounded,
  MoreHorizRounded,
  RefreshRounded,
  SaveRounded,
  ViewListRounded,
} from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  InputAdornment,
  Paper,
  Snackbar,
  Stack,
  TextField,
  Typography,
  useMediaQuery,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ApiError,
  type AuthMeResponse,
  createResource,
  deleteLocalObject,
  deleteResource,
  listResource,
  updateResource,
  uploadLocalObject,
  type JsonValue,
} from '../lib/api';
import type { FieldConfig, RelationConfig, ResourceConfig, ResourceRow } from '../lib/cms';
import {
  assetPreviewEligible,
  assetPreviewUrl,
  buildRelationOption,
  guessAssetKindFromMime,
  localStorageObjectForAsset,
  mergeAssetMetadataDraft,
  readLocalImageDimensions,
  serializeDraft,
  syncRelationSelections,
  toDraft,
  type DraftState,
  type FieldErrors,
  type Notice,
  type RelationOption,
} from '../lib/draft';
import { resolveLocalPreviewHref, resolvePublishedSiteHref } from '../lib/preview';
import { formatMethodLabel, getOperationsForResource } from '../lib/openapi';
import { ConfirmDialog } from './ConfirmDialog';
import { FieldInput } from './FieldInput';
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

export function CollectionWorkspace({
  account,
  config,
}: {
  account: AuthMeResponse;
  config: ResourceConfig;
}) {
  const theme = useTheme();
  const compactWorkspace = useMediaQuery(theme.breakpoints.down('md'));
  const queryClient = useQueryClient();
  const assetFileInputRef = useRef<HTMLInputElement | null>(null);
  const [search, setSearch] = useState('');
  const [notice, setNotice] = useState<Notice>(null);
  const [activeKey, setActiveKey] = useState<string>('new');
  const [selectedRow, setSelectedRow] = useState<ResourceRow | null>(null);
  const [draft, setDraft] = useState<DraftState>(() => toDraft(config));
  const [baselineDraft, setBaselineDraft] = useState<DraftState>(() => toDraft(config));
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [assetImportSummary, setAssetImportSummary] = useState<string | null>(null);
  const [assetImportPending, setAssetImportPending] = useState(false);
  const [mobileListOpen, setMobileListOpen] = useState(false);
  const [mobileContextOpen, setMobileContextOpen] = useState(false);
  const [mobileActionsOpen, setMobileActionsOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState<
    | { kind: 'create' }
    | { kind: 'record'; row: ResourceRow }
    | null
  >(null);
  const deferredSearch = useDeferredValue(search);
  const dirty = !draftsEqual(draft, baselineDraft);

  const relationFields = config.fields.filter(
    (field): field is FieldConfig & { relation: RelationConfig } =>
      (field.kind === 'relation' || field.kind === 'relationMulti') && Boolean(field.relation),
  );
  const syncedRelationFields = config.fields.filter(
    (field): field is FieldConfig & { relationSync: NonNullable<FieldConfig['relationSync']> } =>
      field.kind === 'relationMulti' && Boolean(field.relationSync),
  );

  const resourceQuery = useQuery({
    queryKey: ['resource', config.path, config.context],
    queryFn: () =>
      listResource<ResourceRow>(config.path, {
        limit: config.listLimit ?? 50,
        context: config.context ?? 'edit',
      }),
  });

  const relationQueries = useQueries({
    queries: relationFields.map((field) => ({
      queryKey: ['relation-options', config.path, field.key, field.relation.path, field.relation.context],
      queryFn: () =>
        listResource<ResourceRow>(field.relation.path, {
          limit: field.relation.limit ?? 100,
          context: field.relation.context,
        }),
      enabled: Boolean(activeKey),
      staleTime: 60_000,
    })),
  });

  const relationOptions = Object.fromEntries(
    relationFields.map((field, index) => [
      field.key,
      (relationQueries[index]?.data?.items ?? []).map((item) => buildRelationOption(item, field.relation)),
    ]),
  ) as Record<string, RelationOption[]>;

  const relationErrors = Object.fromEntries(
    relationFields.map((field, index) => [
      field.key,
      relationQueries[index]?.error instanceof Error ? relationQueries[index].error.message : undefined,
    ]),
  ) as Record<string, string | undefined>;

  const relationLoading = Object.fromEntries(
    relationFields.map((field, index) => [field.key, Boolean(relationQueries[index]?.isLoading)]),
  ) as Record<string, boolean>;

  const relationSyncQueries = useQueries({
    queries: syncedRelationFields.map((field) => ({
      queryKey: ['relation-sync', config.path, field.key, selectedRow?.id],
      queryFn: () =>
        listResource<ResourceRow>(field.relationSync.joinPath, {
          limit: 200,
          context: field.relationSync.context ?? 'edit',
        }),
      enabled: typeof selectedRow?.id === 'number',
      staleTime: 30_000,
    })),
  });

  useEffect(() => {
    if (!selectedRow || typeof selectedRow.id !== 'number') {
      return;
    }

    setDraft((current) => {
      let changed = false;
      const next = { ...current };

      syncedRelationFields.forEach((field, index) => {
        const items = relationSyncQueries[index]?.data?.items;
        if (!items) {
          return;
        }

        const selected = items
          .filter((item) => Number(item[field.relationSync.sourceKey]) === Number(selectedRow.id))
          .map((item) => String(item[field.relationSync.targetKey] ?? ''))
          .filter(Boolean)
          .join(',');

        if ((current[field.key] ?? '') !== selected) {
          next[field.key] = selected;
          changed = true;
        }
      });

      if (changed && !dirty) {
        setBaselineDraft(next);
      }

      return changed ? next : current;
    });
  }, [dirty, relationSyncQueries, selectedRow, syncedRelationFields]);

  const rows = resourceQuery.data?.items ?? EMPTY_ROWS;
  const filteredRows = rows.filter((row) => {
    const query = deferredSearch.trim().toLowerCase();
    if (!query) {
      return true;
    }

    return config.searchKeys.some((key) =>
      String(row[key] ?? '')
        .toLowerCase()
        .includes(query),
    );
  });

  const activateRecord = (row: ResourceRow) => {
    const nextDraft = toDraft(config, row);
    startTransition(() => {
      setActiveKey(String(row.id ?? 'new'));
      setSelectedRow(row);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setAssetImportPending(false);
      setAssetImportSummary(null);
      setMobileListOpen(false);
    });
  };

  const openRecord = (row: ResourceRow) => {
    if (dirty) {
      setPendingNavigation({ kind: 'record', row });
      return;
    }

    activateRecord(row);
  };

  const activateCreate = () => {
    const nextDraft = toDraft(config);
    startTransition(() => {
      setActiveKey('new');
      setSelectedRow(null);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setAssetImportPending(false);
      setAssetImportSummary(null);
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
      activateRecord(pendingNavigation.row);
    }
    setPendingNavigation(null);
  };

  const resetDraft = () => {
    setDraft(baselineDraft);
    setFieldErrors({});
    setMobileActionsOpen(false);
  };

  const importAssetFile = async (file: File) => {
    setAssetImportPending(true);
    try {
      const [dimensions, upload] = await Promise.all([
        readLocalImageDimensions(file),
        uploadLocalObject(file),
      ]);

      setDraft((current) => ({
        ...current,
        kind: guessAssetKindFromMime(file.type || current.kind || 'application/octet-stream'),
        file_name: upload.file_name || file.name || current.file_name,
        mime_type:
          upload.content_type || file.type || current.mime_type || 'application/octet-stream',
        byte_size: String(upload.size_bytes || file.size),
        width: dimensions.width ? String(dimensions.width) : '',
        height: dimensions.height ? String(dimensions.height) : '',
        source_url: upload.public_url,
        metadata: mergeAssetMetadataDraft(current.metadata ?? '', {
          storage_bucket: upload.bucket,
          object_key: upload.object_key,
          uploaded_via: 'studio-s3',
        }),
      }));

      setAssetImportSummary(
        dimensions.width && dimensions.height
          ? `${upload.file_name} uploaded (${dimensions.width}x${dimensions.height}).`
          : `${upload.file_name} uploaded successfully.`,
      );
    } finally {
      setAssetImportPending(false);
    }
  };

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
          ? await updateResource<ResourceRow>(config.path, id, body)
          : await createResource<ResourceRow>(config.path, body);

      const savedId = Number(saved.id);
      if (!Number.isNaN(savedId)) {
        for (const field of syncedRelationFields) {
          await syncRelationSelections(field, savedId, relationDraft[field.key] ?? '');
        }
      }

      return saved;
    },
    onSuccess: async (saved, variables) => {
      await queryClient.invalidateQueries();
      const nextDraft = toDraft(config, saved);
      syncedRelationFields.forEach((field) => {
        nextDraft[field.key] = variables.relationDraft[field.key] ?? '';
      });
      setActiveKey(String(saved.id ?? 'new'));
      setSelectedRow(saved);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setNotice({
        severity: 'success',
        message: `${config.shortLabel} ${selectedRow ? 'updated' : 'created'} successfully.`,
      });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.field) {
        setFieldErrors({ [error.field]: error.message });
      }
      setNotice({
        severity: 'error',
        message:
          error instanceof Error
            ? error.message
            : `Unable to save ${config.shortLabel.toLowerCase()}.`,
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (row: ResourceRow) => {
      const id = Number(row.id);
      if (Number.isNaN(id)) {
        throw new Error(`Unable to delete ${config.shortLabel.toLowerCase()} without a valid id.`);
      }

      await deleteResource(config.path, id);

      let cleanupWarning: string | null = null;
      if (config.path === 'assets') {
        const objectRef = localStorageObjectForAsset(row);
        if (objectRef) {
          try {
            await deleteLocalObject(objectRef.bucket, objectRef.objectKey);
          } catch (error) {
            cleanupWarning =
              error instanceof Error
                ? error.message
                : 'The asset row was removed, but storage cleanup failed.';
          }
        }
      }

      return { cleanupWarning };
    },
    onSuccess: async ({ cleanupWarning }) => {
      await queryClient.invalidateQueries();
      const emptyDraft = toDraft(config);
      setActiveKey('new');
      setSelectedRow(null);
      setDraft(emptyDraft);
      setBaselineDraft(emptyDraft);
      setDeleteDialogOpen(false);
      setMobileActionsOpen(false);
      setNotice({
        severity: cleanupWarning ? 'warning' : 'success',
        message: cleanupWarning
          ? `${config.shortLabel} deleted, but storage cleanup needs attention: ${cleanupWarning}`
          : `${config.shortLabel} deleted.`,
      });
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message:
          error instanceof Error
            ? error.message
            : `Unable to delete ${config.shortLabel.toLowerCase()}.`,
      });
    },
  });

  const submitEditor = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFieldErrors({});
    try {
      const body = serializeDraft(config, draft);
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

  const assetPreviewSource = draft.source_url || assetPreviewUrl(selectedRow ?? {}) || '';
  const showAssetPreview =
    config.previewMode === 'asset' &&
    Boolean(assetPreviewSource) &&
    (draft.kind === 'image' || assetPreviewEligible(selectedRow ?? {}));

  const railContent = (
    <Stack spacing={2}>
      <Stack spacing={1}>
        <Typography variant="overline">{config.label}</Typography>
        <Typography variant="h5">{config.description}</Typography>
      </Stack>

      {rows.length === 0 && config.context !== 'admin' ? (
        <ScopeNotice account={account} label={config.label} />
      ) : null}

      <TextField
        InputProps={{
          startAdornment: <InputAdornment position="start">Search</InputAdornment>,
        }}
        label={`Search ${config.label.toLowerCase()}`}
        onChange={(event) => setSearch(event.target.value)}
        value={search}
      />

      <Button onClick={openCreate} startIcon={<AddRounded />} variant="contained">
        New {config.shortLabel}
      </Button>

      {resourceQuery.isLoading ? (
        <Alert severity="info" variant="outlined">
          Loading {config.label.toLowerCase()}…
        </Alert>
      ) : resourceQuery.error ? (
        <Alert severity="error" variant="outlined">
          {resourceQuery.error instanceof Error
            ? resourceQuery.error.message
            : `Unable to load ${config.label.toLowerCase()}.`}
        </Alert>
      ) : filteredRows.length > 0 ? (
        <Box className="record-list">
          {filteredRows.map((row) => (
            <button
              className="record-item"
              data-selected={activeKey === String(row.id ?? '')}
              key={String(row.id)}
              onClick={() => openRecord(row)}
              type="button"
            >
              <Box className="record-itemHeader">
                <Box>
                  <Typography className="record-itemTitle">{config.itemTitle(row)}</Typography>
                  <Typography className="record-itemMeta">{config.itemSubtitle(row)}</Typography>
                </Box>
              </Box>
              <Box className="record-itemFooter">
                {config.itemBadge?.(row) ? (
                  <Typography className="studio-overline">{config.itemBadge?.(row)}</Typography>
                ) : null}
                {row.id ? <Typography className="record-itemMeta">#{String(row.id)}</Typography> : null}
              </Box>
            </button>
          ))}
        </Box>
      ) : (
        <Box className="empty-state">
          <Typography fontWeight={700}>No {config.label.toLowerCase()} yet</Typography>
          <Typography variant="body2">
            {typeof account.workspace_id !== 'number' && config.context !== 'admin'
              ? `Assign a workspace claim first, then create the first ${config.shortLabel.toLowerCase()} here.`
              : `Create the first ${config.shortLabel.toLowerCase()} to start shaping this resource.`}
          </Typography>
        </Box>
      )}
    </Stack>
  );

  const contextContent = (
    <CollectionInspector
      assetPreviewSource={assetPreviewSource}
      config={config}
      draft={draft}
      selectedRow={selectedRow}
      showAssetPreview={showAssetPreview}
    />
  );

  const mobileActionContent = (
    <Stack spacing={1.5}>
      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={0.75}>
          <Typography fontWeight={700}>
            {selectedRow ? config.itemTitle(selectedRow) : `New ${config.shortLabel.toLowerCase()}`}
          </Typography>
          <Typography color="text.secondary" variant="body2">
            {selectedRow
              ? 'Keep lifecycle actions here so the editor can stay focused on the form.'
              : 'Save this draft first to unlock destructive actions and richer context.'}
          </Typography>
        </Stack>
      </Paper>
      <Button fullWidth onClick={resetDraft} startIcon={<RefreshRounded />} variant="outlined">
        Reset changes
      </Button>
      {selectedRow ? (
        <Button
          color="error"
          fullWidth
          onClick={() => setDeleteDialogOpen(true)}
          startIcon={<DeleteOutlineRounded />}
          variant="outlined"
        >
          Delete {config.shortLabel.toLowerCase()}
        </Button>
      ) : null}
    </Stack>
  );

  return (
    <Box className="workspace-grid workspace-grid--collection">
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
              {selectedRow ? `${config.shortLabel} #${String(selectedRow.id ?? '')}` : `New ${config.shortLabel}`}
            </Typography>
            <Typography variant="h4">
              {selectedRow ? config.itemTitle(selectedRow) : `Create ${config.shortLabel.toLowerCase()}`}
            </Typography>
            <Box className="status-line">
              <span className="status-pulse" />
              <Typography color="text.secondary" variant="body2">
                {dirty ? 'Unsaved changes' : 'All changes saved to the current draft'}
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
                {saveMutation.isPending ? 'Saving…' : 'Save'}
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
              onClick={() => setMobileContextOpen(true)}
              size="small"
              startIcon={<InfoRounded />}
              variant="outlined"
            >
              Context
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
              {saveMutation.isPending ? 'Saving…' : 'Save'}
            </Button>
          </Box>
        ) : null}

        {config.path === 'assets' ? (
          <Stack spacing={1.5}>
            <input
              hidden
              onChange={async (event) => {
                const file = event.target.files?.[0];
                if (!file) {
                  return;
                }

                try {
                  await importAssetFile(file);
                } catch (error) {
                  setNotice({
                    severity: 'error',
                    message:
                      error instanceof Error ? error.message : 'Unable to upload the selected file.',
                  });
                }
                event.target.value = '';
              }}
              ref={assetFileInputRef}
              type="file"
            />

            <Paper className="studio-panelTight" sx={{ p: 2 }}>
              <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={1.5}>
                <Stack spacing={0.25}>
                  <Typography fontWeight={700}>Asset intake</Typography>
                  <Typography color="text.secondary" variant="body2">
                    Upload through the local S3-compatible endpoint and let the record prefill from the stored object.
                  </Typography>
                </Stack>
                <Button
                  disabled={assetImportPending}
                  onClick={() => assetFileInputRef.current?.click()}
                  startIcon={<CloudUploadRounded />}
                  variant="outlined"
                >
                  {assetImportPending ? 'Uploading…' : 'Upload file'}
                </Button>
              </Stack>
              {assetImportSummary ? (
                <Alert severity="success" sx={{ mt: 2 }} variant="outlined">
                  {assetImportSummary}
                </Alert>
              ) : null}
            </Paper>
          </Stack>
        ) : null}

        <Stack spacing={2.5}>
          {config.fieldSections.map((section) => (
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
                    const field = config.fields.find((item) => item.key === fieldKey);
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
                          relationError={relationErrors[field.key]}
                          relationLoading={relationLoading[field.key]}
                          relationOptions={relationOptions[field.key] ?? []}
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
          {contextContent}
        </Paper>
      ) : null}

      <WorkspaceDialog
        label={config.label}
        onClose={() => setMobileListOpen(false)}
        open={mobileListOpen}
        title={`Browse ${config.label.toLowerCase()}`}
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {railContent}
        </Paper>
      </WorkspaceDialog>

      <WorkspaceDialog
        label="Resource context"
        onClose={() => setMobileContextOpen(false)}
        open={mobileContextOpen}
        title={`Inspect ${config.shortLabel.toLowerCase()} context`}
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {contextContent}
        </Paper>
      </WorkspaceDialog>

      <WorkspaceDialog
        label="Record actions"
        onClose={() => setMobileActionsOpen(false)}
        open={mobileActionsOpen}
        title={`Manage ${config.shortLabel.toLowerCase()} actions`}
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {mobileActionContent}
        </Paper>
      </WorkspaceDialog>

      <ConfirmDialog
        body={
          selectedRow
            ? `Delete this ${config.shortLabel.toLowerCase()} from the current resource list?`
            : `Delete this ${config.shortLabel.toLowerCase()}?`
        }
        confirmLabel={deleteMutation.isPending ? 'Deleting…' : `Delete ${config.shortLabel.toLowerCase()}`}
        onClose={() => setDeleteDialogOpen(false)}
        onConfirm={() => (selectedRow ? deleteMutation.mutate(selectedRow) : undefined)}
        open={deleteDialogOpen}
        title={`Delete ${config.shortLabel.toLowerCase()}`}
      />

      <ConfirmDialog
        body={`Discard the current unsaved changes and switch ${config.shortLabel.toLowerCase()} context?`}
        confirmLabel="Discard changes"
        onClose={() => setPendingNavigation(null)}
        onConfirm={confirmPendingNavigation}
        open={Boolean(pendingNavigation)}
        title={`Leave ${config.shortLabel.toLowerCase()} draft`}
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

function CollectionInspector({
  assetPreviewSource,
  config,
  draft,
  selectedRow,
  showAssetPreview,
}: {
  assetPreviewSource: string;
  config: ResourceConfig;
  draft: DraftState;
  selectedRow: ResourceRow | null;
  showAssetPreview: boolean;
}) {
  const operations = getOperationsForResource(config.path);
  const workspaceSlug = draft.slug?.trim() ? draft.slug.trim() : null;
  const localPreviewHref = workspaceSlug ? resolveLocalPreviewHref(workspaceSlug) : null;
  const publishedSiteHref = resolvePublishedSiteHref(
    draft.public_base_url ? ({ public_base_url: draft.public_base_url } as ResourceRow) : null,
    '/',
  );

  return (
    <Stack spacing={2.5}>
      <Box className="studio-sectionHeader">
        <Typography variant="h5">Resource context</Typography>
        <Typography color="text.secondary">
          API operations and record-level context for the current editor.
        </Typography>
      </Box>

      {showAssetPreview ? (
        <Box className="preview-blockMedia">
          <img alt={draft.alt_text || 'Asset preview'} src={assetPreviewSource} />
        </Box>
      ) : null}

      {config.previewMode === 'workspace' ? (
        <Paper className="studio-panelTight" sx={{ p: 2 }}>
          <Stack spacing={1}>
            <Typography fontWeight={700}>Workspace identity</Typography>
            <Typography color="text.secondary" variant="body2">
              Local preview: {localPreviewHref ?? 'Workspace slug required'}
            </Typography>
            <Typography color="text.secondary" variant="body2">
              Slug: /{draft.slug || 'workspace'}
            </Typography>
            <Typography color="text.secondary" variant="body2">
              Published base URL: {draft.public_base_url || 'Not configured'}
            </Typography>
            {localPreviewHref ? (
              <Button
                component="a"
                endIcon={<LaunchRounded />}
                href={localPreviewHref}
                rel="noreferrer"
                target="_blank"
                variant="outlined"
              >
                Open local preview
              </Button>
            ) : null}
            {publishedSiteHref ? (
              <Button
                component="a"
                endIcon={<LaunchRounded />}
                href={publishedSiteHref}
                rel="noreferrer"
                target="_blank"
                variant="outlined"
              >
                Open published site
              </Button>
            ) : null}
            {selectedRow && typeof selectedRow.studio_url === 'string' ? (
              <Button
                component="a"
                endIcon={<LaunchRounded />}
                href={selectedRow.studio_url}
                rel="noreferrer"
                target="_blank"
                variant="outlined"
              >
                Open studio URL
              </Button>
            ) : null}
          </Stack>
        </Paper>
      ) : null}

      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={1}>
          <Typography fontWeight={700}>Record summary</Typography>
          <Typography color="text.secondary" variant="body2">
            {selectedRow ? config.itemSubtitle(selectedRow) : `Drafting a new ${config.shortLabel.toLowerCase()}.`}
          </Typography>
          {selectedRow?.id ? (
            <Typography color="text.secondary" variant="body2">
              Record id: #{String(selectedRow.id)}
            </Typography>
          ) : null}
        </Stack>
      </Paper>

      <Stack spacing={1.25}>
        <Typography fontWeight={700}>OpenAPI operations</Typography>
        <Box className="api-list">
          {operations.map((operation) => (
            <Box className="api-item" key={`${operation.method}:${operation.path}`}>
              <Box>
                <Typography fontWeight={700}>{formatMethodLabel(operation.method)}</Typography>
                <Typography className="api-itemPath">{operation.path}</Typography>
              </Box>
              <Typography color="text.secondary" variant="body2">
                {operation.summary}
              </Typography>
            </Box>
          ))}
        </Box>
      </Stack>
    </Stack>
  );
}
