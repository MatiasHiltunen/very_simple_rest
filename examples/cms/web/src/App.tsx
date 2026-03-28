import { useDeferredValue, useEffect, useRef, useState } from 'react';
import {
  Alert,
  Autocomplete,
  AppBar,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  FormControlLabel,
  IconButton,
  InputAdornment,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Paper,
  Snackbar,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Switch,
  TextField,
  Toolbar,
  Typography,
  useMediaQuery,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import { alpha, useTheme } from '@mui/material/styles';
import {
  AddRounded,
  ArrowDownwardRounded,
  ArrowUpwardRounded,
  AutoAwesomeRounded,
  AddCircleOutlineRounded,
  DeleteOutlineRounded,
  EditRounded,
  ExitToAppRounded,
  LaunchRounded,
  MenuRounded,
  SearchRounded,
  VisibilityOffRounded,
  VisibilityRounded,
} from '@mui/icons-material';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, NavLink, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import {
  ApiError,
  clearAuthToken,
  createResource,
  deleteLocalObject,
  deleteResource,
  getAuthenticatedAccount,
  listResource,
  login,
  persistAuthToken,
  readLastEmail,
  readAuthToken,
  runResourceAction,
  setUnauthorizedHandler,
  updateManagedUser,
  uploadLocalObject,
  updateResource,
  type AuthMeResponse,
  type JsonValue,
} from './lib/api';
import {
  cmsNavigation,
  cmsResources,
  defaultDraftValue,
  lookupResource,
  renderFallbackCell,
  type FieldConfig,
  type RelationConfig,
  type ResourceConfig,
} from './lib/cms';

type ResourceRow = Record<string, unknown>;
type DraftState = Record<string, string>;
type Notice = { severity: 'success' | 'error' | 'warning' | 'info'; message: string } | null;
type FieldErrors = Record<string, string>;
type RelationOption = { id: string; label: string; description?: string };
type BlockDraft = {
  type: string;
  title: string;
  content: string;
  tone: string;
  assetId: string;
};

const drawerWidth = 296;
const blockTypes = ['paragraph', 'hero', 'quote', 'callout', 'image'] as const;
const blockTones = ['neutral', 'info', 'success', 'warning'] as const;

function initials(value: string | undefined): string {
  if (!value) {
    return 'CM';
  }
  return value
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? '')
    .join('');
}

function formatDateTimeInput(value: unknown): string {
  if (typeof value !== 'string' || !value) {
    return '';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '';
  }

  const pad = (part: number) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

function stringifyJsonValue(value: unknown): string {
  if (value === null || value === undefined || value === '') {
    return '';
  }
  return JSON.stringify(value, null, 2);
}

function parseObjectArray(value: string): Record<string, unknown>[] | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      return null;
    }
    if (parsed.some((item) => typeof item !== 'object' || item === null || Array.isArray(item))) {
      return null;
    }
    return parsed as Record<string, unknown>[];
  } catch {
    return null;
  }
}

function defaultBlockDraft(): BlockDraft {
  return {
    type: 'paragraph',
    title: '',
    content: '',
    tone: 'neutral',
    assetId: '',
  };
}

function parseBlockDrafts(value: string): BlockDraft[] | null {
  const parsed = parseObjectArray(value);
  if (parsed === null) {
    return null;
  }

  return parsed.map((item) => ({
    type: typeof item.type === 'string' && item.type ? item.type : 'paragraph',
    title: typeof item.title === 'string' ? item.title : '',
    content: typeof item.content === 'string' ? item.content : '',
    tone: typeof item.tone === 'string' && item.tone ? item.tone : 'neutral',
    assetId:
      typeof item.asset_id === 'number'
        ? String(item.asset_id)
        : typeof item.asset_id === 'string'
          ? item.asset_id
          : '',
  }));
}

function serializeBlocks(blocks: BlockDraft[]): string {
  return JSON.stringify(
    blocks.map((block) => {
      const payload: Record<string, JsonValue> = {
        type: block.type,
      };

      if (block.title.trim()) {
        payload.title = block.title.trim();
      }
      if (block.content.trim()) {
        payload.content = block.content.trim();
      }
      if (block.type === 'callout' && block.tone.trim()) {
        payload.tone = block.tone.trim();
      }
      if ((block.type === 'hero' || block.type === 'image') && block.assetId.trim()) {
        const parsed = Number(block.assetId.trim());
        if (!Number.isNaN(parsed)) {
          payload.asset_id = parsed;
        }
      }

      return payload;
    }),
    null,
    2,
  );
}

function parseObjectValue(value: string): Record<string, unknown> | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return {};
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function parseSelectionIds(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

function serializeSelectionIds(ids: string[]): string {
  return parseSelectionIds(ids.join(',')).join(',');
}

function toBooleanFlag(value: unknown): boolean {
  return value === true;
}

function toStringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function guessAssetKindFromMime(mimeType: string): string {
  if (mimeType.startsWith('image/')) {
    return 'image';
  }
  if (mimeType.startsWith('video/')) {
    return 'video';
  }
  if (mimeType.startsWith('audio/')) {
    return 'audio';
  }
  return 'document';
}

async function readLocalImageDimensions(file: File): Promise<{ width?: number; height?: number }> {
  if (!file.type.startsWith('image/')) {
    return {};
  }

  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      const result = { width: image.naturalWidth, height: image.naturalHeight };
      URL.revokeObjectURL(url);
      resolve(result);
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      resolve({});
    };
    image.src = url;
  });
}

function mergeAssetMetadataDraft(
  currentValue: string,
  additions: Record<string, string | number | boolean | null>,
): string {
  const trimmed = currentValue.trim();
  if (!trimmed) {
    return JSON.stringify(additions, null, 2);
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return JSON.stringify({ ...parsed, ...additions }, null, 2);
    }
  } catch {
    return currentValue;
  }

  return currentValue;
}

function deriveWorkspaceSeed(account: AuthMeResponse): {
  name: string;
  slug: string;
  defaultLocale: string;
  publicBaseUrl: string;
} {
  const localPart = (account.email ?? 'editor')
    .split('@')[0]
    .trim()
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim();
  const normalized = localPart || 'editorial team';
  const slug = normalized
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  const title = normalized
    .split(/\s+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
  return {
    name: `${title} Workspace`,
    slug: `${slug || 'editorial'}-studio`,
    defaultLocale: 'en',
    publicBaseUrl: `https://${slug || 'editorial'}.local`,
  };
}

function localStorageObjectForAsset(
  row: ResourceRow,
): { bucket: string; objectKey: string; publicUrl?: string } | null {
  const metadata = row.metadata;
  if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
    const metadataRecord = metadata as Record<string, unknown>;
    const bucket = typeof metadataRecord.storage_bucket === 'string'
      ? metadataRecord.storage_bucket
      : typeof metadataRecord.bucket === 'string'
        ? metadataRecord.bucket
        : null;
    const objectKey =
      typeof metadataRecord.object_key === 'string' ? metadataRecord.object_key : null;
    if (bucket && objectKey) {
      return {
        bucket,
        objectKey,
        publicUrl:
          typeof row.delivery_url === 'string'
            ? row.delivery_url
            : typeof row.source_url === 'string'
              ? row.source_url
              : undefined,
      };
    }
  }

  const sourceUrl =
    typeof row.source_url === 'string'
      ? row.source_url
      : typeof row.delivery_url === 'string'
        ? row.delivery_url
        : null;
  if (!sourceUrl || !sourceUrl.startsWith('/uploads/assets/')) {
    return null;
  }

  return {
    bucket: 'media',
    objectKey: sourceUrl.slice('/uploads/assets/'.length),
    publicUrl: sourceUrl,
  };
}

function assetPreviewUrl(row: ResourceRow): string | null {
  const deliveryUrl = typeof row.delivery_url === 'string' ? row.delivery_url : null;
  if (deliveryUrl) {
    return deliveryUrl;
  }
  return typeof row.source_url === 'string' ? row.source_url : null;
}

function assetPreviewEligible(row: ResourceRow): boolean {
  const kind = typeof row.kind === 'string' ? row.kind : '';
  const mimeType = typeof row.mime_type === 'string' ? row.mime_type : '';
  return kind === 'image' || mimeType.startsWith('image/');
}

function buildRelationOption(row: ResourceRow, relation: RelationConfig): RelationOption {
  const labelValue = row[relation.labelKey];
  const descriptionValue = relation.descriptionKey ? row[relation.descriptionKey] : undefined;
  const label =
    labelValue === null || labelValue === undefined || labelValue === ''
      ? `#${String(row.id ?? '')}`
      : String(labelValue);

  return {
    id: String(row.id ?? ''),
    label,
    description:
      descriptionValue === null || descriptionValue === undefined || descriptionValue === ''
        ? undefined
        : String(descriptionValue),
  };
}

function toDraft(config: ResourceConfig, item?: ResourceRow | null): DraftState {
  return Object.fromEntries(
    config.fields.map((field) => {
      const rawValue = item?.[field.key];
      let value = defaultDraftValue(field);

      if (
        field.kind === 'json' ||
        field.kind === 'jsonArray' ||
        field.kind === 'blocks' ||
        field.kind === 'seo' ||
        field.kind === 'entrySettings'
      ) {
        value = stringifyJsonValue(rawValue);
      } else if (field.kind === 'relationMulti' && Array.isArray(rawValue)) {
        value = serializeSelectionIds(
          rawValue
            .map((entry) => (entry === null || entry === undefined ? '' : String(entry)))
            .filter(Boolean),
        );
      } else if (field.kind === 'datetime') {
        value = formatDateTimeInput(rawValue);
      } else if (rawValue !== null && rawValue !== undefined) {
        value = String(rawValue);
      }

      return [field.key, value];
    }),
  );
}

function serializeFieldValue(field: FieldConfig, rawValue: string): JsonValue {
  const trimmed = rawValue.trim();

  if (!trimmed) {
    if (field.required) {
      throw new Error(`${field.label} is required.`);
    }
    return null;
  }

  switch (field.kind) {
    case 'number': {
      const parsed = Number(trimmed);
      if (Number.isNaN(parsed)) {
        throw new Error(`${field.label} must be a valid number.`);
      }
      return parsed;
    }
    case 'relation': {
      const parsed = Number(trimmed);
      if (Number.isNaN(parsed)) {
        throw new Error(`${field.label} must reference a valid record.`);
      }
      return parsed;
    }
    case 'json': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (Array.isArray(parsed) || typeof parsed !== 'object' || parsed === null) {
        throw new Error(`${field.label} must be a JSON object.`);
      }
      return parsed;
    }
    case 'jsonArray': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (!Array.isArray(parsed)) {
        throw new Error(`${field.label} must be a JSON array.`);
      }
      return parsed;
    }
    case 'seo':
    case 'entrySettings': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (Array.isArray(parsed) || typeof parsed !== 'object' || parsed === null) {
        throw new Error(`${field.label} must be a JSON object.`);
      }
      return parsed;
    }
    case 'relationMulti':
      return parseSelectionIds(trimmed);
    case 'blocks': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (!Array.isArray(parsed)) {
        throw new Error(`${field.label} must be a JSON array of block objects.`);
      }
      if (parsed.some((item) => typeof item !== 'object' || item === null || Array.isArray(item))) {
        throw new Error(`${field.label} must contain block objects.`);
      }
      return parsed;
    }
    case 'datetime': {
      const parsed = new Date(trimmed);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error(`${field.label} must be a valid date and time.`);
      }
      return parsed.toISOString();
    }
    default:
      return trimmed;
  }
}

function serializeDraft(config: ResourceConfig, draft: DraftState): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  for (const field of config.fields) {
    if (field.virtual) {
      continue;
    }
    body[field.key] = serializeFieldValue(field, draft[field.key] ?? '');
  }
  return body;
}

function currentResourceLabel(pathname: string): string {
  return lookupResource(pathname)?.label ?? 'Dashboard';
}

async function syncRelationSelections(
  field: FieldConfig & { relationSync: NonNullable<FieldConfig['relationSync']> },
  ownerId: number,
  rawValue: string,
): Promise<void> {
  const desiredIds = parseSelectionIds(rawValue)
    .map((value) => Number(value))
    .filter((value) => !Number.isNaN(value));

  const current = await listResource<ResourceRow>(field.relationSync.joinPath, {
    limit: 200,
    context: field.relationSync.context ?? 'edit',
  });

  const existingRows = current.items.filter(
    (row) => Number(row[field.relationSync.sourceKey]) === ownerId,
  );
  const existingByTarget = new Map(
    existingRows.map((row) => [Number(row[field.relationSync.targetKey]), Number(row.id)]),
  );

  for (const desiredId of desiredIds) {
    if (existingByTarget.has(desiredId)) {
      continue;
    }

    await createResource(field.relationSync.joinPath, {
      [field.relationSync.sourceKey]: ownerId,
      [field.relationSync.targetKey]: desiredId,
    });
  }

  for (const row of existingRows) {
    const targetId = Number(row[field.relationSync.targetKey]);
    if (desiredIds.includes(targetId)) {
      continue;
    }

    await deleteResource(field.relationSync.joinPath, Number(row.id));
  }
}

function App() {
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(() => readAuthToken());
  const [loginError, setLoginError] = useState<string | null>(null);

  useEffect(() => {
    const handleUnauthorized = () => {
      clearAuthToken();
      setToken(null);
      setLoginError('Your studio session expired. Sign in again.');
      queryClient.clear();
    };

    setUnauthorizedHandler(handleUnauthorized);
    return () => setUnauthorizedHandler(null);
  }, [queryClient]);

  const accountQuery = useQuery({
    queryKey: ['auth', 'me', token],
    queryFn: getAuthenticatedAccount,
    enabled: Boolean(token),
  });

  const handleLogin = async (email: string, password: string) => {
    const auth = await login(email, password);
    persistAuthToken(auth.token);
    setToken(auth.token);
    setLoginError(null);
    await queryClient.invalidateQueries();
  };

  const handleLogout = () => {
    clearAuthToken();
    setToken(null);
    setLoginError(null);
    queryClient.clear();
  };

  const handleReloginRequired = (message: string) => {
    clearAuthToken();
    setToken(null);
    setLoginError(message);
    queryClient.clear();
  };

  if (!token) {
    return <LoginScreen onLogin={handleLogin} initialError={loginError} />;
  }

  if (accountQuery.isLoading) {
    return (
      <Box
        sx={{
          minHeight: '100vh',
          display: 'grid',
          placeItems: 'center',
        }}
      >
        <Stack spacing={2} alignItems="center">
          <CircularProgress />
          <Typography color="text.secondary">Connecting to the studio…</Typography>
        </Stack>
      </Box>
    );
  }

  if (!accountQuery.data) {
    return <LoginScreen onLogin={handleLogin} initialError="Unable to load your account." />;
  }

  return (
    <Routes>
      <Route element={<StudioLayout account={accountQuery.data} onLogout={handleLogout} />}>
        <Route
          index
          element={
            <DashboardScreen
              account={accountQuery.data}
              onReloginRequired={handleReloginRequired}
            />
          }
        />
        {cmsResources.map((resource) => (
          <Route
            key={resource.key}
            path={resource.key}
            element={<ResourceScreen config={resource} />}
          />
        ))}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

function LoginScreen({
  onLogin,
  initialError,
}: {
  onLogin: (email: string, password: string) => Promise<void>;
  initialError: string | null;
}) {
  const [email, setEmail] = useState(() => readLastEmail());
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(initialError);

  useEffect(() => {
    setError(initialError);
  }, [initialError]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await onLogin(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to sign in.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'grid',
        gridTemplateColumns: { xs: '1fr', lg: '1.2fr 0.8fr' },
      }}
    >
      <Box
        sx={{
          display: { xs: 'none', lg: 'flex' },
          flexDirection: 'column',
          justifyContent: 'space-between',
          p: 6,
          background:
            'linear-gradient(160deg, rgba(0, 107, 98, 0.96), rgba(0, 77, 71, 0.9) 58%, rgba(169, 95, 0, 0.88))',
          color: '#fff',
        }}
      >
        <Stack spacing={3} maxWidth={540}>
          <Chip
            label="Modern CMS Studio"
            sx={{
              alignSelf: 'flex-start',
              bgcolor: alpha('#ffffff', 0.16),
              color: '#fff',
              fontWeight: 700,
            }}
          />
          <Typography variant="h3">Editorial control without a template graveyard.</Typography>
          <Typography variant="h6" sx={{ opacity: 0.88 }}>
            Review entries, organize assets, curate navigation, and manage structured content from
            one focused studio.
          </Typography>
        </Stack>
        <Grid container spacing={2}>
          {[
            ['Entries', 'Structured blocks, SEO, and publish workflow.'],
            ['Media', 'Asset metadata, delivery URLs, and accessibility notes.'],
            ['Workspace', 'Theme, locale, and editorial configuration in one place.'],
          ].map(([title, description]) => (
            <Grid key={title} size={{ xs: 12, md: 4 }}>
              <Card sx={{ bgcolor: alpha('#ffffff', 0.12), color: '#fff', borderColor: 'transparent' }}>
                <CardContent>
                  <Typography variant="overline">{title}</Typography>
                  <Typography sx={{ mt: 1, opacity: 0.88 }}>{description}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>

      <Box
        sx={{
          display: 'grid',
          placeItems: 'center',
          p: 3,
        }}
      >
        <Card sx={{ width: '100%', maxWidth: 460 }}>
          <CardContent sx={{ p: 4 }}>
            <Stack component="form" spacing={3} onSubmit={handleSubmit}>
              <Stack spacing={1}>
                <Typography variant="h4">Sign in to the studio</Typography>
                <Typography color="text.secondary">
                  Use a built-in auth account from the CMS backend.
                </Typography>
              </Stack>

              {error ? <Alert severity="error">{error}</Alert> : null}

              <TextField
                autoComplete="email"
                helperText="The studio keeps the last email on this device for faster local sign-in."
                label="Email address"
                onChange={(event) => setEmail(event.target.value)}
                required
                type="email"
                value={email}
              />
              <TextField
                autoComplete="current-password"
                helperText="Bearer auth is used for the local studio session."
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        edge="end"
                        onClick={() => setShowPassword((current) => !current)}
                      >
                        {showPassword ? <VisibilityOffRounded /> : <VisibilityRounded />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                label="Password"
                onChange={(event) => setPassword(event.target.value)}
                required
                type={showPassword ? 'text' : 'password'}
                value={password}
              />

              <Button disabled={submitting} size="large" type="submit" variant="contained">
                {submitting ? 'Signing in…' : 'Open studio'}
              </Button>
              <Typography color="text.secondary" variant="body2">
                In local dev, run the backend and then open the studio on <strong>/studio</strong>.
              </Typography>
            </Stack>
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
}

function StudioLayout({
  account,
  onLogout,
}: {
  account: AuthMeResponse;
  onLogout: () => void;
}) {
  const theme = useTheme();
  const location = useLocation();
  const lgUp = useMediaQuery(theme.breakpoints.up('lg'));
  const [mobileOpen, setMobileOpen] = useState(false);

  const drawerContent = (
    <Stack sx={{ height: '100%' }}>
      <Toolbar sx={{ px: 2.5 }}>
        <Stack spacing={0.5}>
          <Typography variant="overline" color="text.secondary">
            CMS Studio
          </Typography>
          <Typography variant="h6">modern_cms_api</Typography>
        </Stack>
      </Toolbar>
      <Divider />
      <Box sx={{ flex: 1, overflowY: 'auto', p: 1.5 }}>
        {cmsNavigation.map((section) => (
          <Box key={section.label} sx={{ mb: 2 }}>
            <Typography
              color="text.secondary"
              sx={{ px: 1.5, pb: 0.75 }}
              variant="caption"
            >
              {section.label}
            </Typography>
            <List disablePadding>
              {section.items.map((item) => {
                const selected =
                  item.to === '/'
                    ? location.pathname === '/'
                    : location.pathname === item.to || location.pathname.startsWith(`${item.to}/`);
                const Icon = item.icon;

                return (
                  <ListItemButton
                    key={item.to}
                    component={NavLink}
                    onClick={() => setMobileOpen(false)}
                    selected={selected}
                    sx={{
                      borderRadius: 3,
                      mb: 0.5,
                    }}
                    to={item.to}
                  >
                    <ListItemIcon sx={{ minWidth: 40 }}>
                      <Icon color={selected ? 'primary' : 'inherit'} />
                    </ListItemIcon>
                    <ListItemText primary={item.label} />
                  </ListItemButton>
                );
              })}
            </List>
          </Box>
        ))}
      </Box>
    </Stack>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AppBar position="fixed">
        <Toolbar sx={{ gap: 1.5 }}>
          {!lgUp ? (
            <IconButton edge="start" onClick={() => setMobileOpen(true)}>
              <MenuRounded />
            </IconButton>
          ) : null}
          <Stack sx={{ flex: 1, minWidth: 0 }} spacing={0.25}>
            <Typography noWrap variant="overline" color="text.secondary">
              {currentResourceLabel(location.pathname)}
            </Typography>
            <Typography noWrap variant="h6">
              Material studio for the modern CMS backend
            </Typography>
          </Stack>
          {typeof account.workspace_id === 'number' ? (
            <Chip color="primary" label={`Workspace #${account.workspace_id}`} variant="outlined" />
          ) : (
            <Chip color="warning" label="No workspace claim" variant="outlined" />
          )}
          <Button
            color="inherit"
            component="a"
            endIcon={<LaunchRounded />}
            href="/docs"
            rel="noreferrer"
            target="_blank"
          >
            API docs
          </Button>
          <Avatar sx={{ bgcolor: 'primary.main' }}>{initials(account.email)}</Avatar>
          <Stack sx={{ display: { xs: 'none', md: 'flex' } }} spacing={0}>
            <Typography fontWeight={600} variant="body2">
              {account.email ?? `User #${account.id}`}
            </Typography>
            <Typography color="text.secondary" variant="caption">
              {account.roles.join(', ')}
            </Typography>
          </Stack>
          <IconButton onClick={onLogout}>
            <ExitToAppRounded />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Box component="nav" sx={{ width: { lg: drawerWidth }, flexShrink: { lg: 0 } }}>
        <Drawer
          ModalProps={{ keepMounted: true }}
          onClose={() => setMobileOpen(false)}
          open={mobileOpen}
          sx={{ display: { xs: 'block', lg: 'none' } }}
          variant="temporary"
        >
          {drawerContent}
        </Drawer>
        <Drawer
          open
          sx={{
            display: { xs: 'none', lg: 'block' },
            '& .MuiDrawer-paper': { width: drawerWidth },
          }}
          variant="permanent"
        >
          {drawerContent}
        </Drawer>
      </Box>

      <Box component="main" sx={{ flex: 1, minWidth: 0 }}>
        <Toolbar />
        <Box sx={{ p: { xs: 2, md: 3 } }}>
          {typeof account.workspace_id !== 'number' ? (
            <Alert sx={{ mb: 3 }} severity="warning" variant="outlined">
              This account does not currently expose a <code>workspace_id</code> claim. The studio
              will authenticate correctly, but workspace-scoped content APIs will stay empty until
              the user is assigned that claim in built-in auth.
            </Alert>
          ) : null}
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}

function DashboardScreen({
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
        queryKey: ['dashboard', 'entries'],
        queryFn: () => listResource<ResourceRow>('entries', { limit: 8, context: 'card' }),
      },
      {
        queryKey: ['dashboard', 'assets'],
        queryFn: () => listResource<ResourceRow>('assets', { limit: 12, context: 'card' }),
      },
      {
        queryKey: ['dashboard', 'topics'],
        queryFn: () => listResource<ResourceRow>('topics', { limit: 20, context: 'view' }),
      },
      {
        queryKey: ['dashboard', 'menus'],
        queryFn: () => listResource<ResourceRow>('menus', { limit: 20, context: 'view' }),
      },
      {
        queryKey: ['dashboard', 'workspaces'],
        queryFn: () => listResource<ResourceRow>('workspaces', { limit: 5, context: 'admin' }),
      },
    ],
  });

  const recentEntries = entriesQuery.data?.items ?? [];
  const publishedCount = recentEntries.filter((entry) => entry.status === 'published').length;
  const reviewCount = recentEntries.filter((entry) => entry.status === 'in_review').length;
  const workspaceRows = workspacesQuery.data?.items ?? [];
  const claimedWorkspace =
    typeof account.workspace_id === 'number'
      ? workspaceRows.find((item) => Number(item.id) === account.workspace_id)
      : undefined;
  const workspace = claimedWorkspace ?? workspaceRows[0];
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
            palette: 'editorial',
            accent: 'teal',
          },
          editorial_settings: {
            review_required: true,
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
          ? `Workspace “${workspaceName}” was created and your account was assigned to it. Sign in again to refresh the studio claims.`
          : `Your account was assigned to workspace #${workspaceId}. Sign in again to refresh the studio claims.`,
      );
    },
  });

  return (
    <Stack spacing={3}>
      <Paper
        sx={{
          p: { xs: 3, md: 4 },
          borderRadius: 6,
          background:
            'linear-gradient(135deg, rgba(0, 107, 98, 0.98), rgba(0, 77, 71, 0.92) 58%, rgba(169, 95, 0, 0.85))',
          color: '#fff',
        }}
      >
        <Grid alignItems="center" container spacing={3}>
          <Grid size={{ xs: 12, lg: 7 }}>
            <Stack spacing={2}>
              <Chip
                icon={<AutoAwesomeRounded />}
                label="Studio overview"
                sx={{ alignSelf: 'flex-start', bgcolor: alpha('#ffffff', 0.16), color: '#fff' }}
              />
              <Typography variant="h3">Content operations, workspace-aware.</Typography>
              <Typography sx={{ maxWidth: 720, opacity: 0.88 }}>
                This studio is tuned for a modern publishing workflow: structured entries, curated
                topics, reusable assets, and menu composition without legacy CMS baggage.
              </Typography>
            </Stack>
          </Grid>
          <Grid size={{ xs: 12, lg: 5 }}>
            <Stack spacing={1.5}>
              <MetricCard
                caption="Account"
                title={account.email ?? `User #${account.id}`}
                value={account.roles.join(', ')}
              />
              <MetricCard
                caption="Workspace claim"
                title={typeof account.workspace_id === 'number' ? `#${account.workspace_id}` : 'Missing'}
                value={typeof account.is_staff === 'boolean' ? `Staff: ${account.is_staff}` : 'No staff flag'}
              />
            </Stack>
          </Grid>
        </Grid>
      </Paper>

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 6, xl: 3 }}>
          <MetricCard
            caption="Entries loaded"
            title={String(entriesQuery.data?.total ?? entriesQuery.data?.items.length ?? 0)}
            value={`${publishedCount} published / ${reviewCount} in review`}
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 3 }}>
          <MetricCard
            caption="Assets loaded"
            title={String(assetsQuery.data?.total ?? assetsQuery.data?.items.length ?? 0)}
            value="Metadata-first media library"
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 3 }}>
          <MetricCard
            caption="Topics loaded"
            title={String(topicsQuery.data?.total ?? topicsQuery.data?.items.length ?? 0)}
            value="Taxonomy for audience and campaigns"
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6, xl: 3 }}>
          <MetricCard
            caption="Menus loaded"
            title={String(menusQuery.data?.total ?? menusQuery.data?.items.length ?? 0)}
            value="Navigation containers and ordering"
          />
        </Grid>
      </Grid>

      {needsWorkspaceBootstrap ? (
        <Card sx={{ border: '1px solid', borderColor: 'warning.light' }}>
          <CardContent>
            <Stack
              direction={{ xs: 'column', lg: 'row' }}
              justifyContent="space-between"
              spacing={2}
            >
              <Stack spacing={1}>
                <Typography variant="h5">Workspace bootstrap</Typography>
                <Typography color="text.secondary">
                  This account can sign in, but the workspace-scoped APIs will stay empty until the
                  user has a valid <code>workspace_id</code> claim and a matching workspace row.
                </Typography>
                <Typography color="text.secondary" variant="body2">
                  {workspaceRows.length > 0
                    ? `A workspace already exists in the backend. The bootstrap flow will assign your account to “${String(
                        workspaceRows[0]?.name ?? workspaceRows[0]?.slug ?? 'workspace',
                      )}”.`
                    : `No workspace exists yet. The bootstrap flow will create “${workspaceSeed.name}” with slug “${workspaceSeed.slug}”.`}
                </Typography>
              </Stack>
              <Stack spacing={1.25} sx={{ minWidth: { lg: 320 } }}>
                <Alert severity="warning" variant="outlined">
                  The studio must issue a fresh login after claim changes so the bearer token picks
                  up the new workspace scope.
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
          </CardContent>
        </Card>
      ) : null}

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, lg: 7 }}>
          <Card>
            <CardContent>
              <Stack direction="row" justifyContent="space-between" spacing={2}>
                <Stack spacing={0.75}>
                  <Typography variant="h5">Recent entries</Typography>
                  <Typography color="text.secondary">
                    The latest editorial items from the current workspace.
                  </Typography>
                </Stack>
                <Button component={NavLink} to="/entries" variant="outlined">
                  Open entries
                </Button>
              </Stack>
              <Stack divider={<Divider flexItem sx={{ my: 1.5 }} />} sx={{ mt: 3 }}>
                {recentEntries.length > 0 ? (
                  recentEntries.map((entry) => (
                    <Stack
                      key={String(entry.id)}
                      direction={{ xs: 'column', md: 'row' }}
                      justifyContent="space-between"
                      spacing={1.5}
                    >
                      <Stack spacing={0.5}>
                        <Typography fontWeight={700}>{String(entry.title ?? 'Untitled')}</Typography>
                        <Typography color="text.secondary" variant="body2">
                          {String(entry.summary ?? 'No summary yet.')}
                        </Typography>
                      </Stack>
                      <Stack direction="row" spacing={1}>
                        <Chip label={String(entry.type ?? 'entry')} size="small" variant="outlined" />
                        <Chip label={String(entry.status ?? 'draft')} size="small" color="primary" variant="outlined" />
                      </Stack>
                    </Stack>
                  ))
                ) : (
                  <Alert severity="info" variant="outlined">
                    No entry data is available yet. Create the first entry from the Entries screen.
                  </Alert>
                )}
              </Stack>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, lg: 5 }}>
          <Stack spacing={3}>
            <Card>
              <CardContent>
                <Typography variant="h5">Workspace focus</Typography>
                {workspace ? (
                  <Stack spacing={1.5} sx={{ mt: 2 }}>
                    <Typography variant="h6">{String(workspace.name)}</Typography>
                    <Typography color="text.secondary">/{String(workspace.slug)}</Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      <Chip label={`Locale: ${String(workspace.default_locale ?? 'n/a')}`} variant="outlined" />
                      {workspace.public_base_url ? (
                        <Chip
                          component="a"
                          clickable
                          href={String(workspace.public_base_url)}
                          label="Public site"
                          rel="noreferrer"
                          target="_blank"
                          variant="outlined"
                        />
                      ) : null}
                    </Stack>
                  </Stack>
                ) : (
                  <Alert severity="info" sx={{ mt: 2 }} variant="outlined">
                    Workspace details will appear here once a workspace has been created or the
                    current account is assigned to one.
                  </Alert>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardContent>
                <Typography variant="h5">Suggested next steps</Typography>
                <Stack spacing={1.5} sx={{ mt: 2 }}>
                  <Typography color="text.secondary">
                    1. Make sure the current account has a live workspace claim and a matching
                    workspace row.
                  </Typography>
                  <Typography color="text.secondary">
                    2. Add topics and assets before publishing entries with workflow actions.
                  </Typography>
                  <Typography color="text.secondary">
                    3. Build menus after your first entry set is live.
                  </Typography>
                </Stack>
              </CardContent>
            </Card>
          </Stack>
        </Grid>
      </Grid>
    </Stack>
  );
}

function MetricCard({
  caption,
  title,
  value,
}: {
  caption: string;
  title: string;
  value: string;
}) {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Typography color="text.secondary" variant="overline">
          {caption}
        </Typography>
        <Typography sx={{ mt: 0.75 }} variant="h4">
          {title}
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1.25 }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

function ResourceScreen({ config }: { config: ResourceConfig }) {
  const queryClient = useQueryClient();
  const assetFileInputRef = useRef<HTMLInputElement | null>(null);
  const [search, setSearch] = useState('');
  const [notice, setNotice] = useState<Notice>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<ResourceRow | null>(null);
  const [draft, setDraft] = useState<DraftState>(() => toDraft(config));
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [assetImportSummary, setAssetImportSummary] = useState<string | null>(null);
  const [assetImportPending, setAssetImportPending] = useState(false);
  const deferredSearch = useDeferredValue(search);
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
      queryKey: ['relation-options', field.key, field.relation.path, field.relation.context],
      queryFn: () =>
        listResource<ResourceRow>(field.relation.path, {
          limit: field.relation.limit ?? 100,
          context: field.relation.context,
        }),
      enabled: editorOpen,
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
      queryKey: ['relation-sync', config.path, field.key, editingItem?.id],
      queryFn: () =>
        listResource<ResourceRow>(field.relationSync.joinPath, {
          limit: 200,
          context: field.relationSync.context ?? 'edit',
        }),
      enabled: editorOpen && typeof editingItem?.id === 'number',
      staleTime: 30_000,
    })),
  });

  const blockAssetQuery = useQuery({
    queryKey: ['block-asset-options'],
    queryFn: () =>
      listResource<ResourceRow>('assets', {
        limit: 100,
        context: 'edit',
      }),
    enabled: editorOpen && config.path === 'entries',
    staleTime: 60_000,
  });

  const blockAssetOptions = (blockAssetQuery.data?.items ?? []).map((item) =>
    buildRelationOption(item, {
      path: 'assets',
      labelKey: 'file_name',
      descriptionKey: 'kind',
      context: 'edit',
    }),
  );

  useEffect(() => {
    if (!editorOpen || typeof editingItem?.id !== 'number') {
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

        const selected = serializeSelectionIds(
          items
            .filter((item) => Number(item[field.relationSync.sourceKey]) === editingItem.id)
            .map((item) => String(item[field.relationSync.targetKey] ?? '')),
        );

        if ((current[field.key] ?? '') !== selected) {
          next[field.key] = selected;
          changed = true;
        }
      });

      return changed ? next : current;
    });
  }, [editingItem?.id, editorOpen, relationSyncQueries, syncedRelationFields]);

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
    onSuccess: async () => {
      await queryClient.invalidateQueries();
      setEditorOpen(false);
      setEditingItem(null);
      setFieldErrors({});
      setNotice({
        severity: 'success',
        message: `${config.shortLabel} ${editingItem ? 'updated' : 'created'} successfully.`,
      });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.field) {
        setFieldErrors({ [error.field]: error.message });
      }
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : `Unable to save ${config.shortLabel.toLowerCase()}.`,
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
                : 'The asset row was removed, but the storage object cleanup failed.';
          }
        }
      }

      return { cleanupWarning };
    },
    onSuccess: async ({ cleanupWarning }) => {
      await queryClient.invalidateQueries();
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
        message: error instanceof Error ? error.message : `Unable to delete ${config.shortLabel.toLowerCase()}.`,
      });
    },
  });

  const actionMutation = useMutation({
    mutationFn: ({ id, action }: { id: number; action: string }) =>
      runResourceAction(config.path, id, action),
    onSuccess: async (_, variables) => {
      await queryClient.invalidateQueries();
      setNotice({
        severity: 'success',
        message: `${config.shortLabel} action “${variables.action}” completed.`,
      });
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to run action.',
      });
    },
  });

  const rows = resourceQuery.data?.items ?? [];
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
  const assetPreviewSource =
    draft.source_url || assetPreviewUrl(editingItem ?? {}) || '';
  const assetPreviewName = draft.file_name || String(editingItem?.file_name ?? 'Unnamed asset');
  const assetPreviewMime = draft.mime_type || String(editingItem?.mime_type ?? 'unknown');
  const showAssetPreview =
    config.path === 'assets' &&
    Boolean(assetPreviewSource) &&
    (draft.kind === 'image' || assetPreviewEligible(editingItem ?? {}));

  const openCreate = () => {
    setEditingItem(null);
    setDraft(toDraft(config));
    setFieldErrors({});
    setAssetImportPending(false);
    setAssetImportSummary(null);
    setEditorOpen(true);
  };

  const openEdit = (item: ResourceRow) => {
    setEditingItem(item);
    setDraft(toDraft(config, item));
    setFieldErrors({});
    setAssetImportPending(false);
    setAssetImportSummary(null);
    setEditorOpen(true);
  };

  const importAssetFile = async (file: File) => {
    setAssetImportPending(true);
    try {
      const [dimensions, upload] = await Promise.all([
        readLocalImageDimensions(file),
        uploadLocalObject(file),
      ]);
      const publicUrl = upload.public_url;

      setDraft((current) => ({
        ...current,
        kind: guessAssetKindFromMime(file.type || current.kind || 'application/octet-stream'),
        file_name: upload.file_name || file.name || current.file_name,
        mime_type: upload.content_type || file.type || current.mime_type || 'application/octet-stream',
        byte_size: String(upload.size_bytes || file.size),
        width: dimensions.width ? String(dimensions.width) : '',
        height: dimensions.height ? String(dimensions.height) : '',
        source_url: publicUrl,
        metadata: mergeAssetMetadataDraft(current.metadata ?? '', {
          storage_bucket: upload.bucket,
          object_key: upload.object_key,
          uploaded_via: 'studio-s3',
        }),
      }));

      setAssetImportSummary(
        dimensions.width && dimensions.height
          ? `${upload.file_name} uploaded to ${publicUrl} (${upload.content_type || 'unknown type'}, ${upload.size_bytes} bytes, ${dimensions.width}x${dimensions.height}).`
          : `${upload.file_name} uploaded to ${publicUrl} (${upload.content_type || 'unknown type'}, ${upload.size_bytes} bytes).`,
      );
    } finally {
      setAssetImportPending(false);
    }
  };

  const submitEditor = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFieldErrors({});
    try {
      const body = serializeDraft(config, draft);
      await saveMutation.mutateAsync({
        id: typeof editingItem?.id === 'number' ? editingItem.id : undefined,
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

  return (
    <Stack spacing={3}>
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        justifyContent="space-between"
        spacing={2}
        sx={{ alignItems: { md: 'center' } }}
      >
        <Stack spacing={0.75}>
          <Typography variant="h4">{config.label}</Typography>
          <Typography color="text.secondary">{config.description}</Typography>
        </Stack>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
          <TextField
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchRounded fontSize="small" />
                </InputAdornment>
              ),
            }}
            label={`Search ${config.label.toLowerCase()}`}
            onChange={(event) => setSearch(event.target.value)}
            value={search}
          />
          <Button onClick={openCreate} startIcon={<AddRounded />} variant="contained">
            New {config.shortLabel}
          </Button>
        </Stack>
      </Stack>

      {resourceQuery.isLoading ? (
        <Paper sx={{ display: 'grid', placeItems: 'center', minHeight: 240 }}>
          <Stack spacing={2} alignItems="center">
            <CircularProgress />
            <Typography color="text.secondary">Loading {config.label.toLowerCase()}…</Typography>
          </Stack>
        </Paper>
      ) : resourceQuery.error ? (
        <Alert severity="error" variant="outlined">
          {resourceQuery.error instanceof Error
            ? resourceQuery.error.message
            : `Unable to load ${config.label.toLowerCase()}.`}
        </Alert>
      ) : (
        <Card>
          <CardContent sx={{ p: 0 }}>
            {filteredRows.length > 0 ? (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      {config.columns.map((column) => (
                        <TableCell key={column.key}>{column.label}</TableCell>
                      ))}
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredRows.map((row) => (
                      <TableRow hover key={String(row.id)}>
                        {config.columns.map((column) => (
                          <TableCell key={column.key} sx={{ verticalAlign: 'top' }}>
                            {column.render
                              ? column.render(row[column.key], row)
                              : renderFallbackCell(row[column.key])}
                          </TableCell>
                        ))}
                        <TableCell align="right" sx={{ whiteSpace: 'nowrap', verticalAlign: 'top' }}>
                          <Stack direction="row" justifyContent="flex-end" spacing={0.5}>
                            {config.actions?.map((action) => (
                              <Button
                                key={action.key}
                                color={action.tone ?? 'primary'}
                                onClick={() =>
                                  actionMutation.mutate({
                                    id: Number(row.id),
                                    action: action.key,
                                  })
                                }
                                size="small"
                                variant="outlined"
                              >
                                {action.label}
                              </Button>
                            ))}
                            <IconButton onClick={() => openEdit(row)} size="small">
                              <EditRounded fontSize="small" />
                            </IconButton>
                            <IconButton
                              color="error"
                              onClick={() => {
                                if (window.confirm(`Delete this ${config.shortLabel.toLowerCase()}?`)) {
                                  deleteMutation.mutate(row);
                                }
                              }}
                              size="small"
                            >
                              <DeleteOutlineRounded fontSize="small" />
                            </IconButton>
                          </Stack>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Box sx={{ p: 4 }}>
                <Alert severity="info" variant="outlined">
                  No {config.label.toLowerCase()} matched the current view. Create one or adjust the
                  search term.
                </Alert>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      <Dialog
        fullWidth
        maxWidth="md"
        onClose={() => setEditorOpen(false)}
        open={editorOpen}
        scroll="paper"
      >
        <Box component="form" onSubmit={submitEditor}>
          <DialogTitle>{editingItem ? `Edit ${config.shortLabel}` : `New ${config.shortLabel}`}</DialogTitle>
          <DialogContent dividers>
            {config.path === 'assets' ? (
              <Stack spacing={1.5} sx={{ mb: 2.5 }}>
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
                <Stack
                  direction={{ xs: 'column', md: 'row' }}
                  justifyContent="space-between"
                  spacing={1.5}
                >
                  <Stack spacing={0.25}>
                    <Typography variant="subtitle1">Asset intake</Typography>
                    <Typography color="text.secondary" variant="body2">
                      Upload a local file through the built-in S3-compatible development endpoint,
                      then prefill the asset record from the stored object metadata.
                    </Typography>
                  </Stack>
                  <Button
                    disabled={assetImportPending}
                    onClick={() => assetFileInputRef.current?.click()}
                    startIcon={<AddCircleOutlineRounded />}
                    variant="outlined"
                  >
                    {assetImportPending ? 'Uploading…' : 'Upload local file'}
                  </Button>
                </Stack>
                {assetImportPending ? (
                  <Alert severity="info" variant="outlined">
                    Uploading the selected file into local development storage…
                  </Alert>
                ) : null}
                {assetImportSummary ? (
                  <Alert severity="success" variant="outlined">
                    {assetImportSummary}
                  </Alert>
                ) : null}
                {showAssetPreview ? (
                  <Paper
                    sx={{
                      p: 1.5,
                      borderRadius: 3,
                      border: '1px solid',
                      borderColor: 'divider',
                    }}
                    variant="outlined"
                  >
                    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                      <Box
                        alt={draft.alt_text || 'Asset preview'}
                        component="img"
                        src={assetPreviewSource}
                        sx={{
                          width: { xs: '100%', md: 220 },
                          height: { xs: 180, md: 140 },
                          objectFit: 'cover',
                          borderRadius: 2,
                          bgcolor: 'action.hover',
                        }}
                      />
                      <Stack spacing={0.5} sx={{ minWidth: 0 }}>
                        <Typography variant="subtitle1">Preview</Typography>
                        <Typography color="text.secondary" variant="body2">
                          Local uploads are stored through the built-in S3-compatible endpoint and
                          served back through the public storage mount.
                        </Typography>
                        <Typography variant="body2">{assetPreviewName}</Typography>
                        <Typography color="text.secondary" variant="body2">
                          {assetPreviewMime}
                        </Typography>
                        <Button
                          component="a"
                          href={assetPreviewSource}
                          rel="noreferrer"
                          size="small"
                          startIcon={<LaunchRounded />}
                          target="_blank"
                          variant="text"
                        >
                          Open original
                        </Button>
                      </Stack>
                    </Stack>
                  </Paper>
                ) : null}
              </Stack>
            ) : null}
            <Grid container spacing={2}>
              {config.fields.map((field) => (
                <Grid
                  key={field.key}
                  size={{
                    xs: 12,
                    md: field.kind === 'textarea' || field.kind === 'json' || field.kind === 'jsonArray' ? 12 : 6,
                  }}
                >
                  <FieldInput
                    currentItemId={typeof editingItem?.id === 'number' ? editingItem.id : undefined}
                    error={fieldErrors[field.key]}
                    field={field}
                    onChange={(value) =>
                      setDraft((current) => {
                        const next = {
                          ...current,
                          [field.key]: value,
                        };
                        return next;
                      })
                    }
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
                    blockAssetOptions={blockAssetOptions}
                    value={draft[field.key] ?? ''}
                  />
                </Grid>
              ))}
            </Grid>
          </DialogContent>
          <DialogActions sx={{ px: 3, py: 2 }}>
            <Button onClick={() => setEditorOpen(false)}>Cancel</Button>
            <Button disabled={saveMutation.isPending} type="submit" variant="contained">
              {saveMutation.isPending ? 'Saving…' : editingItem ? 'Save changes' : 'Create'}
            </Button>
          </DialogActions>
        </Box>
      </Dialog>

      <Snackbar
        autoHideDuration={4200}
        onClose={() => setNotice(null)}
        open={Boolean(notice)}
      >
        <Alert onClose={() => setNotice(null)} severity={notice?.severity ?? 'success'} variant="filled">
          {notice?.message}
        </Alert>
      </Snackbar>
    </Stack>
  );
}

function FieldInput({
  currentItemId,
  error,
  field,
  onClearError,
  relationError,
  relationLoading,
  relationOptions,
  blockAssetOptions,
  value,
  onChange,
}: {
  currentItemId?: number;
  error?: string;
  field: FieldConfig;
  onClearError: () => void;
  relationError?: string;
  relationLoading?: boolean;
  relationOptions: RelationOption[];
  blockAssetOptions: RelationOption[];
  value: string;
  onChange: (value: string) => void;
}) {
  const handleChange = (nextValue: string) => {
    onClearError();
    onChange(nextValue);
  };

  if (field.kind === 'select') {
    return (
      <TextField
        error={Boolean(error)}
        helperText={error ?? field.helperText}
        label={field.label}
        onChange={(event) => handleChange(event.target.value)}
        required={field.required}
        select
        SelectProps={{ native: true }}
        value={value}
      >
        {!field.required ? <option value="">Unset</option> : null}
        {(field.options ?? []).map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </TextField>
    );
  }

  if (field.kind === 'relation') {
    const availableOptions =
      field.key === 'parent_item' && currentItemId
        ? relationOptions.filter((option) => Number(option.id) !== currentItemId)
        : relationOptions;
    const selectedOption =
      availableOptions.find((option) => option.id === value) ??
      (value
        ? {
            id: value,
            label: `#${value}`,
            description: 'Current value',
          }
        : null);

    return (
      <Autocomplete
        autoHighlight
        clearOnEscape
        disableClearable={field.required}
        fullWidth
        getOptionLabel={(option) => option.label}
        isOptionEqualToValue={(option, selected) => option.id === selected.id}
        loading={relationLoading}
        onChange={(_, option) => handleChange(option?.id ?? '')}
        options={availableOptions}
        renderInput={(params) => (
          <TextField
            {...params}
            error={Boolean(error)}
            helperText={error ?? relationError ?? field.helperText}
            label={field.label}
            required={field.required}
          />
        )}
        renderOption={(props, option) => (
          <Box component="li" {...props}>
            <Stack spacing={0.25}>
              <Typography fontWeight={600}>{option.label}</Typography>
              <Typography color="text.secondary" variant="body2">
                {option.description ? `${option.description} · #${option.id}` : `#${option.id}`}
              </Typography>
            </Stack>
          </Box>
        )}
        value={selectedOption}
      />
    );
  }

  if (field.kind === 'relationMulti') {
    const selectedIds = parseSelectionIds(value);
    const selectedOptions = selectedIds.map((id) => {
      return (
        relationOptions.find((option) => option.id === id) ?? {
          id,
          label: `#${id}`,
          description: 'Current value',
        }
      );
    });

    return (
      <Autocomplete
        autoHighlight
        clearOnEscape
        fullWidth
        getOptionLabel={(option) => option.label}
        isOptionEqualToValue={(option, selected) => option.id === selected.id}
        loading={relationLoading}
        multiple
        onChange={(_, options) => handleChange(serializeSelectionIds(options.map((option) => option.id)))}
        options={relationOptions}
        renderInput={(params) => (
          <TextField
            {...params}
            error={Boolean(error)}
            helperText={error ?? relationError ?? field.helperText}
            label={field.label}
          />
        )}
        renderOption={(props, option) => (
          <Box component="li" {...props}>
            <Stack spacing={0.25}>
              <Typography fontWeight={600}>{option.label}</Typography>
              <Typography color="text.secondary" variant="body2">
                {option.description ? `${option.description} · #${option.id}` : `#${option.id}`}
              </Typography>
            </Stack>
          </Box>
        )}
        value={selectedOptions}
      />
    );
  }

  if (field.kind === 'blocks') {
    return (
      <BlockEditorField
        assetOptions={blockAssetOptions}
        error={error}
        field={field}
        onChange={handleChange}
        value={value}
      />
    );
  }

  if (field.kind === 'seo') {
    return <SeoEditorField error={error} field={field} onChange={handleChange} value={value} />;
  }

  if (field.kind === 'entrySettings') {
    return (
      <EntrySettingsEditorField error={error} field={field} onChange={handleChange} value={value} />
    );
  }

  if (field.kind === 'textarea' || field.kind === 'json' || field.kind === 'jsonArray') {
    return (
      <TextField
        error={Boolean(error)}
        helperText={error ?? field.helperText}
        label={field.label}
        multiline
        minRows={field.minRows ?? 4}
        onChange={(event) => handleChange(event.target.value)}
        required={field.required}
        sx={
          field.kind === 'json' || field.kind === 'jsonArray'
            ? { '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }
            : undefined
        }
        value={value}
      />
    );
  }

  return (
    <TextField
      error={Boolean(error)}
      helperText={error ?? field.helperText}
      label={field.label}
      onChange={(event) => handleChange(event.target.value)}
      required={field.required}
      type={field.kind === 'number' ? 'number' : field.kind === 'datetime' ? 'datetime-local' : 'text'}
      value={value}
    />
  );
}

function SeoEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const seo = parseObjectValue(value);

  if (seo === null) {
    return (
      <TextField
        error
        helperText={error ?? 'SEO data is not a valid JSON object. Edit the raw JSON directly to recover it.'}
        label={field.label}
        minRows={field.minRows ?? 6}
        multiline
        onChange={(event) => onChange(event.target.value)}
        sx={{ '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }}
        value={value}
      />
    );
  }

  const updateSeo = (patch: Record<string, unknown>) => {
    const next = { ...seo, ...patch };
    const compact = Object.fromEntries(
      Object.entries(next).filter(([, entryValue]) => {
        if (typeof entryValue === 'string') {
          return entryValue.trim().length > 0;
        }
        return entryValue !== null && entryValue !== undefined;
      }),
    );
    onChange(Object.keys(compact).length > 0 ? JSON.stringify(compact, null, 2) : '');
  };

  return (
    <Stack spacing={1.5}>
      <Stack spacing={0.25}>
        <Typography variant="subtitle1">{field.label}</Typography>
        <Typography color="text.secondary" variant="body2">
          {error ?? field.helperText}
        </Typography>
      </Stack>
      <TextField
        error={Boolean(error)}
        helperText="Recommended: under 60 characters."
        label="Meta title"
        onChange={(event) => updateSeo({ meta_title: event.target.value })}
        value={toStringValue(seo.meta_title)}
      />
      <TextField
        helperText="Recommended: under 160 characters."
        label="Meta description"
        minRows={3}
        multiline
        onChange={(event) => updateSeo({ meta_description: event.target.value })}
        value={toStringValue(seo.meta_description)}
      />
      <TextField
        label="Canonical URL"
        onChange={(event) => updateSeo({ canonical_url: event.target.value })}
        value={toStringValue(seo.canonical_url)}
      />
      <TextField
        label="Indexing mode"
        onChange={(event) => updateSeo({ index_mode: event.target.value })}
        select
        SelectProps={{ native: true }}
        value={toStringValue(seo.index_mode) || 'index'}
      >
        <option value="index">index</option>
        <option value="noindex">noindex</option>
      </TextField>
    </Stack>
  );
}

function EntrySettingsEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const settings = parseObjectValue(value);

  if (settings === null) {
    return (
      <TextField
        error
        helperText={error ?? 'Settings data is not a valid JSON object. Edit the raw JSON directly to recover it.'}
        label={field.label}
        minRows={field.minRows ?? 6}
        multiline
        onChange={(event) => onChange(event.target.value)}
        sx={{ '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }}
        value={value}
      />
    );
  }

  const updateSettings = (patch: Record<string, unknown>) => {
    const next = { ...settings, ...patch };
    const compact = Object.fromEntries(
      Object.entries(next).filter(([, entryValue]) => {
        if (typeof entryValue === 'string') {
          return entryValue.trim().length > 0;
        }
        return entryValue !== null && entryValue !== undefined;
      }),
    );
    onChange(Object.keys(compact).length > 0 ? JSON.stringify(compact, null, 2) : '');
  };

  return (
    <Stack spacing={1.5}>
      <Stack spacing={0.25}>
        <Typography variant="subtitle1">{field.label}</Typography>
        <Typography color="text.secondary" variant="body2">
          {error ?? field.helperText}
        </Typography>
      </Stack>
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5}>
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.featured)}
              onChange={(_, checked) => updateSettings({ featured: checked })}
            />
          }
          label="Featured"
        />
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.pin_to_home)}
              onChange={(_, checked) => updateSettings({ pin_to_home: checked })}
            />
          }
          label="Pin to home"
        />
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.show_table_of_contents)}
              onChange={(_, checked) => updateSettings({ show_table_of_contents: checked })}
            />
          }
          label="Show table of contents"
        />
      </Stack>
      <TextField
        label="Hero variant"
        onChange={(event) => updateSettings({ hero_variant: event.target.value })}
        select
        SelectProps={{ native: true }}
        value={toStringValue(settings.hero_variant) || 'standard'}
      >
        <option value="standard">standard</option>
        <option value="spotlight">spotlight</option>
        <option value="minimal">minimal</option>
      </TextField>
      <TextField
        label="Editorial note"
        minRows={3}
        multiline
        onChange={(event) => updateSettings({ note: event.target.value })}
        value={toStringValue(settings.note)}
      />
    </Stack>
  );
}

function BlockEditorField({
  assetOptions,
  error,
  field,
  onChange,
  value,
}: {
  assetOptions: RelationOption[];
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const blocks = parseBlockDrafts(value);

  if (blocks === null) {
    return (
      <TextField
        error
        helperText={error ?? 'Existing block data is not in the expected array format. Edit the raw JSON directly.'}
        label={field.label}
        multiline
        minRows={field.minRows ?? 8}
        onChange={(event) => onChange(event.target.value)}
        sx={{ '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }}
        value={value}
      />
    );
  }

  const updateBlocks = (nextBlocks: BlockDraft[]) => {
    onChange(nextBlocks.length > 0 ? serializeBlocks(nextBlocks) : '');
  };

  const addBlock = () => updateBlocks([...blocks, defaultBlockDraft()]);
  const replaceBlock = (index: number, block: BlockDraft) => {
    const nextBlocks = [...blocks];
    nextBlocks[index] = block;
    updateBlocks(nextBlocks);
  };
  const deleteBlock = (index: number) => updateBlocks(blocks.filter((_, current) => current !== index));
  const moveBlock = (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= blocks.length) {
      return;
    }
    const nextBlocks = [...blocks];
    const [item] = nextBlocks.splice(index, 1);
    nextBlocks.splice(target, 0, item);
    updateBlocks(nextBlocks);
  };

  return (
    <Stack spacing={1.5}>
      <Stack direction="row" justifyContent="space-between" spacing={1}>
        <Stack spacing={0.25}>
          <Typography variant="subtitle1">{field.label}</Typography>
          <Typography color="text.secondary" variant="body2">
            {error ?? field.helperText ?? 'Compose the entry body as ordered content blocks.'}
          </Typography>
        </Stack>
        <Button onClick={addBlock} size="small" startIcon={<AddCircleOutlineRounded />} variant="outlined">
          Add block
        </Button>
      </Stack>

      {blocks.length > 0 ? (
        blocks.map((block, index) => {
          const assetValue =
            assetOptions.find((option) => option.id === block.assetId) ??
            (block.assetId ? { id: block.assetId, label: `#${block.assetId}` } : null);

          return (
            <Card key={`${index}:${block.type}`} sx={{ borderStyle: 'dashed' }}>
              <CardContent>
                <Stack spacing={2}>
                  <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5}>
                    <TextField
                      label="Block type"
                      onChange={(event) => replaceBlock(index, { ...block, type: event.target.value })}
                      required
                      select
                      SelectProps={{ native: true }}
                      sx={{ minWidth: { md: 200 } }}
                      value={block.type}
                    >
                      {blockTypes.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </TextField>
                    <TextField
                      fullWidth
                      label="Heading"
                      onChange={(event) => replaceBlock(index, { ...block, title: event.target.value })}
                      value={block.title}
                    />
                  </Stack>

                  <TextField
                    fullWidth
                    label="Content"
                    minRows={block.type === 'quote' ? 3 : 5}
                    multiline
                    onChange={(event) => replaceBlock(index, { ...block, content: event.target.value })}
                    value={block.content}
                  />

                  {block.type === 'callout' ? (
                    <TextField
                      label="Tone"
                      onChange={(event) => replaceBlock(index, { ...block, tone: event.target.value })}
                      select
                      SelectProps={{ native: true }}
                      value={block.tone}
                    >
                      {blockTones.map((tone) => (
                        <option key={tone} value={tone}>
                          {tone}
                        </option>
                      ))}
                    </TextField>
                  ) : null}

                  {block.type === 'hero' || block.type === 'image' ? (
                    <Autocomplete
                      autoHighlight
                      clearOnEscape
                      fullWidth
                      getOptionLabel={(option) => option.label}
                      isOptionEqualToValue={(option, selected) => option.id === selected.id}
                      onChange={(_, option) => replaceBlock(index, { ...block, assetId: option?.id ?? '' })}
                      options={assetOptions}
                      renderInput={(params) => (
                        <TextField
                          {...params}
                          helperText="Optional media asset linked to this block."
                          label="Linked asset"
                        />
                      )}
                      renderOption={(props, option) => (
                        <Box component="li" {...props}>
                          <Stack spacing={0.25}>
                            <Typography fontWeight={600}>{option.label}</Typography>
                            <Typography color="text.secondary" variant="body2">
                              {option.description ? `${option.description} · #${option.id}` : `#${option.id}`}
                            </Typography>
                          </Stack>
                        </Box>
                      )}
                      value={assetValue}
                    />
                  ) : null}

                  <Stack direction="row" justifyContent="space-between" spacing={1}>
                    <Stack direction="row" spacing={1}>
                      <Button
                        disabled={index === 0}
                        onClick={() => moveBlock(index, -1)}
                        size="small"
                        startIcon={<ArrowUpwardRounded />}
                        variant="text"
                      >
                        Up
                      </Button>
                      <Button
                        disabled={index === blocks.length - 1}
                        onClick={() => moveBlock(index, 1)}
                        size="small"
                        startIcon={<ArrowDownwardRounded />}
                        variant="text"
                      >
                        Down
                      </Button>
                    </Stack>
                    <Button
                      color="error"
                      onClick={() => deleteBlock(index)}
                      size="small"
                      startIcon={<DeleteOutlineRounded />}
                      variant="text"
                    >
                      Remove
                    </Button>
                  </Stack>
                </Stack>
              </CardContent>
            </Card>
          );
        })
      ) : (
        <Alert severity="info" variant="outlined">
          No content blocks yet. Add a block to start composing the entry body.
        </Alert>
      )}
    </Stack>
  );
}

export default App;
