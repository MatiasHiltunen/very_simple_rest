import { startTransition, useDeferredValue, useState } from 'react';
import {
  AddRounded,
  DeleteOutlineRounded,
  InfoRounded,
  MarkEmailUnreadRounded,
  MoreHorizRounded,
  RefreshRounded,
  SaveRounded,
  ViewListRounded,
} from '@mui/icons-material';
import {
  Alert,
  Box,
  Button,
  Chip,
  FormControlLabel,
  InputAdornment,
  Paper,
  Snackbar,
  Stack,
  Switch,
  TextField,
  Typography,
  useMediaQuery,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';
import {
  createManagedUser,
  deleteResource,
  listResource,
  resendManagedUserVerification,
  updateManagedUser,
  type AuthMeResponse,
} from '../lib/api';
import { formatFriendlyDate, type Notice } from '../lib/draft';
import { formatMethodLabel, getOperationsForResource } from '../lib/openapi';
import { ConfirmDialog } from './ConfirmDialog';
import { WorkspaceDialog } from './WorkspaceDialog';

const EMPTY_USERS: AuthMeResponse[] = [];
const COMMON_ROLES = ['editor', 'admin', 'author', 'viewer'] as const;

interface UserDraft {
  email: string;
  password: string;
  role: string;
  emailVerified: boolean;
  sendVerificationEmail: boolean;
  workspaceId: string;
}

function draftsEqual(left: UserDraft, right: UserDraft): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function toUserDraft(user?: AuthMeResponse | null): UserDraft {
  return {
    email: typeof user?.email === 'string' ? user.email : '',
    password: '',
    role: typeof user?.role === 'string' && user.role.trim() ? user.role : 'editor',
    emailVerified: user?.email_verified === true,
    sendVerificationEmail: false,
    workspaceId: typeof user?.workspace_id === 'number' ? String(user.workspace_id) : '',
  };
}

function userTitle(user: AuthMeResponse | null, draft: UserDraft): string {
  if (user) {
    return user.email ?? `User #${user.id}`;
  }
  return draft.email.trim() || 'Create account';
}

function workspaceLabel(row: Record<string, unknown>): string {
  if (typeof row.name === 'string' && row.name.trim()) {
    return row.name;
  }
  if (typeof row.slug === 'string' && row.slug.trim()) {
    return row.slug;
  }
  return `Workspace #${String(row.id ?? '?')}`;
}

export function UsersWorkspace({ account }: { account: AuthMeResponse }) {
  const theme = useTheme();
  const compactWorkspace = useMediaQuery(theme.breakpoints.down('md'));
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [notice, setNotice] = useState<Notice>(null);
  const [activeKey, setActiveKey] = useState('new');
  const [selectedUser, setSelectedUser] = useState<AuthMeResponse | null>(null);
  const [draft, setDraft] = useState<UserDraft>(() => toUserDraft());
  const [baselineDraft, setBaselineDraft] = useState<UserDraft>(() => toUserDraft());
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [mobileListOpen, setMobileListOpen] = useState(false);
  const [mobileContextOpen, setMobileContextOpen] = useState(false);
  const [mobileActionsOpen, setMobileActionsOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState<
    | { kind: 'create' }
    | { kind: 'user'; user: AuthMeResponse }
    | null
  >(null);
  const deferredSearch = useDeferredValue(search);
  const dirty = !draftsEqual(draft, baselineDraft);
  const canManageUsers = account.roles.includes('admin');

  const [usersQuery, workspacesQuery] = useQueries({
    queries: [
      {
        queryKey: ['users', 'managed'],
        queryFn: () => listResource<AuthMeResponse>('auth/admin/users', { limit: 100 }),
        enabled: canManageUsers,
      },
      {
        queryKey: ['users', 'workspaces'],
        queryFn: () => listResource<Record<string, unknown>>('workspaces', { limit: 50, context: 'admin' }),
        enabled: canManageUsers,
      },
    ],
  });

  const users = usersQuery.data?.items ?? EMPTY_USERS;
  const workspaces = workspacesQuery.data?.items ?? [];
  const filteredUsers = users.filter((user) => {
    const query = deferredSearch.trim().toLowerCase();
    if (!query) {
      return true;
    }

    return [user.email, user.role, user.workspace_id]
      .map((value) => String(value ?? '').toLowerCase())
      .some((value) => value.includes(query));
  });

  const activateCreate = () => {
    const emptyDraft = toUserDraft();
    startTransition(() => {
      setActiveKey('new');
      setSelectedUser(null);
      setDraft(emptyDraft);
      setBaselineDraft(emptyDraft);
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

  const activateUser = (user: AuthMeResponse) => {
    const nextDraft = toUserDraft(user);
    startTransition(() => {
      setActiveKey(String(user.id));
      setSelectedUser(user);
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setFieldErrors({});
      setMobileListOpen(false);
    });
  };

  const openUser = (user: AuthMeResponse) => {
    if (dirty) {
      setPendingNavigation({ kind: 'user', user });
      return;
    }

    activateUser(user);
  };

  const confirmPendingNavigation = () => {
    if (!pendingNavigation) {
      return;
    }

    if (pendingNavigation.kind === 'create') {
      activateCreate();
    } else {
      activateUser(pendingNavigation.user);
    }
    setPendingNavigation(null);
  };

  const resetDraft = () => {
    setDraft(baselineDraft);
    setFieldErrors({});
  };

  const saveMutation = useMutation({
    mutationFn: async () => {
      const nextErrors: Record<string, string> = {};
      const trimmedEmail = draft.email.trim();
      const trimmedRole = draft.role.trim();

      if (!selectedUser && !trimmedEmail) {
        nextErrors.email = 'Email is required.';
      }
      if (!selectedUser && !draft.password.trim()) {
        nextErrors.password = 'Password is required when creating a user.';
      }
      if (!trimmedRole) {
        nextErrors.role = 'Role is required.';
      }

      if (Object.keys(nextErrors).length > 0) {
        setFieldErrors(nextErrors);
        throw new Error('Complete the required account fields.');
      }

      if (selectedUser) {
        return updateManagedUser(selectedUser.id, {
          role: trimmedRole,
          email_verified: draft.emailVerified,
          claims: {
            workspace_id: draft.workspaceId ? Number(draft.workspaceId) : null,
          },
        });
      }

      const created = await createManagedUser({
        email: trimmedEmail,
        password: draft.password.trim(),
        role: trimmedRole,
        email_verified: draft.emailVerified,
        send_verification_email: draft.sendVerificationEmail,
      });

      if (!draft.workspaceId) {
        return created;
      }

      return updateManagedUser(created.id, {
        role: trimmedRole,
        email_verified: draft.emailVerified,
        claims: {
          workspace_id: Number(draft.workspaceId),
        },
      });
    },
    onSuccess: async (savedUser) => {
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      const nextDraft = toUserDraft(savedUser);
      setSelectedUser(savedUser);
      setActiveKey(String(savedUser.id));
      setDraft(nextDraft);
      setBaselineDraft(nextDraft);
      setNotice({
        severity: 'success',
        message: selectedUser
          ? 'Account settings updated.'
          : draft.sendVerificationEmail
            ? 'Account created and verification email queued.'
            : 'Account created.',
      });
      setMobileActionsOpen(false);
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to save the account.',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      if (!selectedUser) {
        return;
      }
      await deleteResource('auth/admin/users', selectedUser.id);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      const emptyDraft = toUserDraft();
      setActiveKey('new');
      setSelectedUser(null);
      setDraft(emptyDraft);
      setBaselineDraft(emptyDraft);
      setDeleteDialogOpen(false);
      setMobileActionsOpen(false);
      setNotice({
        severity: 'success',
        message: 'Account deleted.',
      });
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to delete the account.',
      });
    },
  });

  const verificationMutation = useMutation({
    mutationFn: async () => {
      if (!selectedUser) {
        return;
      }
      await resendManagedUserVerification(selectedUser.id);
    },
    onSuccess: () => {
      setNotice({
        severity: 'success',
        message: 'Verification email sent.',
      });
      setMobileActionsOpen(false);
    },
    onError: (error) => {
      setNotice({
        severity: 'error',
        message: error instanceof Error ? error.message : 'Unable to send verification email.',
      });
    },
  });

  if (!canManageUsers) {
    return (
      <Paper className="studio-panel" sx={{ p: { xs: 2.5, md: 3 } }}>
        <Stack spacing={2}>
          <Typography variant="h5">Admin access required</Typography>
          <Typography color="text.secondary">
            Built-in user management uses the admin auth endpoints. Sign in with an admin role to create
            accounts, assign workspace claims, and resend verification emails.
          </Typography>
          <Button component={NavLink} to="/" variant="outlined">
            Return to command center
          </Button>
        </Stack>
      </Paper>
    );
  }

  const operations = getOperationsForResource('auth/admin/users');
  const currentWorkspace = workspaces.find((row) => Number(row.id) === Number(draft.workspaceId));

  const railContent = (
    <Stack spacing={2}>
      <Stack spacing={1}>
        <Typography variant="overline">Access control</Typography>
        <Typography variant="h5">
          Create accounts, verify access, and attach users to a workspace scope.
        </Typography>
      </Stack>

      <TextField
        InputProps={{
          startAdornment: <InputAdornment position="start">Search</InputAdornment>,
        }}
        label="Search users"
        onChange={(event) => setSearch(event.target.value)}
        value={search}
      />

      <Button onClick={openCreate} startIcon={<AddRounded />} variant="contained">
        New account
      </Button>

      {usersQuery.isLoading ? (
        <Alert severity="info" variant="outlined">
          Loading built-in accounts…
        </Alert>
      ) : usersQuery.error ? (
        <Alert severity="error" variant="outlined">
          {usersQuery.error instanceof Error ? usersQuery.error.message : 'Unable to load users.'}
        </Alert>
      ) : filteredUsers.length > 0 ? (
        <Box className="record-list">
          {filteredUsers.map((user) => (
            <button
              className="record-item"
              data-selected={activeKey === String(user.id)}
              key={String(user.id)}
              onClick={() => openUser(user)}
              type="button"
            >
              <Box className="record-itemHeader">
                <Box>
                  <Typography className="record-itemTitle">
                    {user.email ?? `User #${user.id}`}
                  </Typography>
                  <Typography className="record-itemMeta">
                    {user.email_verified ? 'Verified' : 'Awaiting verification'} · {user.role ?? 'editor'}
                  </Typography>
                </Box>
              </Box>
              <Box className="record-itemFooter">
                <Typography className="studio-overline">
                  {typeof user.workspace_id === 'number' ? `WS #${user.workspace_id}` : 'No workspace'}
                </Typography>
                <Typography className="record-itemMeta">#{user.id}</Typography>
              </Box>
            </button>
          ))}
        </Box>
      ) : (
        <Box className="empty-state">
          <Typography fontWeight={700}>No built-in users yet</Typography>
          <Typography variant="body2">
            Create the first account here instead of leaving auth administration outside the studio.
          </Typography>
        </Box>
      )}
    </Stack>
  );

  const contextContent = (
    <Stack spacing={2.5}>
      <Box className="studio-sectionHeader">
        <Typography variant="h5">Account context</Typography>
        <Typography color="text.secondary">
          Verification state, workspace scope, and the admin endpoints behind this surface.
        </Typography>
      </Box>

      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={1}>
          <Typography fontWeight={700}>Current selection</Typography>
          <Typography color="text.secondary" variant="body2">
            {selectedUser
              ? `${selectedUser.email ?? `User #${selectedUser.id}`} · ${selectedUser.role ?? 'editor'}`
              : 'Create a new account, then assign a workspace scope before handing it off.'}
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Chip
              color={draft.emailVerified ? 'success' : 'warning'}
              label={draft.emailVerified ? 'Verified' : 'Verification pending'}
              size="small"
              variant="outlined"
            />
            <Chip
              label={currentWorkspace ? workspaceLabel(currentWorkspace) : 'No workspace claim'}
              size="small"
              variant="outlined"
            />
          </Stack>
        </Stack>
      </Paper>

      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={1}>
          <Typography fontWeight={700}>Audit trail</Typography>
          <Typography color="text.secondary" variant="body2">
            Created: {selectedUser?.created_at ? formatFriendlyDate(selectedUser.created_at) : 'New draft'}
          </Typography>
          <Typography color="text.secondary" variant="body2">
            Updated: {selectedUser?.updated_at ? formatFriendlyDate(selectedUser.updated_at) : 'Not saved yet'}
          </Typography>
          <Typography color="text.secondary" variant="body2">
            Verified at: {selectedUser?.email_verified_at ? formatFriendlyDate(selectedUser.email_verified_at) : 'Not verified yet'}
          </Typography>
        </Stack>
      </Paper>

      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={1.25}>
          <Typography fontWeight={700}>API surface</Typography>
          <Box className="api-list">
            {operations.map((operation) => (
              <Box className="api-item" key={`${operation.method}:${operation.path}`}>
                <Box>
                  <Typography fontWeight={700}>{formatMethodLabel(operation.method)}</Typography>
                  <Typography className="api-itemPath">{operation.path}</Typography>
                </Box>
                <Typography color="text.secondary" textAlign="right" variant="body2">
                  {operation.summary}
                </Typography>
              </Box>
            ))}
          </Box>
        </Stack>
      </Paper>
    </Stack>
  );

  const mobileActionContent = (
    <Stack spacing={1.5}>
      <Paper className="studio-panelTight" sx={{ p: 2 }}>
        <Stack spacing={0.75}>
          <Typography fontWeight={700}>{userTitle(selectedUser, draft)}</Typography>
          <Typography color="text.secondary" variant="body2">
            {selectedUser
              ? 'Use this sheet for lifecycle actions while the editor stays focused on fields.'
              : 'Save the account first to unlock verification and deletion actions.'}
          </Typography>
        </Stack>
      </Paper>

      <Button fullWidth onClick={resetDraft} startIcon={<RefreshRounded />} variant="outlined">
        Reset changes
      </Button>

      {selectedUser && !draft.emailVerified ? (
        <Button
          disabled={verificationMutation.isPending}
          fullWidth
          onClick={() => verificationMutation.mutate()}
          startIcon={<MarkEmailUnreadRounded />}
          variant="outlined"
        >
          {verificationMutation.isPending ? 'Sending…' : 'Resend verification'}
        </Button>
      ) : null}

      {selectedUser ? (
        <Button
          color="error"
          disabled={deleteMutation.isPending}
          fullWidth
          onClick={() => setDeleteDialogOpen(true)}
          startIcon={<DeleteOutlineRounded />}
          variant="outlined"
        >
          Delete account
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
        onSubmit={(event) => {
          event.preventDefault();
          setFieldErrors({});
          void saveMutation.mutateAsync();
        }}
        sx={{ p: { xs: 2, md: 3 } }}
      >
        <Stack direction={{ xs: 'column', lg: 'row' }} justifyContent="space-between" spacing={2}>
          <Stack spacing={0.75}>
            <Typography variant="overline">
              {selectedUser ? `User #${selectedUser.id}` : 'New built-in account'}
            </Typography>
            <Typography variant="h4">{userTitle(selectedUser, draft)}</Typography>
            <Box className="status-line">
              <span className="status-pulse" />
              <Typography color="text.secondary" variant="body2">
                {dirty ? 'Unsaved account changes' : 'Account editor is in sync with the latest saved state'}
              </Typography>
            </Box>
          </Stack>

          {!compactWorkspace ? (
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
              <Button onClick={resetDraft} startIcon={<RefreshRounded />} variant="outlined">
                Reset
              </Button>
              {selectedUser && !draft.emailVerified ? (
                <Button
                  disabled={verificationMutation.isPending}
                  onClick={() => verificationMutation.mutate()}
                  startIcon={<MarkEmailUnreadRounded />}
                  variant="outlined"
                >
                  {verificationMutation.isPending ? 'Sending…' : 'Resend verification'}
                </Button>
              ) : null}
              {selectedUser ? (
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
                {saveMutation.isPending ? 'Saving…' : selectedUser ? 'Save account' : 'Create account'}
              </Button>
            </Stack>
          ) : null}
        </Stack>

        {compactWorkspace ? (
          <Box className="workspace-mobileToolbar">
            <Button onClick={() => setMobileListOpen(true)} size="small" startIcon={<ViewListRounded />} variant="outlined">
              Users
            </Button>
            <Button onClick={() => setMobileContextOpen(true)} size="small" startIcon={<InfoRounded />} variant="outlined">
              Context
            </Button>
            <Button onClick={() => setMobileActionsOpen(true)} size="small" startIcon={<MoreHorizRounded />} variant="outlined">
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

        <Stack spacing={2.5}>
          <Paper className="studio-panelTight" sx={{ p: 2 }}>
            <Stack spacing={2}>
              <Box className="studio-sectionHeader">
                <Typography variant="h6">Identity</Typography>
                <Typography color="text.secondary" variant="body2">
                  Create the account first, then keep role and workspace scope in sync here.
                </Typography>
              </Box>

              <Box
                sx={{
                  display: 'grid',
                  gap: 2,
                  gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
                }}
              >
                <TextField
                  disabled={Boolean(selectedUser)}
                  error={Boolean(fieldErrors.email)}
                  helperText={
                    fieldErrors.email ??
                    (selectedUser
                      ? 'Email is fixed after account creation.'
                      : 'The built-in auth identity used to sign in.')
                  }
                  label="Email address"
                  onChange={(event) => setDraft((current) => ({ ...current, email: event.target.value }))}
                  type="email"
                  value={draft.email}
                />

                {!selectedUser ? (
                  <TextField
                    error={Boolean(fieldErrors.password)}
                    helperText={fieldErrors.password ?? 'Required only for new accounts.'}
                    label="Password"
                    onChange={(event) =>
                      setDraft((current) => ({ ...current, password: event.target.value }))
                    }
                    type="password"
                    value={draft.password}
                  />
                ) : (
                  <TextField
                    disabled
                    helperText="Passwords are created through the auth endpoint and not shown again."
                    label="Password"
                    value="••••••••"
                  />
                )}

                <TextField
                  error={Boolean(fieldErrors.role)}
                  helperText={fieldErrors.role ?? 'Choose the primary built-in auth role for this account.'}
                  label="Role"
                  onChange={(event) => setDraft((current) => ({ ...current, role: event.target.value }))}
                  select
                  SelectProps={{ native: true }}
                  value={draft.role}
                >
                  {COMMON_ROLES.map((role) => (
                    <option key={role} value={role}>
                      {role}
                    </option>
                  ))}
                </TextField>

                <TextField
                  helperText="Optional workspace scope added as a custom claim on the account."
                  label="Workspace claim"
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, workspaceId: event.target.value }))
                  }
                  select
                  SelectProps={{ native: true }}
                  value={draft.workspaceId}
                >
                  <option value="">No workspace claim</option>
                  {workspaces.map((workspace) => (
                    <option key={String(workspace.id)} value={String(workspace.id)}>
                      {workspaceLabel(workspace)}
                    </option>
                  ))}
                </TextField>
              </Box>
            </Stack>
          </Paper>

          <Paper className="studio-panelTight" sx={{ p: 2 }}>
            <Stack spacing={1.5}>
              <Box className="studio-sectionHeader">
                <Typography variant="h6">Verification</Typography>
                <Typography color="text.secondary" variant="body2">
                  Make email state explicit instead of forcing admins to infer it from raw auth data.
                </Typography>
              </Box>

              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} flexWrap="wrap">
                <FormControlLabel
                  control={
                    <Switch
                      checked={draft.emailVerified}
                      onChange={(_, checked) =>
                        setDraft((current) => ({ ...current, emailVerified: checked }))
                      }
                    />
                  }
                  label="Email already verified"
                />
                {!selectedUser ? (
                  <FormControlLabel
                    control={
                      <Switch
                        checked={draft.sendVerificationEmail}
                        onChange={(_, checked) =>
                          setDraft((current) => ({ ...current, sendVerificationEmail: checked }))
                        }
                      />
                    }
                    label="Send verification email"
                  />
                ) : null}
              </Stack>

              {selectedUser ? (
                <Alert severity={draft.emailVerified ? 'success' : 'info'} variant="outlined">
                  {draft.emailVerified
                    ? 'This account is already marked as verified.'
                    : 'Use "Resend verification" if the recipient still needs a new verification email.'}
                </Alert>
              ) : null}
            </Stack>
          </Paper>
        </Stack>
      </Paper>

      {!compactWorkspace ? (
        <Paper className="studio-panel preview-scroll workspace-pane workspace-pane--preview" sx={{ p: { xs: 2, md: 3 } }}>
          {contextContent}
        </Paper>
      ) : null}

      <WorkspaceDialog
        label="Users"
        onClose={() => setMobileListOpen(false)}
        open={mobileListOpen}
        title="Browse built-in accounts"
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {railContent}
        </Paper>
      </WorkspaceDialog>

      <WorkspaceDialog
        label="Account context"
        onClose={() => setMobileContextOpen(false)}
        open={mobileContextOpen}
        title="Inspect the current account"
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {contextContent}
        </Paper>
      </WorkspaceDialog>

      <WorkspaceDialog
        label="Account actions"
        onClose={() => setMobileActionsOpen(false)}
        open={mobileActionsOpen}
        title="Manage the current account"
      >
        <Paper className="studio-panel" sx={{ p: 2 }}>
          {mobileActionContent}
        </Paper>
      </WorkspaceDialog>

      <ConfirmDialog
        body={
          selectedUser
            ? `Delete ${selectedUser.email ?? `user #${selectedUser.id}`} from built-in auth?`
            : 'Delete this account?'
        }
        confirmLabel={deleteMutation.isPending ? 'Deleting…' : 'Delete account'}
        onClose={() => setDeleteDialogOpen(false)}
        onConfirm={() => deleteMutation.mutate()}
        open={deleteDialogOpen}
        title="Delete account"
      />

      <ConfirmDialog
        body="Discard the current unsaved account changes and switch context?"
        confirmLabel="Discard changes"
        onClose={() => setPendingNavigation(null)}
        onConfirm={confirmPendingNavigation}
        open={Boolean(pendingNavigation)}
        title="Leave account draft"
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
