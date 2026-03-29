import { useEffect, useState } from 'react';
import { CircularProgress, Stack, Typography } from '@mui/material';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import {
  clearAuthToken,
  getAuthenticatedAccount,
  login,
  logout,
  persistAuthToken,
  readAuthToken,
  setUnauthorizedHandler,
} from './lib/api';
import { collectionResources } from './lib/cms';
import { CollectionWorkspace } from './components/CollectionWorkspace';
import { EntryWorkspace } from './components/EntryWorkspace';
import { LoginScreen } from './components/LoginScreen';
import { OverviewScreen } from './components/OverviewScreen';
import { SitePreviewScreen } from './components/SitePreviewScreen';
import { StudioShell } from './components/StudioShell';
import { UsersWorkspace } from './components/UsersWorkspace';

function isKnownStudioPath(pathname: string): boolean {
  if (pathname === '/') {
    return true;
  }

  const knownPrefixes = [
    '/entries',
    '/users',
    '/preview',
    ...collectionResources.map((resource) => `/${resource.key}`),
  ];
  return knownPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function LoadingScreen() {
  return (
    <Stack sx={{ minHeight: '100vh' }} alignItems="center" justifyContent="center" spacing={2}>
      <CircularProgress />
      <Typography color="text.secondary">Connecting to the studio…</Typography>
    </Stack>
  );
}

export default function App() {
  const queryClient = useQueryClient();
  const location = useLocation();
  const [token, setToken] = useState<string | null>(() => readAuthToken());
  const [loginError, setLoginError] = useState<string | null>(null);

  const clearSession = (message?: string) => {
    clearAuthToken();
    setToken(null);
    setLoginError(message ?? null);
    queryClient.clear();
  };

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

  const handleLogout = async () => {
    try {
      await logout();
    } catch {
      // Local token cleanup is enough for bearer-auth development flows.
    } finally {
      clearSession();
    }
  };

  const handleReloginRequired = (message: string) => {
    clearSession(message);
  };

  if (!token) {
    if (!isKnownStudioPath(location.pathname)) {
      return <Navigate replace to="/" />;
    }
    return <LoginScreen initialError={loginError} onLogin={handleLogin} />;
  }

  if (accountQuery.isLoading) {
    return <LoadingScreen />;
  }

  if (!accountQuery.data) {
    return <LoginScreen initialError="Unable to load your account." onLogin={handleLogin} />;
  }

  return (
    <Routes>
      <Route path="preview/:workspaceSlug/*" element={<SitePreviewScreen />} />
      <Route element={<StudioShell account={accountQuery.data} onLogout={handleLogout} />}>
        <Route
          index
          element={
            <OverviewScreen
              account={accountQuery.data}
              onReloginRequired={handleReloginRequired}
            />
          }
        />
        <Route path="entries" element={<EntryWorkspace account={accountQuery.data} />} />
        <Route path="users" element={<UsersWorkspace account={accountQuery.data} />} />
        {collectionResources.map((resource) => (
          <Route
            element={<CollectionWorkspace account={accountQuery.data} config={resource} />}
            key={resource.key}
            path={resource.key}
          />
        ))}
        <Route path="*" element={<Navigate replace to="/" />} />
      </Route>
    </Routes>
  );
}
