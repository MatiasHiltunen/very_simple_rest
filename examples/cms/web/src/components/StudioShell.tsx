import {
  LaunchRounded,
  LogoutRounded,
  MenuRounded,
} from '@mui/icons-material';
import {
  Avatar,
  Box,
  Button,
  Chip,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Stack,
  Typography,
  useMediaQuery,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import type { AuthMeResponse } from '../lib/api';
import { cmsNavigation, lookupResource } from '../lib/cms';
import { initials } from '../lib/draft';
import { resolveDocsPath } from '../lib/runtime';

function shellHeading(pathname: string): {
  label: string;
  description: string;
  compactDescription?: string;
} {
  if (pathname === '/') {
    return {
      label: 'Command center',
      description: 'Workspace readiness, content health, and API coverage.',
      compactDescription: 'Workspace health and API coverage.',
    };
  }

  if (pathname === '/users') {
    return {
      label: 'Users',
      description: 'Built-in auth accounts, verification, and workspace claims.',
      compactDescription: 'Accounts and workspace claims.',
    };
  }

  const resource = lookupResource(pathname);
  const summaries: Record<string, { full: string; compact?: string }> = {
    entries: {
      full: 'Live editorial workspace.',
    },
    topics: {
      full: 'Reusable taxonomy and routing.',
      compact: 'Taxonomy and routing.',
    },
    assets: {
      full: 'Media intake, metadata, and preview.',
      compact: 'Media and preview.',
    },
    menus: {
      full: 'Navigation structure and settings.',
      compact: 'Navigation settings.',
    },
    'menu-items': {
      full: 'Link order, targets, and hierarchy.',
      compact: 'Links and hierarchy.',
    },
    profiles: {
      full: 'Author identity and member preferences.',
      compact: 'Author identity and preferences.',
    },
    workspaces: {
      full: 'Brand, locale, and editorial policy.',
      compact: 'Brand, locale, editorial policy.',
    },
    users: {
      full: 'Built-in auth accounts, verification, and workspace claims.',
      compact: 'Accounts and workspace claims.',
    },
    'entry-topics': {
      full: 'Explicit entry-topic relationships.',
      compact: 'Entry-topic relationships.',
    },
  };
  const summary = resource ? summaries[resource.key] : null;

  return {
    label: resource?.label ?? 'Studio',
    description: summary?.full ?? 'Schema-aware workspace for the CMS backend.',
    compactDescription: summary?.compact ?? summary?.full ?? 'Schema-aware CMS workspace.',
  };
}

export function StudioShell({
  account,
  onLogout,
}: {
  account: AuthMeResponse;
  onLogout: () => void | Promise<void>;
}) {
  const theme = useTheme();
  const location = useLocation();
  const lgDown = useMediaQuery(theme.breakpoints.down('lg'));
  const mdDown = useMediaQuery(theme.breakpoints.down('md'));
  const [mobileOpen, setMobileOpen] = useState(false);

  const heading = shellHeading(location.pathname);
  const docsPath = resolveDocsPath();
  const navigation = cmsNavigation
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => item.to !== '/users' || account.roles.includes('admin')),
    }))
    .filter((section) => section.items.length > 0);

  const navContent = (drawer = false) => (
    <Box className={drawer ? 'studio-rail studio-rail--drawer' : 'studio-rail'}>
      <Box className="studio-brand">
        <Box className="brand-mark">VS</Box>
        <Box className="brand-copy">
          <Typography className="brand-title">Very Simple CMS</Typography>
          <Typography className="brand-subtitle">OpenAPI studio</Typography>
        </Box>
      </Box>

      <Box className="studio-nav">
        {navigation.map((section) => (
          <Box className="studio-navSection" key={section.label}>
            <Typography className="studio-navLabel">{section.label}</Typography>
            <List disablePadding>
              {section.items.map((item) => {
                const selected =
                  item.to === '/'
                    ? location.pathname === '/'
                    : location.pathname === item.to || location.pathname.startsWith(`${item.to}/`);
                const Icon = item.icon;

                return (
                  <ListItemButton
                    component={NavLink}
                    key={item.to}
                    onClick={() => setMobileOpen(false)}
                    selected={selected}
                    sx={{ borderRadius: 3, mb: 0.5 }}
                    to={item.to}
                  >
                    <ListItemIcon sx={{ minWidth: 38 }}>
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

      <Box className="studio-accountMeta">
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Avatar sx={{ bgcolor: 'primary.main' }}>{initials(account.email)}</Avatar>
          <Stack spacing={0.25} minWidth={0}>
            <Typography fontWeight={700} noWrap>
              {account.email ?? `User #${account.id}`}
            </Typography>
            <Typography color="text.secondary" noWrap variant="body2">
              {account.roles.join(', ')}
            </Typography>
          </Stack>
        </Stack>

        {typeof account.workspace_id === 'number' ? (
          <Chip color="primary" label={`Workspace #${account.workspace_id}`} variant="outlined" />
        ) : (
          <Chip color="warning" label="No workspace claim" variant="outlined" />
        )}

        <Button
          component="a"
          endIcon={<LaunchRounded />}
          href={docsPath}
          rel="noreferrer"
          target="_blank"
          variant="outlined"
        >
          API docs
        </Button>
        <Button onClick={() => void onLogout()} startIcon={<LogoutRounded />} variant="text">
          Sign out
        </Button>
      </Box>
    </Box>
  );

  return (
    <Box className="studio-app">
      <Box className="studio-frame">
        {!lgDown ? navContent() : null}

        <Box className="studio-main">
          <Box className="studio-topbar">
            <Stack
              className="studio-topbarLead"
              direction="row"
              spacing={1.5}
              alignItems="center"
              minWidth={0}
            >
              {lgDown ? (
                <IconButton onClick={() => setMobileOpen(true)}>
                  <MenuRounded />
                </IconButton>
              ) : null}
              <Box className="studio-topbarMeta">
                <Typography className="studio-overline">{heading.label}</Typography>
                <Typography className="studio-topbarTitle" variant="h5">
                  {mdDown ? heading.compactDescription ?? heading.description : heading.description}
                </Typography>
              </Box>
            </Stack>

            {!mdDown ? (
              <Stack className="studio-topbarActions" direction="row" spacing={1} alignItems="center">
                {typeof account.workspace_id === 'number' ? (
                  <Chip
                    color="primary"
                    label={`Workspace #${account.workspace_id}`}
                    size="small"
                    variant="outlined"
                  />
                ) : (
                  <Chip
                    color="warning"
                    label="Workspace not assigned"
                    size="small"
                    variant="outlined"
                  />
                )}
                <Avatar sx={{ bgcolor: 'secondary.main' }}>{initials(account.email)}</Avatar>
              </Stack>
            ) : null}
          </Box>

          <Box className="studio-content">
            <Outlet />
          </Box>
        </Box>
      </Box>

      <Drawer
        ModalProps={{ keepMounted: true }}
        onClose={() => setMobileOpen(false)}
        open={mobileOpen}
        sx={{ display: { lg: 'none' } }}
      >
        <Box sx={{ width: 292 }}>
          {navContent(true)}
        </Box>
      </Drawer>
    </Box>
  );
}
