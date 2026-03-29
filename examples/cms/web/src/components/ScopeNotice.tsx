import { Alert, Button, Stack } from '@mui/material';
import { NavLink } from 'react-router-dom';
import type { AuthMeResponse } from '../lib/api';

export function ScopeNotice({
  account,
  label,
}: {
  account: AuthMeResponse;
  label: string;
}) {
  if (typeof account.workspace_id === 'number') {
    return null;
  }

  return (
    <Alert
      action={
        <Stack direction="row" spacing={1}>
          <Button color="inherit" component={NavLink} size="small" to="/" variant="text">
            Command
          </Button>
          {account.roles.includes('admin') ? (
            <Button color="inherit" component={NavLink} size="small" to="/users" variant="text">
              Users
            </Button>
          ) : null}
        </Stack>
      }
      severity="warning"
      variant="outlined"
    >
      {label} is workspace-scoped. Without a <code>workspace_id</code> claim, this view can stay empty
      even when records already exist.
    </Alert>
  );
}
