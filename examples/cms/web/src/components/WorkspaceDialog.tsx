import { CloseRounded } from '@mui/icons-material';
import { Box, Dialog, IconButton, Stack, Typography, useMediaQuery } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import type { ReactNode } from 'react';

export function WorkspaceDialog({
  children,
  label,
  open,
  onClose,
  title,
}: {
  children: ReactNode;
  label: string;
  open: boolean;
  onClose: () => void;
  title: string;
}) {
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down('sm'));

  return (
    <Dialog fullScreen onClose={onClose} open={open}>
      <Box
        sx={{
          minHeight: '100%',
          background:
            'linear-gradient(180deg, rgba(244, 239, 231, 0.94), rgba(239, 231, 220, 0.98))',
        }}
      >
        <Stack
          direction="row"
          alignItems="flex-start"
          justifyContent="space-between"
          spacing={2}
          sx={{ px: { xs: 2, sm: 3 }, pt: { xs: 2, sm: 3 }, pb: 1.5 }}
        >
          <Box className="studio-sectionHeader">
            <Typography variant="overline">{label}</Typography>
            <Typography variant={compact ? 'h5' : 'h4'}>{title}</Typography>
          </Box>
          <IconButton onClick={onClose}>
            <CloseRounded />
          </IconButton>
        </Stack>

        <Box sx={{ px: { xs: 2, sm: 3 }, pb: { xs: 2, sm: 3 } }}>{children}</Box>
      </Box>
    </Dialog>
  );
}
