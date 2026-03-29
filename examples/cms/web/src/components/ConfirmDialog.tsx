import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';

export function ConfirmDialog({
  body,
  confirmLabel,
  onClose,
  onConfirm,
  open,
  title,
  tone = 'error',
}: {
  body: string;
  confirmLabel: string;
  onClose: () => void;
  onConfirm: () => void;
  open: boolean;
  title: string;
  tone?: 'error' | 'primary';
}) {
  return (
    <Dialog maxWidth="xs" onClose={onClose} open={open} fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Typography color="text.secondary">{body}</Typography>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 3 }}>
        <Button onClick={onClose} variant="text">
          Cancel
        </Button>
        <Button color={tone} onClick={onConfirm} variant="contained">
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
