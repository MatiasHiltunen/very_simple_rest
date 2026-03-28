import { alpha, createTheme } from '@mui/material/styles';

export const studioTheme = createTheme({
  cssVariables: true,
  shape: {
    borderRadius: 20,
  },
  palette: {
    mode: 'light',
    primary: {
      main: '#006b62',
      light: '#3a978c',
      dark: '#004d47',
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#a95f00',
      light: '#d28127',
      dark: '#7a4300',
      contrastText: '#ffffff',
    },
    background: {
      default: '#f4f7f8',
      paper: '#ffffff',
    },
    success: {
      main: '#2e7d32',
    },
    warning: {
      main: '#c77700',
    },
    error: {
      main: '#ba1a1a',
    },
  },
  typography: {
    fontFamily: 'Roboto, system-ui, sans-serif',
    h3: {
      fontWeight: 700,
      letterSpacing: '-0.04em',
    },
    h4: {
      fontWeight: 700,
      letterSpacing: '-0.03em',
    },
    h5: {
      fontWeight: 700,
    },
    h6: {
      fontWeight: 600,
    },
    button: {
      fontWeight: 600,
      textTransform: 'none',
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: alpha('#ffffff', 0.9),
          backdropFilter: 'blur(18px)',
          color: '#102027',
          boxShadow: 'none',
          borderBottom: `1px solid ${alpha('#102027', 0.08)}`,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          borderRight: `1px solid ${alpha('#102027', 0.08)}`,
          backgroundImage:
            'linear-gradient(180deg, rgba(0, 107, 98, 0.08), rgba(255, 255, 255, 0))',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          boxShadow: '0 18px 40px rgba(16, 32, 39, 0.08)',
          border: `1px solid ${alpha('#102027', 0.06)}`,
        },
      },
    },
    MuiButton: {
      defaultProps: {
        disableElevation: true,
      },
      styleOverrides: {
        root: {
          borderRadius: 999,
          paddingInline: 18,
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 600,
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        fullWidth: true,
        size: 'small',
      },
    },
  },
});
