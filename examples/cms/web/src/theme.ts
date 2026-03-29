import { alpha, createTheme } from '@mui/material/styles';

const ink = '#171411';
const mist = '#f3ede3';
const paper = '#fbf7f1';
const line = alpha('#3d3128', 0.14);
const primary = '#0f766e';
const secondary = '#a8572b';

export const studioTheme = createTheme({
  cssVariables: true,
  shape: {
    borderRadius: 18,
  },
  palette: {
    mode: 'light',
    primary: {
      main: primary,
      light: '#2e9a90',
      dark: '#0a5852',
      contrastText: '#ffffff',
    },
    secondary: {
      main: secondary,
      light: '#c76c38',
      dark: '#84421d',
      contrastText: '#ffffff',
    },
    background: {
      default: mist,
      paper,
    },
    text: {
      primary: ink,
      secondary: alpha(ink, 0.68),
    },
    success: {
      main: '#2f7d4f',
    },
    warning: {
      main: '#b7751c',
    },
    error: {
      main: '#b13a2f',
    },
    divider: line,
  },
  typography: {
    fontFamily: '"Manrope Variable", "Avenir Next", "Segoe UI", sans-serif',
    h1: {
      fontFamily: '"Newsreader", Georgia, serif',
      fontSize: 'clamp(2.8rem, 8vw, 5.5rem)',
      fontWeight: 700,
      letterSpacing: '-0.05em',
      lineHeight: 0.94,
    },
    h2: {
      fontFamily: '"Newsreader", Georgia, serif',
      fontSize: 'clamp(2.1rem, 6.2vw, 4.2rem)',
      fontWeight: 700,
      letterSpacing: '-0.05em',
      lineHeight: 0.98,
    },
    h3: {
      fontFamily: '"Newsreader", Georgia, serif',
      fontSize: 'clamp(1.6rem, 4.6vw, 2.8rem)',
      fontWeight: 700,
      letterSpacing: '-0.04em',
    },
    h4: {
      fontFamily: '"Newsreader", Georgia, serif',
      fontSize: 'clamp(1.28rem, 3.2vw, 1.9rem)',
      fontWeight: 700,
      letterSpacing: '-0.03em',
    },
    h5: {
      fontSize: 'clamp(0.96rem, 1.8vw, 1.2rem)',
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    h6: {
      fontSize: 'clamp(0.92rem, 1.4vw, 1.04rem)',
      fontWeight: 700,
      letterSpacing: '-0.02em',
    },
    body1: {
      fontSize: '0.95rem',
      lineHeight: 1.6,
    },
    body2: {
      fontSize: '0.88rem',
      lineHeight: 1.55,
    },
    overline: {
      fontWeight: 800,
      fontSize: '0.68rem',
      letterSpacing: '0.12em',
      textTransform: 'uppercase',
    },
    button: {
      fontWeight: 700,
      letterSpacing: '-0.01em',
      textTransform: 'none',
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        ':root': {
          colorScheme: 'light',
        },
        body: {
          color: ink,
        },
        '::selection': {
          backgroundColor: alpha(primary, 0.2),
        },
      },
    },
    MuiPaper: {
      defaultProps: {
        elevation: 0,
      },
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: `1px solid ${line}`,
          boxShadow: '0 20px 60px rgba(23, 20, 17, 0.04)',
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
          paddingInline: 14,
          minHeight: 38,
        },
        containedPrimary: {
          boxShadow: `0 14px 32px ${alpha(primary, 0.22)}`,
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          borderRadius: 16,
          backgroundColor: alpha('#ffffff', 0.72),
          transition: 'background-color 180ms ease, transform 180ms ease',
          '&:hover': {
            backgroundColor: '#ffffff',
          },
          '&.Mui-focused': {
            transform: 'translateY(-1px)',
            backgroundColor: '#ffffff',
          },
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        fullWidth: true,
        size: 'small',
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 999,
          fontSize: '0.78rem',
          fontWeight: 700,
        },
      },
    },
    MuiAutocomplete: {
      styleOverrides: {
        paper: {
          borderRadius: 18,
          border: `1px solid ${line}`,
          boxShadow: '0 18px 42px rgba(23, 20, 17, 0.12)',
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          borderRadius: 28,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          background: `linear-gradient(180deg, ${alpha('#ffffff', 0.92)}, ${alpha(paper, 0.96)})`,
          borderRight: `1px solid ${line}`,
        },
      },
    },
    MuiAvatar: {
      styleOverrides: {
        root: {
          fontWeight: 800,
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 18,
        },
      },
    },
  },
});
