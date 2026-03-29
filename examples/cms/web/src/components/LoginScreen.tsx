import { VisibilityOffRounded, VisibilityRounded } from '@mui/icons-material';
import {
  Alert,
  Box,
  IconButton,
  InputAdornment,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import Button from '@mui/material/Button';
import { useEffect, useState } from 'react';
import { readLastEmail } from '../lib/api';
import type { DraftState } from '../lib/draft';
import { resolveDocsPath, studioBasePath } from '../lib/runtime';
import { PagePreview } from './PagePreview';

const sampleDraft: DraftState = {
  type: 'landing_page',
  status: 'published',
  visibility: 'public',
  slug: 'spring-issue',
  title: 'A studio where the page is always in view.',
  summary:
    'Edit structure, media, SEO, and publishing state with the rendered result beside you instead of hidden behind forms.',
  hero_asset: '',
  reviewer: '',
  published_at: new Date().toISOString(),
  scheduled_for: '',
  topics: '',
  body_blocks: JSON.stringify(
    [
      {
        type: 'paragraph',
        title: 'Compose',
        content:
          'Build entries with structured fields and ordered body blocks. The preview updates as you write, reorder, and adjust presentation settings.',
      },
      {
        type: 'callout',
        title: 'Preview-first workflow',
        content:
          'The page preview is not a thumbnail. It is the main feedback loop for editorial decisions.',
        tone: 'info',
      },
      {
        type: 'quote',
        content: 'The CMS should feel like editing the page, not filling out paperwork.',
      },
    ],
    null,
    2,
  ),
  seo: JSON.stringify(
    {
      meta_title: 'A studio where the page is always in view',
      meta_description: 'Refined CMS workspace with live editorial preview.',
      index_mode: 'index',
    },
    null,
    2,
  ),
  settings: JSON.stringify(
    {
      hero_variant: 'spotlight',
      featured: true,
      show_table_of_contents: false,
    },
    null,
    2,
  ),
};

const sampleWorkspace = {
  name: 'Very Simple CMS',
  public_base_url: 'https://example.local',
};

export function LoginScreen({
  initialError,
  onLogin,
}: {
  initialError: string | null;
  onLogin: (email: string, password: string) => Promise<void>;
}) {
  const [email, setEmail] = useState(() => readLastEmail());
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(initialError);
  const studioPath = studioBasePath().replace(/\/$/, '') || '/';
  const docsPath = resolveDocsPath();

  useEffect(() => {
    setError(initialError);
  }, [initialError]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await onLogin(email, password);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : 'Unable to sign in.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Box className="login-shell">
      <Box className="login-hero">
        <Box className="login-orb" />
        <Box className="login-copy">
          <span className="login-kicker">OpenAPI-first editorial studio</span>
          <Typography className="login-display" component="h1">
            Very Simple CMS
          </Typography>
          <Typography className="login-support">
            Refined authoring for the schema in <code>openapi.json</code>: entries, topics, assets,
            menus, profiles, and workspace controls, with the live page beside the form from the first keystroke.
          </Typography>
        </Box>

        <Box className="login-canvas">
          <Box className="preview-demoShell">
            <Box className="preview-demoRail" aria-hidden="true">
              <Box className="preview-demoLine is-mid" />
              <Box className="preview-demoLine is-short" />
              <Box className="preview-demoLine" />
              <Box className="preview-demoLine is-mid" />
              <Box className="preview-demoLine is-short" />
            </Box>
            <Box className="login-preview">
              <PagePreview
                assetsById={new Map()}
                draft={sampleDraft}
                mode="desktop"
                selectedTopics={[]}
                workspace={sampleWorkspace}
              />
            </Box>
          </Box>
        </Box>
      </Box>

      <Box className="login-panel">
        <Paper className="login-form studio-panel" component="form" onSubmit={handleSubmit}>
          <Stack spacing={3}>
            <Stack spacing={1}>
              <Typography variant="overline">Studio access</Typography>
              <Typography variant="h3">Sign in</Typography>
              <Typography color="text.secondary">
                Use a built-in auth account from the CMS backend. The studio remembers the last email
                on this device for faster local iteration.
              </Typography>
            </Stack>

            {error ? <Alert severity="error">{error}</Alert> : null}

            <TextField
              autoComplete="email"
              label="Email address"
              onChange={(event) => setEmail(event.target.value)}
              required
              type="email"
              value={email}
            />
            <TextField
              autoComplete="current-password"
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
              {submitting ? 'Opening studio…' : 'Open studio'}
            </Button>

            <Typography className="login-footnote">
              Run the backend, then open the studio at <strong>{studioPath}</strong>. API docs stay
              available at <strong>{docsPath}</strong>.
            </Typography>
          </Stack>
        </Paper>
      </Box>
    </Box>
  );
}
