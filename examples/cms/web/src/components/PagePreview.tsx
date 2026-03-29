import { LaunchRounded } from '@mui/icons-material';
import { Box, Button, Chip, Stack, Typography } from '@mui/material';
import type { ResourceRow } from '../lib/cms';
import type { DraftState } from '../lib/draft';
import {
  assetPreviewUrl,
  formatFriendlyDate,
  parseBlockDrafts,
  parseObjectValue,
  toStringValue,
} from '../lib/draft';

function sourceForAsset(asset: ResourceRow | null): string | null {
  if (!asset) {
    return null;
  }
  return assetPreviewUrl(asset);
}

function bodyParagraphs(content: string): string[] {
  return content
    .split(/\n{2,}/)
    .map((part) => part.trim())
    .filter(Boolean);
}

export function PagePreview({
  assetsById,
  draft,
  mode,
  selectedTopics,
  workspace,
}: {
  assetsById: Map<number, ResourceRow>;
  draft: DraftState;
  mode: 'desktop' | 'mobile';
  selectedTopics: ResourceRow[];
  workspace: ResourceRow | null;
}) {
  const heroAssetId = Number(draft.hero_asset ?? '');
  const heroAsset = Number.isNaN(heroAssetId) ? null : (assetsById.get(heroAssetId) ?? null);
  const heroUrl = sourceForAsset(heroAsset);
  const blocks = parseBlockDrafts(draft.body_blocks ?? '') ?? [];
  const settings = parseObjectValue(draft.settings ?? '') ?? {};
  const seo = parseObjectValue(draft.seo ?? '') ?? {};
  const heroVariant = toStringValue(settings.hero_variant) || 'standard';
  const previewLabel = draft.title?.trim() || 'Untitled story';
  const previewPath = draft.slug?.trim() ? `/${draft.slug.trim()}` : '/untitled';
  const previewHref =
    typeof workspace?.public_base_url === 'string' && workspace.public_base_url
      ? `${workspace.public_base_url.replace(/\/$/, '')}${previewPath}`
      : previewPath;
  const brand = typeof workspace?.name === 'string' && workspace.name ? workspace.name : 'OpenAPI CMS';
  const summary =
    draft.summary?.trim() ||
    'Add a summary to see how the page introduces itself across previews and listings.';

  return (
    <Box className="preview-shell">
      <Box className="preview-device">
        <span className="preview-dot" />
        <span>Live page preview</span>
        <span aria-hidden="true">•</span>
        <span>{mode === 'desktop' ? 'Desktop canvas' : 'Mobile canvas'}</span>
      </Box>

      <Box className="preview-frame">
        <Box className="preview-page" data-mode={mode}>
          <Box className="preview-siteHeader">
            <Stack spacing={0.5}>
              <Typography fontWeight={800} letterSpacing="0.12em" textTransform="uppercase" variant="caption">
                {brand}
              </Typography>
              <Typography variant="body2">{previewPath}</Typography>
            </Stack>
            <Button
              color="inherit"
              component="a"
              endIcon={<LaunchRounded />}
              href={previewHref}
              rel="noreferrer"
              size="small"
              target="_blank"
              variant="text"
            >
              Open path
            </Button>
          </Box>

          <Box
            className="preview-hero"
            data-variant={heroVariant}
            sx={heroUrl ? { backgroundImage: `linear-gradient(180deg, rgba(16, 22, 20, 0.16), rgba(16, 22, 20, 0.82)), url("${heroUrl}")` } : undefined}
          >
            <Box className="preview-heroContent">
              <Box className="preview-brandLine">
                <span>{brand}</span>
                <span aria-hidden="true">/</span>
                <span>{draft.type || 'article'}</span>
              </Box>
              <Typography className="preview-title">{previewLabel}</Typography>
              <Typography className="preview-summary">{summary}</Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip
                  label={(draft.status || 'draft').replaceAll('_', ' ')}
                  size="small"
                  sx={{ bgcolor: 'rgba(255,255,255,0.14)', color: '#fff' }}
                  variant="outlined"
                />
                <Chip
                  label={draft.visibility || 'workspace'}
                  size="small"
                  sx={{ bgcolor: 'rgba(255,255,255,0.14)', color: '#fff' }}
                  variant="outlined"
                />
                <Chip
                  label={formatFriendlyDate(draft.published_at || draft.scheduled_for)}
                  size="small"
                  sx={{ bgcolor: 'rgba(255,255,255,0.14)', color: '#fff' }}
                  variant="outlined"
                />
              </Stack>
              {selectedTopics.length > 0 ? (
                <Box className="preview-topicRow">
                  {selectedTopics.map((topic) => (
                    <Chip
                      key={String(topic.id)}
                      label={String(topic.name ?? topic.slug ?? `Topic #${String(topic.id ?? '')}`)}
                      size="small"
                      sx={{ bgcolor: 'rgba(255,255,255,0.16)', color: '#fff' }}
                      variant="outlined"
                    />
                  ))}
                </Box>
              ) : null}
            </Box>
          </Box>

          <Box className="preview-story">
            <Box className="preview-storyMeta">
              <Typography className="preview-blockTitle">Reading view</Typography>
              <Typography className="preview-blockCopy">
                The studio preview updates immediately from the entry draft, including hero choice,
                block ordering, SEO, and presentation settings.
              </Typography>
            </Box>

            {blocks.length > 0 ? (
              blocks.map((block, index) => {
                const blockAssetId = Number(block.assetId);
                const blockAsset =
                  Number.isNaN(blockAssetId) ? null : (assetsById.get(blockAssetId) ?? null);
                const blockAssetUrl = sourceForAsset(blockAsset);

                if (block.type === 'quote') {
                  return (
                    <Box className="preview-block" key={`${index}:${block.type}`}>
                      {block.title ? (
                        <Typography className="preview-blockTitle">{block.title}</Typography>
                      ) : null}
                      <Typography className="preview-blockQuote">
                        {block.content || 'A quote block becomes visible here.'}
                      </Typography>
                    </Box>
                  );
                }

                if (block.type === 'callout') {
                  return (
                    <Box className="preview-block" key={`${index}:${block.type}`}>
                      {block.title ? (
                        <Typography className="preview-blockTitle">{block.title}</Typography>
                      ) : null}
                      <Box className="preview-blockCallout" data-tone={block.tone}>
                        <Typography className="preview-blockCopy">
                          {block.content || 'Use callouts for urgent notes, guidance, or highlights.'}
                        </Typography>
                      </Box>
                    </Box>
                  );
                }

                if ((block.type === 'image' || block.type === 'hero') && blockAssetUrl) {
                  return (
                    <Box className="preview-block" key={`${index}:${block.type}`}>
                      {block.title ? (
                        <Typography className="preview-blockTitle">{block.title}</Typography>
                      ) : null}
                      <Box className="preview-blockMedia">
                        <img
                          alt={typeof blockAsset?.alt_text === 'string' ? blockAsset.alt_text : block.title || 'Preview media'}
                          src={blockAssetUrl}
                        />
                      </Box>
                      {block.content ? (
                        <Typography className="preview-blockCopy">{block.content}</Typography>
                      ) : null}
                    </Box>
                  );
                }

                return (
                  <Box className="preview-block" key={`${index}:${block.type}`}>
                    {block.title ? (
                      <Typography className="preview-blockTitle">{block.title}</Typography>
                    ) : null}
                    <Stack spacing={1.5}>
                      {bodyParagraphs(block.content).map((paragraph) => (
                        <Typography className="preview-blockCopy" key={paragraph}>
                          {paragraph}
                        </Typography>
                      ))}
                      {!block.content.trim() ? (
                        <Typography className="preview-blockCopy">
                          Write the main body here and the preview will render it as the reader sees it.
                        </Typography>
                      ) : null}
                    </Stack>
                  </Box>
                );
              })
            ) : (
              <Box className="empty-state">
                <Typography fontWeight={700}>No story blocks yet</Typography>
                <Typography variant="body2">
                  Add paragraph, quote, image, or callout blocks to see the page take shape.
                </Typography>
              </Box>
            )}
          </Box>

          <Box className="preview-footer">
            <Typography>
              SEO title: {toStringValue(seo.meta_title) || previewLabel}
            </Typography>
            <Typography>
              Canonical: {toStringValue(seo.canonical_url) || previewHref}
            </Typography>
            <Typography>
              Indexing: {toStringValue(seo.index_mode) || 'index'}
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}
