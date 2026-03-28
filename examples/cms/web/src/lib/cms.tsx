import type { ReactNode } from 'react';
import type { SvgIconComponent } from '@mui/icons-material';
import {
  AccountCircleRounded,
  ArticleRounded,
  DashboardRounded,
  DrawRounded,
  ImageRounded,
  LabelRounded,
  LayersRounded,
  LinkRounded,
  SettingsRounded,
  SpaceDashboardRounded,
} from '@mui/icons-material';
import { Chip, Link, Stack, Typography } from '@mui/material';

export type FieldKind =
  | 'text'
  | 'textarea'
  | 'number'
  | 'select'
  | 'json'
  | 'jsonArray'
  | 'datetime'
  | 'relation'
  | 'relationMulti'
  | 'blocks'
  | 'seo'
  | 'entrySettings';

export interface RelationConfig {
  path: string;
  labelKey: string;
  descriptionKey?: string;
  context?: string;
  limit?: number;
}

export interface RelationSyncConfig {
  joinPath: string;
  sourceKey: string;
  targetKey: string;
  context?: string;
}

export interface FieldConfig {
  key: string;
  label: string;
  kind: FieldKind;
  required?: boolean;
  nullable?: boolean;
  options?: string[];
  defaultValue?: string;
  helperText?: string;
  minRows?: number;
  relation?: RelationConfig;
  relationSync?: RelationSyncConfig;
  virtual?: boolean;
}

export interface ColumnConfig {
  key: string;
  label: string;
  render?: (value: unknown, row: Record<string, unknown>) => ReactNode;
}

export interface ResourceActionConfig {
  key: string;
  label: string;
  tone?: 'primary' | 'secondary' | 'success' | 'warning';
}

export interface ResourceConfig {
  key: string;
  path: string;
  label: string;
  shortLabel: string;
  description: string;
  icon: SvgIconComponent;
  context?: string;
  listLimit?: number;
  searchKeys: string[];
  columns: ColumnConfig[];
  fields: FieldConfig[];
  actions?: ResourceActionConfig[];
}

export interface NavigationItem {
  label: string;
  to: string;
  icon: SvgIconComponent;
}

export interface NavigationSection {
  label: string;
  items: NavigationItem[];
}

export const ENTRY_TYPES = ['article', 'page', 'release_note', 'landing_page'] as const;
export const ENTRY_STATUSES = ['draft', 'in_review', 'scheduled', 'published', 'archived'] as const;
export const VISIBILITY_VALUES = ['public', 'workspace', 'private'] as const;
export const MEDIA_KINDS = ['image', 'video', 'document', 'audio'] as const;
export const MENU_ITEM_KINDS = ['entry', 'url'] as const;
export const LINK_TARGETS = ['self', 'blank'] as const;

function toneForValue(value: unknown): 'default' | 'success' | 'warning' | 'secondary' {
  switch (value) {
    case 'published':
      return 'success';
    case 'scheduled':
    case 'in_review':
      return 'warning';
    case 'archived':
      return 'secondary';
    default:
      return 'default';
  }
}

function renderEnumChip(value: unknown): ReactNode {
  if (value === null || value === undefined || value === '') {
    return <Typography color="text.secondary">-</Typography>;
  }

  return (
    <Chip
      color={toneForValue(value)}
      label={String(value).replaceAll('_', ' ')}
      size="small"
      sx={{ textTransform: 'capitalize' }}
      variant="outlined"
    />
  );
}

function renderId(value: unknown): ReactNode {
  if (value === null || value === undefined || value === '') {
    return <Typography color="text.secondary">-</Typography>;
  }
  return <Typography fontWeight={600}>#{String(value)}</Typography>;
}

function renderDate(value: unknown): ReactNode {
  if (typeof value !== 'string' || !value) {
    return <Typography color="text.secondary">-</Typography>;
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return <Typography>{value}</Typography>;
  }

  return (
    <Stack spacing={0.25}>
      <Typography fontWeight={600}>{date.toLocaleDateString()}</Typography>
      <Typography color="text.secondary" variant="body2">
        {date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </Typography>
    </Stack>
  );
}

function renderLink(value: unknown): ReactNode {
  if (typeof value !== 'string' || !value) {
    return <Typography color="text.secondary">-</Typography>;
  }

  return (
    <Link href={value} target="_blank" rel="noreferrer" underline="hover">
      {value}
    </Link>
  );
}

function renderJsonSummary(value: unknown): ReactNode {
  if (!value) {
    return <Typography color="text.secondary">-</Typography>;
  }

  if (Array.isArray(value)) {
    return <Typography>{value.length} items</Typography>;
  }

  if (typeof value === 'object') {
    return <Typography>{Object.keys(value as Record<string, unknown>).length} fields</Typography>;
  }

  return <Typography>{String(value)}</Typography>;
}

export const cmsResources: ResourceConfig[] = [
  {
    key: 'entries',
    path: 'entries',
    label: 'Entries',
    shortLabel: 'Entry',
    description: 'Author, review, and publish structured content with blocks and SEO metadata.',
    icon: ArticleRounded,
    context: 'edit',
    listLimit: 50,
    searchKeys: ['title', 'slug', 'summary'],
    columns: [
      { key: 'title', label: 'Title' },
      { key: 'type', label: 'Type', render: renderEnumChip },
      { key: 'status', label: 'Status', render: renderEnumChip },
      { key: 'visibility', label: 'Visibility', render: renderEnumChip },
      { key: 'author', label: 'Author', render: renderId },
      { key: 'published_at', label: 'Published', render: renderDate },
    ],
    fields: [
      { key: 'type', label: 'Entry type', kind: 'select', options: [...ENTRY_TYPES], defaultValue: 'article', required: true },
      { key: 'status', label: 'Status', kind: 'select', options: [...ENTRY_STATUSES], defaultValue: 'draft', required: true },
      { key: 'visibility', label: 'Visibility', kind: 'select', options: [...VISIBILITY_VALUES], defaultValue: 'workspace', required: true },
      { key: 'slug', label: 'Slug', kind: 'text', required: true },
      { key: 'title', label: 'Title', kind: 'text', required: true },
      { key: 'summary', label: 'Summary', kind: 'textarea', nullable: true, minRows: 3 },
      {
        key: 'hero_asset',
        label: 'Hero asset',
        kind: 'relation',
        nullable: true,
        helperText: 'Choose a library asset to headline the entry.',
        relation: {
          path: 'assets',
          labelKey: 'file_name',
          descriptionKey: 'kind',
          context: 'edit',
        },
      },
      {
        key: 'reviewer',
        label: 'Reviewer',
        kind: 'relation',
        nullable: true,
        helperText: 'Optional built-in auth user who should review the draft.',
        relation: {
          path: 'auth/admin/users',
          labelKey: 'email',
          descriptionKey: 'role',
          limit: 50,
        },
      },
      { key: 'published_at', label: 'Published at', kind: 'datetime', nullable: true },
      { key: 'scheduled_for', label: 'Scheduled for', kind: 'datetime', nullable: true },
      {
        key: 'topics',
        label: 'Topics',
        kind: 'relationMulti',
        helperText: 'Attach reusable topics directly from the entry editor.',
        relation: {
          path: 'topics',
          labelKey: 'name',
          descriptionKey: 'slug',
          context: 'edit',
        },
        relationSync: {
          joinPath: 'entry-topics',
          sourceKey: 'entry',
          targetKey: 'topic',
          context: 'edit',
        },
        virtual: true,
      },
      {
        key: 'body_blocks',
        label: 'Body blocks',
        kind: 'blocks',
        nullable: true,
        minRows: 10,
        helperText: 'Build the article body with ordered content blocks.',
      },
      {
        key: 'seo',
        label: 'SEO',
        kind: 'seo',
        nullable: true,
        minRows: 8,
        helperText: 'Editorial SEO controls with canonical URL and indexing mode.',
      },
      {
        key: 'settings',
        label: 'Entry settings',
        kind: 'entrySettings',
        nullable: true,
        minRows: 8,
        helperText: 'Rendering and promotion flags for the published experience.',
      },
    ],
    actions: [
      { key: 'submit_review', label: 'Submit', tone: 'secondary' },
      { key: 'publish', label: 'Publish', tone: 'success' },
      { key: 'archive', label: 'Archive', tone: 'warning' },
    ],
  },
  {
    key: 'topics',
    path: 'topics',
    label: 'Topics',
    shortLabel: 'Topic',
    description: 'Manage reusable editorial taxonomies shared across entries.',
    icon: LabelRounded,
    context: 'edit',
    listLimit: 100,
    searchKeys: ['name', 'slug', 'description'],
    columns: [
      { key: 'name', label: 'Name' },
      { key: 'slug', label: 'Slug' },
      { key: 'color', label: 'Color' },
      { key: 'topic_url', label: 'URL', render: renderLink },
    ],
    fields: [
      { key: 'name', label: 'Name', kind: 'text', required: true },
      { key: 'slug', label: 'Slug', kind: 'text', required: true },
      { key: 'description', label: 'Description', kind: 'textarea', nullable: true, minRows: 3 },
      { key: 'color', label: 'Color token', kind: 'text', nullable: true },
      { key: 'meta', label: 'Topic metadata', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'assets',
    path: 'assets',
    label: 'Assets',
    shortLabel: 'Asset',
    description: 'Track media inventory, metadata, and delivery URLs for the studio.',
    icon: ImageRounded,
    context: 'edit',
    listLimit: 100,
    searchKeys: ['file_name', 'mime_type', 'alt_text'],
    columns: [
      { key: 'file_name', label: 'File name' },
      { key: 'kind', label: 'Kind', render: renderEnumChip },
      { key: 'byte_size', label: 'Bytes' },
      { key: 'uploader', label: 'Uploader', render: renderId },
      { key: 'delivery_url', label: 'Delivery URL', render: renderLink },
    ],
    fields: [
      { key: 'kind', label: 'Kind', kind: 'select', options: [...MEDIA_KINDS], defaultValue: 'image', required: true },
      { key: 'file_name', label: 'File name', kind: 'text', required: true },
      { key: 'mime_type', label: 'MIME type', kind: 'text', required: true, defaultValue: 'image/jpeg' },
      { key: 'byte_size', label: 'Byte size', kind: 'number', required: true, defaultValue: '0' },
      { key: 'width', label: 'Width', kind: 'number', nullable: true },
      { key: 'height', label: 'Height', kind: 'number', nullable: true },
      { key: 'alt_text', label: 'Alt text', kind: 'textarea', nullable: true, minRows: 3 },
      { key: 'source_url', label: 'Source URL', kind: 'text', nullable: true },
      { key: 'focal_point', label: 'Focal point', kind: 'json', nullable: true, minRows: 6 },
      { key: 'metadata', label: 'Metadata', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'menus',
    path: 'menus',
    label: 'Menus',
    shortLabel: 'Menu',
    description: 'Define navigational containers for site sections and campaigns.',
    icon: DrawRounded,
    context: 'edit',
    listLimit: 50,
    searchKeys: ['name', 'handle', 'description'],
    columns: [
      { key: 'name', label: 'Name' },
      { key: 'handle', label: 'Handle' },
      { key: 'description', label: 'Description' },
    ],
    fields: [
      { key: 'name', label: 'Name', kind: 'text', required: true },
      { key: 'handle', label: 'Handle', kind: 'text', required: true },
      { key: 'description', label: 'Description', kind: 'textarea', nullable: true, minRows: 3 },
      { key: 'settings', label: 'Menu settings', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'menu-items',
    path: 'menu-items',
    label: 'Menu Items',
    shortLabel: 'Menu item',
    description: 'Compose menu hierarchies with entry links or external destinations.',
    icon: LinkRounded,
    context: 'edit',
    listLimit: 100,
    searchKeys: ['label', 'external_url'],
    columns: [
      { key: 'label', label: 'Label' },
      { key: 'menu', label: 'Menu', render: renderId },
      { key: 'item_kind', label: 'Kind', render: renderEnumChip },
      { key: 'entry', label: 'Entry', render: renderId },
      { key: 'sort_order', label: 'Order' },
    ],
    fields: [
      {
        key: 'menu',
        label: 'Menu',
        kind: 'relation',
        required: true,
        relation: {
          path: 'menus',
          labelKey: 'name',
          descriptionKey: 'handle',
          context: 'edit',
        },
      },
      {
        key: 'parent_item',
        label: 'Parent item',
        kind: 'relation',
        nullable: true,
        relation: {
          path: 'menu-items',
          labelKey: 'label',
          descriptionKey: 'item_kind',
          context: 'edit',
        },
      },
      { key: 'label', label: 'Label', kind: 'text', required: true },
      { key: 'item_kind', label: 'Kind', kind: 'select', options: [...MENU_ITEM_KINDS], defaultValue: 'entry', required: true },
      {
        key: 'entry',
        label: 'Entry',
        kind: 'relation',
        nullable: true,
        relation: {
          path: 'entries',
          labelKey: 'title',
          descriptionKey: 'status',
          context: 'edit',
        },
      },
      { key: 'external_url', label: 'External URL', kind: 'text', nullable: true },
      { key: 'target', label: 'Target', kind: 'select', options: [...LINK_TARGETS], defaultValue: 'self', required: true },
      { key: 'sort_order', label: 'Sort order', kind: 'number', required: true, defaultValue: '0' },
      { key: 'meta', label: 'Item metadata', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'profiles',
    path: 'profiles',
    label: 'Profiles',
    shortLabel: 'Profile',
    description: 'Keep author bios, handles, and publishing preferences in sync with auth users.',
    icon: AccountCircleRounded,
    context: 'self',
    listLimit: 50,
    searchKeys: ['display_name', 'handle', 'headline'],
    columns: [
      { key: 'display_name', label: 'Display name' },
      { key: 'handle', label: 'Handle' },
      { key: 'headline', label: 'Headline' },
      { key: 'avatar_asset', label: 'Avatar asset', render: renderId },
      { key: 'profile_url', label: 'Profile URL', render: renderLink },
    ],
    fields: [
      { key: 'handle', label: 'Handle', kind: 'text', required: true },
      { key: 'display_name', label: 'Display name', kind: 'text', required: true },
      { key: 'headline', label: 'Headline', kind: 'text', nullable: true },
      { key: 'bio', label: 'Bio', kind: 'textarea', nullable: true, minRows: 5 },
      {
        key: 'avatar_asset',
        label: 'Avatar asset',
        kind: 'relation',
        nullable: true,
        relation: {
          path: 'assets',
          labelKey: 'file_name',
          descriptionKey: 'kind',
          context: 'edit',
        },
      },
      { key: 'preferences', label: 'Preferences', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'workspaces',
    path: 'workspaces',
    label: 'Workspace',
    shortLabel: 'Workspace',
    description: 'Configure the workspace identity, locale, theme, and editorial settings.',
    icon: SpaceDashboardRounded,
    context: 'admin',
    listLimit: 10,
    searchKeys: ['name', 'slug', 'default_locale'],
    columns: [
      { key: 'name', label: 'Name' },
      { key: 'slug', label: 'Slug' },
      { key: 'default_locale', label: 'Locale' },
      { key: 'studio_url', label: 'Studio URL', render: renderLink },
    ],
    fields: [
      { key: 'name', label: 'Name', kind: 'text', required: true },
      { key: 'slug', label: 'Slug', kind: 'text', required: true },
      { key: 'default_locale', label: 'Default locale', kind: 'text', required: true, defaultValue: 'en' },
      { key: 'public_base_url', label: 'Public base URL', kind: 'text', nullable: true },
      { key: 'theme_settings', label: 'Theme settings', kind: 'json', nullable: true, minRows: 8 },
      { key: 'editorial_settings', label: 'Editorial settings', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'entry-topics',
    path: 'entry-topics',
    label: 'Entry Topics',
    shortLabel: 'Entry topic',
    description: 'Manage explicit entry-to-topic links when curating content collections.',
    icon: LayersRounded,
    context: 'edit',
    listLimit: 100,
    searchKeys: ['entry', 'topic'],
    columns: [
      { key: 'entry', label: 'Entry', render: renderId },
      { key: 'topic', label: 'Topic', render: renderId },
      { key: 'workspace', label: 'Workspace', render: renderId },
    ],
    fields: [
      {
        key: 'entry',
        label: 'Entry',
        kind: 'relation',
        required: true,
        relation: {
          path: 'entries',
          labelKey: 'title',
          descriptionKey: 'status',
          context: 'edit',
        },
      },
      {
        key: 'topic',
        label: 'Topic',
        kind: 'relation',
        required: true,
        relation: {
          path: 'topics',
          labelKey: 'name',
          descriptionKey: 'slug',
          context: 'edit',
        },
      },
    ],
  },
];

export const cmsNavigation: NavigationSection[] = [
  {
    label: 'Overview',
    items: [{ label: 'Dashboard', to: '/', icon: DashboardRounded }],
  },
  {
    label: 'Publishing',
    items: [
      { label: 'Entries', to: '/entries', icon: ArticleRounded },
      { label: 'Topics', to: '/topics', icon: LabelRounded },
      { label: 'Assets', to: '/assets', icon: ImageRounded },
    ],
  },
  {
    label: 'Structure',
    items: [
      { label: 'Menus', to: '/menus', icon: DrawRounded },
      { label: 'Menu Items', to: '/menu-items', icon: LinkRounded },
      { label: 'Entry Topics', to: '/entry-topics', icon: LayersRounded },
    ],
  },
  {
    label: 'Workspace',
    items: [
      { label: 'Profiles', to: '/profiles', icon: AccountCircleRounded },
      { label: 'Workspace', to: '/workspaces', icon: SettingsRounded },
    ],
  },
];

export function lookupResource(pathname: string): ResourceConfig | undefined {
  const trimmed = pathname.replace(/^\//, '');
  return cmsResources.find((resource) => resource.key === trimmed);
}

export function defaultDraftValue(field: FieldConfig): string {
  if (field.defaultValue !== undefined) {
    return field.defaultValue;
  }
  return '';
}

export function renderFallbackCell(value: unknown): ReactNode {
  if (value === null || value === undefined || value === '') {
    return <Typography color="text.secondary">-</Typography>;
  }
  if (Array.isArray(value) || typeof value === 'object') {
    return renderJsonSummary(value);
  }
  return <Typography>{String(value)}</Typography>;
}
