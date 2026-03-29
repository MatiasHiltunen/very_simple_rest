import type { SvgIconComponent } from '@mui/icons-material';
import {
  AccountCircleRounded,
  AdminPanelSettingsRounded,
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

export type ResourceRow = Record<string, unknown>;

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

export interface ResourceActionConfig {
  key: string;
  label: string;
  tone?: 'primary' | 'secondary' | 'success' | 'warning';
}

export interface ResourceFieldSection {
  title: string;
  description: string;
  fields: string[];
}

export interface ResourceConfig {
  key: string;
  path: string;
  label: string;
  shortLabel: string;
  description: string;
  icon: SvgIconComponent;
  group: 'publishing' | 'structure' | 'workspace';
  context?: string;
  listLimit?: number;
  searchKeys: string[];
  fields: FieldConfig[];
  fieldSections: ResourceFieldSection[];
  actions?: ResourceActionConfig[];
  itemTitle: (row: ResourceRow) => string;
  itemSubtitle: (row: ResourceRow) => string;
  itemBadge?: (row: ResourceRow) => string | undefined;
  previewMode?: 'asset' | 'workspace' | 'generic';
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

function stringValue(value: unknown, fallback: string): string {
  if (typeof value === 'string' && value.trim()) {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return fallback;
}

export const cmsResources: ResourceConfig[] = [
  {
    key: 'entries',
    path: 'entries',
    label: 'Entries',
    shortLabel: 'Entry',
    description:
      'Compose structured editorial pages with hero media, reusable topics, workflow actions, SEO, and render settings.',
    icon: ArticleRounded,
    group: 'publishing',
    context: 'edit',
    listLimit: 50,
    searchKeys: ['title', 'slug', 'summary', 'preview_label'],
    itemTitle: (row) => stringValue(row.title, 'Untitled entry'),
    itemSubtitle: (row) =>
      stringValue(row.summary, stringValue(row.permalink, 'No summary or permalink yet.')),
    itemBadge: (row) => stringValue(row.status, 'draft'),
    fieldSections: [
      {
        title: 'Essentials',
        description: 'Core identity and routing for the page.',
        fields: ['type', 'status', 'visibility', 'slug', 'title', 'summary', 'hero_asset', 'topics'],
      },
      {
        title: 'Story',
        description: 'Narrative blocks that power the live page preview.',
        fields: ['body_blocks'],
      },
      {
        title: 'Publishing',
        description: 'Review and release controls for the current draft.',
        fields: ['reviewer', 'published_at', 'scheduled_for'],
      },
      {
        title: 'Discovery',
        description: 'Search metadata and presentation behavior for the rendered page.',
        fields: ['seo', 'settings'],
      },
    ],
    fields: [
      {
        key: 'type',
        label: 'Entry type',
        kind: 'select',
        options: [...ENTRY_TYPES],
        defaultValue: 'article',
        required: true,
      },
      {
        key: 'status',
        label: 'Status',
        kind: 'select',
        options: [...ENTRY_STATUSES],
        defaultValue: 'draft',
        required: true,
      },
      {
        key: 'visibility',
        label: 'Visibility',
        kind: 'select',
        options: [...VISIBILITY_VALUES],
        defaultValue: 'workspace',
        required: true,
      },
      { key: 'slug', label: 'Slug', kind: 'text', required: true },
      { key: 'title', label: 'Title', kind: 'text', required: true },
      { key: 'summary', label: 'Summary', kind: 'textarea', nullable: true, minRows: 3 },
      {
        key: 'hero_asset',
        label: 'Hero asset',
        kind: 'relation',
        nullable: true,
        helperText: 'Choose the media asset that should lead the page.',
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
        helperText: 'Order blocks to shape the live reading experience.',
      },
      {
        key: 'seo',
        label: 'SEO',
        kind: 'seo',
        nullable: true,
        minRows: 8,
        helperText: 'Canonical URL, title, description, and index mode.',
      },
      {
        key: 'settings',
        label: 'Entry settings',
        kind: 'entrySettings',
        nullable: true,
        minRows: 8,
        helperText: 'Rendering flags such as hero mode and homepage promotion.',
      },
    ],
    actions: [
      { key: 'submit_review', label: 'Submit for review', tone: 'secondary' },
      { key: 'publish', label: 'Publish', tone: 'success' },
      { key: 'archive', label: 'Archive', tone: 'warning' },
    ],
  },
  {
    key: 'topics',
    path: 'topics',
    label: 'Topics',
    shortLabel: 'Topic',
    description: 'Maintain editorial taxonomies shared across entries and campaigns.',
    icon: LabelRounded,
    group: 'publishing',
    context: 'edit',
    listLimit: 100,
    searchKeys: ['name', 'slug', 'description'],
    itemTitle: (row) => stringValue(row.name, 'Untitled topic'),
    itemSubtitle: (row) => stringValue(row.description, stringValue(row.slug, 'No description yet.')),
    itemBadge: (row) => stringValue(row.slug, 'topic'),
    fieldSections: [
      {
        title: 'Topic details',
        description: 'Label, routing, and visual identity for the taxonomy.',
        fields: ['name', 'slug', 'description', 'color', 'meta'],
      },
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
    description: 'Track media metadata, storage references, alt text, and delivery URLs.',
    icon: ImageRounded,
    group: 'publishing',
    context: 'edit',
    listLimit: 100,
    searchKeys: ['file_name', 'mime_type', 'alt_text', 'source_url'],
    itemTitle: (row) => stringValue(row.file_name, 'Unnamed asset'),
    itemSubtitle: (row) =>
      stringValue(row.alt_text, stringValue(row.delivery_url, stringValue(row.source_url, 'No delivery URL yet.'))),
    itemBadge: (row) => stringValue(row.kind, 'asset'),
    previewMode: 'asset',
    fieldSections: [
      {
        title: 'Asset details',
        description: 'Media metadata used by previews and delivery.',
        fields: [
          'kind',
          'file_name',
          'mime_type',
          'byte_size',
          'width',
          'height',
          'alt_text',
          'source_url',
          'focal_point',
          'metadata',
        ],
      },
    ],
    fields: [
      {
        key: 'kind',
        label: 'Kind',
        kind: 'select',
        options: [...MEDIA_KINDS],
        defaultValue: 'image',
        required: true,
      },
      { key: 'file_name', label: 'File name', kind: 'text', required: true },
      {
        key: 'mime_type',
        label: 'MIME type',
        kind: 'text',
        required: true,
        defaultValue: 'image/jpeg',
      },
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
    description: 'Define navigation containers for primary, utility, or campaign-specific menus.',
    icon: DrawRounded,
    group: 'structure',
    context: 'edit',
    listLimit: 50,
    searchKeys: ['name', 'handle', 'description'],
    itemTitle: (row) => stringValue(row.name, 'Untitled menu'),
    itemSubtitle: (row) => stringValue(row.description, stringValue(row.handle, 'No description yet.')),
    itemBadge: (row) => stringValue(row.handle, 'menu'),
    fieldSections: [
      {
        title: 'Menu details',
        description: 'Identity and settings for the navigation container.',
        fields: ['name', 'handle', 'description', 'settings'],
      },
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
    description: 'Compose hierarchical menu links to entries or external URLs.',
    icon: LinkRounded,
    group: 'structure',
    context: 'edit',
    listLimit: 100,
    searchKeys: ['label', 'external_url'],
    itemTitle: (row) => stringValue(row.label, 'Untitled menu item'),
    itemSubtitle: (row) =>
      stringValue(row.external_url, `Menu #${stringValue(row.menu, '?')} · order ${stringValue(row.sort_order, '0')}`),
    itemBadge: (row) => stringValue(row.item_kind, 'entry'),
    fieldSections: [
      {
        title: 'Link details',
        description: 'Where the menu item should point and how it should behave.',
        fields: ['menu', 'parent_item', 'label', 'item_kind', 'entry', 'external_url', 'target', 'sort_order', 'meta'],
      },
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
      {
        key: 'item_kind',
        label: 'Kind',
        kind: 'select',
        options: [...MENU_ITEM_KINDS],
        defaultValue: 'entry',
        required: true,
      },
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
      {
        key: 'target',
        label: 'Target',
        kind: 'select',
        options: [...LINK_TARGETS],
        defaultValue: 'self',
        required: true,
      },
      { key: 'sort_order', label: 'Sort order', kind: 'number', required: true, defaultValue: '0' },
      { key: 'meta', label: 'Item metadata', kind: 'json', nullable: true, minRows: 8 },
    ],
  },
  {
    key: 'profiles',
    path: 'profiles',
    label: 'Profiles',
    shortLabel: 'Profile',
    description: 'Manage public bios, handles, and publishing preferences for authors.',
    icon: AccountCircleRounded,
    group: 'workspace',
    context: 'self',
    listLimit: 50,
    searchKeys: ['display_name', 'handle', 'headline'],
    itemTitle: (row) => stringValue(row.display_name, 'Unnamed profile'),
    itemSubtitle: (row) => stringValue(row.headline, stringValue(row.handle, 'No headline yet.')),
    itemBadge: (row) => stringValue(row.handle, 'profile'),
    fieldSections: [
      {
        title: 'Profile details',
        description: 'Identity, biography, and member-specific preferences.',
        fields: ['handle', 'display_name', 'headline', 'bio', 'avatar_asset', 'preferences'],
      },
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
    description: 'Configure workspace identity, locale, theming, and editorial policy.',
    icon: SpaceDashboardRounded,
    group: 'workspace',
    context: 'admin',
    listLimit: 10,
    searchKeys: ['name', 'slug', 'default_locale'],
    itemTitle: (row) => stringValue(row.name, 'Untitled workspace'),
    itemSubtitle: (row) =>
      stringValue(row.public_base_url, stringValue(row.studio_url, stringValue(row.slug, 'No public base URL yet.'))),
    itemBadge: (row) => stringValue(row.default_locale, 'en'),
    previewMode: 'workspace',
    fieldSections: [
      {
        title: 'Workspace identity',
        description: 'Public routing, locale, and theme behavior for the workspace.',
        fields: ['name', 'slug', 'default_locale', 'public_base_url', 'theme_settings', 'editorial_settings'],
      },
    ],
    fields: [
      { key: 'name', label: 'Name', kind: 'text', required: true },
      { key: 'slug', label: 'Slug', kind: 'text', required: true },
      {
        key: 'default_locale',
        label: 'Default locale',
        kind: 'text',
        required: true,
        defaultValue: 'en',
      },
      { key: 'public_base_url', label: 'Public base URL', kind: 'text', nullable: true },
      { key: 'theme_settings', label: 'Theme settings', kind: 'json', nullable: true, minRows: 8 },
      {
        key: 'editorial_settings',
        label: 'Editorial settings',
        kind: 'json',
        nullable: true,
        minRows: 8,
      },
    ],
  },
  {
    key: 'entry-topics',
    path: 'entry-topics',
    label: 'Entry Topics',
    shortLabel: 'Entry topic',
    description: 'Manage explicit entry-to-topic links when curating content collections.',
    icon: LayersRounded,
    group: 'structure',
    context: 'edit',
    listLimit: 100,
    searchKeys: ['entry', 'topic'],
    itemTitle: (row) => `Entry #${stringValue(row.entry, '?')} → Topic #${stringValue(row.topic, '?')}`,
    itemSubtitle: (row) => `Workspace #${stringValue(row.workspace, '?')}`,
    itemBadge: () => 'relation',
    fieldSections: [
      {
        title: 'Relation details',
        description: 'Map one entry to one reusable topic.',
        fields: ['entry', 'topic'],
      },
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

export const entryResource = cmsResources.find((resource) => resource.key === 'entries')!;
export const collectionResources = cmsResources.filter((resource) => resource.key !== 'entries');

export const cmsNavigation: NavigationSection[] = [
  {
    label: 'Overview',
    items: [{ label: 'Command', to: '/', icon: DashboardRounded }],
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
      { label: 'Users', to: '/users', icon: AdminPanelSettingsRounded },
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
