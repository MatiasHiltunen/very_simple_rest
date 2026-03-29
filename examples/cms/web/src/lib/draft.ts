import {
  createResource,
  deleteResource,
  listResource,
  type AuthMeResponse,
  type JsonValue,
} from './api';
import {
  defaultDraftValue,
  type FieldConfig,
  type RelationConfig,
  type ResourceConfig,
  type ResourceRow,
} from './cms';

export type DraftState = Record<string, string>;
export type Notice =
  | { severity: 'success' | 'error' | 'warning' | 'info'; message: string }
  | null;
export type FieldErrors = Record<string, string>;

export interface RelationOption {
  id: string;
  label: string;
  description?: string;
  previewUrl?: string;
}

export interface BlockDraft {
  type: string;
  title: string;
  content: string;
  tone: string;
  assetId: string;
}

const blockTypes = ['paragraph', 'hero', 'quote', 'callout', 'image'] as const;
const blockTones = ['neutral', 'info', 'success', 'warning'] as const;

export function initials(value: string | undefined): string {
  if (!value) {
    return 'CM';
  }
  return value
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? '')
    .join('');
}

export function formatDateTimeInput(value: unknown): string {
  if (typeof value !== 'string' || !value) {
    return '';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '';
  }

  const pad = (part: number) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function formatFriendlyDate(value: unknown): string {
  if (typeof value !== 'string' || !value) {
    return 'Unscheduled';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(date);
}

export function stringifyJsonValue(value: unknown): string {
  if (value === null || value === undefined || value === '') {
    return '';
  }

  return JSON.stringify(value, null, 2);
}

function parseObjectArray(value: string): Record<string, unknown>[] | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      return null;
    }
    if (parsed.some((item) => typeof item !== 'object' || item === null || Array.isArray(item))) {
      return null;
    }
    return parsed as Record<string, unknown>[];
  } catch {
    return null;
  }
}

export function defaultBlockDraft(): BlockDraft {
  return {
    type: 'paragraph',
    title: '',
    content: '',
    tone: 'neutral',
    assetId: '',
  };
}

export function parseBlockDrafts(value: string): BlockDraft[] | null {
  const parsed = parseObjectArray(value);
  if (parsed === null) {
    return null;
  }

  return parsed.map((item) => ({
    type:
      typeof item.type === 'string' && blockTypes.includes(item.type as (typeof blockTypes)[number])
        ? item.type
        : 'paragraph',
    title: typeof item.title === 'string' ? item.title : '',
    content: typeof item.content === 'string' ? item.content : '',
    tone:
      typeof item.tone === 'string' && blockTones.includes(item.tone as (typeof blockTones)[number])
        ? item.tone
        : 'neutral',
    assetId:
      typeof item.asset_id === 'number'
        ? String(item.asset_id)
        : typeof item.asset_id === 'string'
          ? item.asset_id
          : '',
  }));
}

export function serializeBlocks(blocks: BlockDraft[]): string {
  return JSON.stringify(
    blocks.map((block) => {
      const payload: Record<string, JsonValue> = {
        type: block.type,
      };

      if (block.title.trim()) {
        payload.title = block.title.trim();
      }
      if (block.content.trim()) {
        payload.content = block.content.trim();
      }
      if (block.type === 'callout' && block.tone.trim()) {
        payload.tone = block.tone.trim();
      }
      if ((block.type === 'hero' || block.type === 'image') && block.assetId.trim()) {
        const parsed = Number(block.assetId.trim());
        if (!Number.isNaN(parsed)) {
          payload.asset_id = parsed;
        }
      }

      return payload;
    }),
    null,
    2,
  );
}

export function parseObjectValue(value: string): Record<string, unknown> | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return {};
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function parseSelectionIds(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

export function serializeSelectionIds(ids: string[]): string {
  return parseSelectionIds(ids.join(',')).join(',');
}

export function toBooleanFlag(value: unknown): boolean {
  return value === true;
}

export function toStringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

export function guessAssetKindFromMime(mimeType: string): string {
  if (mimeType.startsWith('image/')) {
    return 'image';
  }
  if (mimeType.startsWith('video/')) {
    return 'video';
  }
  if (mimeType.startsWith('audio/')) {
    return 'audio';
  }
  return 'document';
}

export async function readLocalImageDimensions(
  file: File,
): Promise<{ width?: number; height?: number }> {
  if (!file.type.startsWith('image/')) {
    return {};
  }

  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      const result = { width: image.naturalWidth, height: image.naturalHeight };
      URL.revokeObjectURL(url);
      resolve(result);
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      resolve({});
    };
    image.src = url;
  });
}

export function mergeAssetMetadataDraft(
  currentValue: string,
  additions: Record<string, string | number | boolean | null>,
): string {
  const trimmed = currentValue.trim();
  if (!trimmed) {
    return JSON.stringify(additions, null, 2);
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return JSON.stringify({ ...parsed, ...additions }, null, 2);
    }
  } catch {
    return currentValue;
  }

  return currentValue;
}

export function deriveWorkspaceSeed(account: AuthMeResponse): {
  name: string;
  slug: string;
  defaultLocale: string;
} {
  const localPart = (account.email ?? 'editor')
    .split('@')[0]
    .trim()
    .replace(/[^A-Za-z0-9]+/g, ' ')
    .trim();
  const normalized = localPart || 'editorial team';
  const slug = normalized
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  const title = normalized
    .split(/\s+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');

  return {
    name: `${title} Workspace`,
    slug: `${slug || 'editorial'}-studio`,
    defaultLocale: 'en',
  };
}

export function localStorageObjectForAsset(
  row: ResourceRow,
): { bucket: string; objectKey: string; publicUrl?: string } | null {
  const metadata = row.metadata;
  if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
    const metadataRecord = metadata as Record<string, unknown>;
    const bucket =
      typeof metadataRecord.storage_bucket === 'string'
        ? metadataRecord.storage_bucket
        : typeof metadataRecord.bucket === 'string'
          ? metadataRecord.bucket
          : null;
    const objectKey =
      typeof metadataRecord.object_key === 'string' ? metadataRecord.object_key : null;

    if (bucket && objectKey) {
      return {
        bucket,
        objectKey,
        publicUrl:
          typeof row.delivery_url === 'string'
            ? row.delivery_url
            : typeof row.source_url === 'string'
              ? row.source_url
              : undefined,
      };
    }
  }

  const sourceUrl =
    typeof row.source_url === 'string'
      ? row.source_url
      : typeof row.delivery_url === 'string'
        ? row.delivery_url
        : null;

  if (!sourceUrl || !sourceUrl.startsWith('/uploads/assets/')) {
    return null;
  }

  return {
    bucket: 'media',
    objectKey: sourceUrl.slice('/uploads/assets/'.length),
    publicUrl: sourceUrl,
  };
}

export function assetPreviewUrl(row: ResourceRow): string | null {
  const deliveryUrl = typeof row.delivery_url === 'string' ? row.delivery_url : null;
  if (deliveryUrl) {
    return deliveryUrl;
  }
  return typeof row.source_url === 'string' ? row.source_url : null;
}

export function assetPreviewEligible(row: ResourceRow): boolean {
  const kind = typeof row.kind === 'string' ? row.kind : '';
  const mimeType = typeof row.mime_type === 'string' ? row.mime_type : '';
  return kind === 'image' || mimeType.startsWith('image/');
}

export function buildRelationOption(row: ResourceRow, relation: RelationConfig): RelationOption {
  const labelValue = row[relation.labelKey];
  const descriptionValue = relation.descriptionKey ? row[relation.descriptionKey] : undefined;
  const label =
    labelValue === null || labelValue === undefined || labelValue === ''
      ? `#${String(row.id ?? '')}`
      : String(labelValue);

  return {
    id: String(row.id ?? ''),
    label,
    description:
      descriptionValue === null || descriptionValue === undefined || descriptionValue === ''
        ? undefined
        : String(descriptionValue),
    previewUrl: assetPreviewUrl(row) ?? undefined,
  };
}

export function toDraft(config: ResourceConfig, item?: ResourceRow | null): DraftState {
  return Object.fromEntries(
    config.fields.map((field) => {
      const rawValue = item?.[field.key];
      let value = defaultDraftValue(field);

      if (
        field.kind === 'json' ||
        field.kind === 'jsonArray' ||
        field.kind === 'blocks' ||
        field.kind === 'seo' ||
        field.kind === 'entrySettings'
      ) {
        value = stringifyJsonValue(rawValue);
      } else if (field.kind === 'relationMulti' && Array.isArray(rawValue)) {
        value = serializeSelectionIds(
          rawValue
            .map((entry) => (entry === null || entry === undefined ? '' : String(entry)))
            .filter(Boolean),
        );
      } else if (field.kind === 'datetime') {
        value = formatDateTimeInput(rawValue);
      } else if (rawValue !== null && rawValue !== undefined) {
        value = String(rawValue);
      }

      return [field.key, value];
    }),
  );
}

export function serializeFieldValue(field: FieldConfig, rawValue: string): JsonValue {
  const trimmed = rawValue.trim();

  if (!trimmed) {
    if (field.required) {
      throw new Error(`${field.label} is required.`);
    }
    return null;
  }

  switch (field.kind) {
    case 'number': {
      const parsed = Number(trimmed);
      if (Number.isNaN(parsed)) {
        throw new Error(`${field.label} must be a valid number.`);
      }
      return parsed;
    }
    case 'relation': {
      const parsed = Number(trimmed);
      if (Number.isNaN(parsed)) {
        throw new Error(`${field.label} must reference a valid record.`);
      }
      return parsed;
    }
    case 'json':
    case 'seo':
    case 'entrySettings': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (Array.isArray(parsed) || typeof parsed !== 'object' || parsed === null) {
        throw new Error(`${field.label} must be a JSON object.`);
      }
      return parsed;
    }
    case 'jsonArray': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (!Array.isArray(parsed)) {
        throw new Error(`${field.label} must be a JSON array.`);
      }
      return parsed;
    }
    case 'relationMulti':
      return parseSelectionIds(trimmed);
    case 'blocks': {
      const parsed = JSON.parse(trimmed) as JsonValue;
      if (!Array.isArray(parsed)) {
        throw new Error(`${field.label} must be a JSON array of block objects.`);
      }
      if (parsed.some((item) => typeof item !== 'object' || item === null || Array.isArray(item))) {
        throw new Error(`${field.label} must contain block objects.`);
      }
      return parsed;
    }
    case 'datetime': {
      const parsed = new Date(trimmed);
      if (Number.isNaN(parsed.getTime())) {
        throw new Error(`${field.label} must be a valid date and time.`);
      }
      return parsed.toISOString();
    }
    default:
      return trimmed;
  }
}

export function serializeDraft(
  config: ResourceConfig,
  draft: DraftState,
): Record<string, JsonValue> {
  const body: Record<string, JsonValue> = {};
  for (const field of config.fields) {
    if (field.virtual) {
      continue;
    }
    body[field.key] = serializeFieldValue(field, draft[field.key] ?? '');
  }
  return body;
}

export async function syncRelationSelections(
  field: FieldConfig & { relationSync: NonNullable<FieldConfig['relationSync']> },
  ownerId: number,
  rawValue: string,
): Promise<void> {
  const desiredIds = parseSelectionIds(rawValue)
    .map((value) => Number(value))
    .filter((value) => !Number.isNaN(value));

  const current = await listResource<ResourceRow>(field.relationSync.joinPath, {
    limit: 200,
    context: field.relationSync.context ?? 'edit',
  });

  const existingRows = current.items.filter(
    (row) => Number(row[field.relationSync.sourceKey]) === ownerId,
  );
  const existingByTarget = new Map(
    existingRows.map((row) => [Number(row[field.relationSync.targetKey]), Number(row.id)]),
  );

  for (const desiredId of desiredIds) {
    if (existingByTarget.has(desiredId)) {
      continue;
    }

    await createResource(field.relationSync.joinPath, {
      [field.relationSync.sourceKey]: ownerId,
      [field.relationSync.targetKey]: desiredId,
    });
  }

  for (const row of existingRows) {
    const targetId = Number(row[field.relationSync.targetKey]);
    if (desiredIds.includes(targetId)) {
      continue;
    }

    await deleteResource(field.relationSync.joinPath, Number(row.id));
  }
}
