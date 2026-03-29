import { useState } from 'react';
import {
  AddRounded,
  ArrowDownwardRounded,
  ArrowUpwardRounded,
  DeleteOutlineRounded,
} from '@mui/icons-material';
import {
  Alert,
  Autocomplete,
  Avatar,
  Box,
  Button,
  FormControlLabel,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import type { FieldConfig } from '../lib/cms';
import type { RelationOption } from '../lib/draft';
import {
  defaultBlockDraft,
  parseBlockDrafts,
  parseObjectValue,
  parseSelectionIds,
  serializeBlocks,
  serializeSelectionIds,
  toBooleanFlag,
  toStringValue,
} from '../lib/draft';

const blockTypes = ['paragraph', 'hero', 'quote', 'callout', 'image'] as const;
const blockTones = ['neutral', 'info', 'success', 'warning'] as const;

type JsonValueKind = 'text' | 'number' | 'boolean' | 'json' | 'null';

function RelationOptionLabel({ option }: { option: RelationOption }) {
  return (
    <Stack direction="row" spacing={1.5} alignItems="center">
      {option.previewUrl ? (
        <Avatar
          alt={option.label}
          src={option.previewUrl}
          sx={{ width: 36, height: 36, borderRadius: 2 }}
          variant="rounded"
        />
      ) : null}
      <Stack spacing={0.25}>
        <Typography fontWeight={700}>{option.label}</Typography>
        <Typography color="text.secondary" variant="body2">
          {option.description ? `${option.description} · #${option.id}` : `#${option.id}`}
        </Typography>
      </Stack>
    </Stack>
  );
}

export function FieldInput({
  currentItemId,
  error,
  field,
  onClearError,
  relationError,
  relationLoading,
  relationOptions = [],
  blockAssetOptions = [],
  value,
  onChange,
}: {
  currentItemId?: number;
  error?: string;
  field: FieldConfig;
  onClearError: () => void;
  relationError?: string;
  relationLoading?: boolean;
  relationOptions?: RelationOption[];
  blockAssetOptions?: RelationOption[];
  value: string;
  onChange: (value: string) => void;
}) {
  const handleChange = (nextValue: string) => {
    onClearError();
    onChange(nextValue);
  };

  if (field.kind === 'select') {
    return (
      <TextField
        error={Boolean(error)}
        helperText={error ?? field.helperText}
        label={field.label}
        onChange={(event) => handleChange(event.target.value)}
        required={field.required}
        select
        SelectProps={{ native: true }}
        value={value}
      >
        {!field.required ? <option value="">Unset</option> : null}
        {(field.options ?? []).map((option) => (
          <option key={option} value={option}>
            {option.replaceAll('_', ' ')}
          </option>
        ))}
      </TextField>
    );
  }

  if (field.kind === 'relation') {
    const availableOptions =
      field.key === 'parent_item' && currentItemId
        ? relationOptions.filter((option) => Number(option.id) !== currentItemId)
        : relationOptions;
    const selectedOption =
      availableOptions.find((option) => option.id === value) ??
      (value
        ? {
            id: value,
            label: `#${value}`,
            description: 'Current value',
          }
        : null);

    return (
      <Autocomplete
        autoHighlight
        clearOnEscape
        disableClearable={field.required}
        fullWidth
        getOptionLabel={(option) => option.label}
        isOptionEqualToValue={(option, selected) => option.id === selected.id}
        loading={relationLoading}
        onChange={(_, option) => handleChange(option?.id ?? '')}
        options={availableOptions}
        renderInput={(params) => (
          <TextField
            {...params}
            error={Boolean(error)}
            helperText={error ?? relationError ?? field.helperText}
            label={field.label}
            required={field.required}
          />
        )}
        renderOption={(props, option) => (
          <Box component="li" {...props}>
            <RelationOptionLabel option={option} />
          </Box>
        )}
        value={selectedOption}
      />
    );
  }

  if (field.kind === 'relationMulti') {
    const selectedIds = parseSelectionIds(value);
    const selectedOptions = selectedIds.map((id) => {
      return (
        relationOptions.find((option) => option.id === id) ?? {
          id,
          label: `#${id}`,
          description: 'Current value',
        }
      );
    });

    return (
      <Autocomplete
        autoHighlight
        clearOnEscape
        fullWidth
        getOptionLabel={(option) => option.label}
        isOptionEqualToValue={(option, selected) => option.id === selected.id}
        loading={relationLoading}
        multiple
        onChange={(_, options) =>
          handleChange(serializeSelectionIds(options.map((option) => option.id)))
        }
        options={relationOptions}
        renderInput={(params) => (
          <TextField
            {...params}
            error={Boolean(error)}
            helperText={error ?? relationError ?? field.helperText}
            label={field.label}
          />
        )}
        renderOption={(props, option) => (
          <Box component="li" {...props}>
            <RelationOptionLabel option={option} />
          </Box>
        )}
        value={selectedOptions}
      />
    );
  }

  if (field.kind === 'blocks') {
    return (
      <BlockEditorField
        assetOptions={blockAssetOptions}
        error={error}
        field={field}
        onChange={handleChange}
        value={value}
      />
    );
  }

  if (field.kind === 'seo') {
    return <SeoEditorField error={error} field={field} onChange={handleChange} value={value} />;
  }

  if (field.kind === 'entrySettings') {
    return (
      <EntrySettingsEditorField
        error={error}
        field={field}
        onChange={handleChange}
        value={value}
      />
    );
  }

  if (field.kind === 'json') {
    if (field.key === 'focal_point') {
      return (
        <FocalPointEditorField error={error} field={field} onChange={handleChange} value={value} />
      );
    }

    if (field.key === 'theme_settings') {
      return (
        <ThemeSettingsEditorField error={error} field={field} onChange={handleChange} value={value} />
      );
    }

    if (field.key === 'editorial_settings') {
      return (
        <EditorialSettingsEditorField
          error={error}
          field={field}
          onChange={handleChange}
          value={value}
        />
      );
    }

    return <JsonMapEditorField error={error} field={field} onChange={handleChange} value={value} />;
  }

  if (field.kind === 'jsonArray') {
    return <JsonArrayEditorField error={error} field={field} onChange={handleChange} value={value} />;
  }

  if (field.kind === 'textarea') {
    return (
      <TextField
        error={Boolean(error)}
        helperText={error ?? field.helperText}
        label={field.label}
        multiline
        minRows={field.minRows ?? 4}
        onChange={(event) => handleChange(event.target.value)}
        required={field.required}
        value={value}
      />
    );
  }

  return (
    <TextField
      error={Boolean(error)}
      helperText={error ?? field.helperText}
      InputLabelProps={field.kind === 'datetime' ? { shrink: true } : undefined}
      label={field.label}
      onChange={(event) => handleChange(event.target.value)}
      required={field.required}
      type={
        field.kind === 'number' ? 'number' : field.kind === 'datetime' ? 'datetime-local' : 'text'
      }
      value={value}
    />
  );
}

function rawJsonTextField({
  error,
  helperText,
  label,
  minRows,
  onChange,
  value,
}: {
  error?: string;
  helperText: string;
  label: string;
  minRows: number;
  onChange: (value: string) => void;
  value: string;
}) {
  return (
    <TextField
      error={Boolean(error)}
      helperText={helperText}
      label={label}
      minRows={minRows}
      multiline
      onChange={(event) => onChange(event.target.value)}
      sx={{ '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }}
      value={value}
    />
  );
}

function JsonEditorHeader({
  description,
  label,
  onToggleRaw,
  rawOpen,
}: {
  description: string;
  label: string;
  onToggleRaw: () => void;
  rawOpen: boolean;
}) {
  return (
    <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={1.5}>
      <Stack spacing={0.25}>
        <Typography variant="subtitle1">{label}</Typography>
        <Typography color="text.secondary" variant="body2">
          {description}
        </Typography>
      </Stack>
      <Button onClick={onToggleRaw} size="small" variant="text">
        {rawOpen ? 'Hide raw JSON' : 'Open raw JSON'}
      </Button>
    </Stack>
  );
}

function inferJsonValueKind(value: unknown): JsonValueKind {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'number') {
    return 'number';
  }
  if (typeof value === 'boolean') {
    return 'boolean';
  }
  if (typeof value === 'object') {
    return 'json';
  }
  return 'text';
}

function rawJsonValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function encodeJsonMap(value: Record<string, unknown>): string {
  return Object.keys(value).length > 0 ? JSON.stringify(value, null, 2) : '';
}

function encodeJsonArray(value: unknown[]): string {
  return value.length > 0 ? JSON.stringify(value, null, 2) : '';
}

function parseJsonValue(kind: JsonValueKind, value: string): unknown {
  switch (kind) {
    case 'number': {
      const parsed = Number(value);
      return Number.isNaN(parsed) ? 0 : parsed;
    }
    case 'boolean':
      return value === 'true';
    case 'json':
      try {
        return JSON.parse(value);
      } catch {
        return {};
      }
    case 'null':
      return null;
    default:
      return value;
  }
}

function kindResetValue(kind: JsonValueKind): string {
  switch (kind) {
    case 'boolean':
      return 'false';
    case 'number':
      return '0';
    case 'json':
      return '{}';
    default:
      return '';
  }
}

function JsonMapEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const parsed = parseObjectValue(value);

  if (parsed === null) {
    return rawJsonTextField({
      error: error ?? 'This field contains invalid JSON.',
      helperText:
        'This field could not be parsed as an object. Fix the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 6,
      onChange,
      value,
    });
  }

  const entries = Object.entries(parsed);
  const setObject = (nextObject: Record<string, unknown>) => onChange(encodeJsonMap(nextObject));
  const addProperty = () => {
    setObject({
      ...parsed,
      [`field_${entries.length + 1}`]: '',
    });
  };
  const updateEntry = (
    index: number,
    patch: {
      key?: string;
      kind?: JsonValueKind;
      value?: string;
    },
  ) => {
    const nextObject: Record<string, unknown> = {};

    entries.forEach(([entryKey, entryValue], entryIndex) => {
      const nextKey = entryIndex === index ? (patch.key ?? entryKey) : entryKey;
      const nextKind =
        entryIndex === index ? (patch.kind ?? inferJsonValueKind(entryValue)) : inferJsonValueKind(entryValue);
      const nextValue =
        entryIndex === index
          ? parseJsonValue(nextKind, patch.value ?? rawJsonValue(entryValue))
          : entryValue;
      nextObject[nextKey] = nextValue;
    });

    setObject(nextObject);
  };
  const removeEntry = (index: number) => {
    setObject(Object.fromEntries(entries.filter((_, entryIndex) => entryIndex !== index)));
  };

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={error ?? field.helperText ?? 'Add named properties without writing JSON by hand.'}
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />

      {entries.length > 0 ? (
        entries.map(([entryKey, entryValue], index) => {
          const kind = inferJsonValueKind(entryValue);

          return (
            <Box className="json-editorRow" key={`${entryKey}:${index}`}>
              <TextField
                label="Key"
                onChange={(event) => updateEntry(index, { key: event.target.value })}
                value={entryKey}
              />
              <TextField
                label="Type"
                onChange={(event) =>
                  updateEntry(index, {
                    kind: event.target.value as JsonValueKind,
                    value: kindResetValue(event.target.value as JsonValueKind),
                  })
                }
                select
                SelectProps={{ native: true }}
                value={kind}
              >
                <option value="text">Text</option>
                <option value="number">Number</option>
                <option value="boolean">True / false</option>
                <option value="json">Nested JSON</option>
                <option value="null">Null</option>
              </TextField>
              {kind === 'boolean' ? (
                <TextField
                  label="Value"
                  onChange={(event) => updateEntry(index, { value: event.target.value })}
                  select
                  SelectProps={{ native: true }}
                  value={String(entryValue === true)}
                >
                  <option value="false">false</option>
                  <option value="true">true</option>
                </TextField>
              ) : kind === 'null' ? (
                <TextField disabled label="Value" value="null" />
              ) : (
                <TextField
                  label="Value"
                  minRows={kind === 'json' ? 3 : 1}
                  multiline={kind === 'json'}
                  onChange={(event) => updateEntry(index, { value: event.target.value })}
                  sx={
                    kind === 'json'
                      ? { '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }
                      : undefined
                  }
                  type={kind === 'number' ? 'number' : 'text'}
                  value={rawJsonValue(entryValue)}
                />
              )}
              <Button color="error" onClick={() => removeEntry(index)} variant="text">
                Remove
              </Button>
            </Box>
          );
        })
      ) : (
        <Alert severity="info" variant="outlined">
          No properties yet. Add a property row or open raw JSON for nested data.
        </Alert>
      )}

      <Button onClick={addProperty} size="small" startIcon={<AddRounded />} variant="outlined">
        Add property
      </Button>

      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available for nested structures or precise recovery.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 6,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function JsonArrayEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  let parsed: unknown[] | null = null;

  if (!value.trim()) {
    parsed = [];
  } else {
    try {
      const next = JSON.parse(value) as unknown;
      parsed = Array.isArray(next) ? next : null;
    } catch {
      parsed = null;
    }
  }

  if (parsed === null) {
    return rawJsonTextField({
      error: error ?? 'This field contains invalid JSON.',
      helperText:
        'This field could not be parsed as an array. Fix the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 6,
      onChange,
      value,
    });
  }

  const setItems = (nextItems: unknown[]) => onChange(encodeJsonArray(nextItems));
  const addItem = () => setItems([...parsed, '']);
  const updateItem = (
    index: number,
    patch: {
      kind?: JsonValueKind;
      value?: string;
    },
  ) => {
    const nextItems = parsed.map((item, itemIndex) => {
      if (itemIndex !== index) {
        return item;
      }

      const nextKind = patch.kind ?? inferJsonValueKind(item);
      return parseJsonValue(nextKind, patch.value ?? rawJsonValue(item));
    });
    setItems(nextItems);
  };
  const removeItem = (index: number) => setItems(parsed.filter((_, itemIndex) => itemIndex !== index));

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={
          error ?? field.helperText ?? 'Edit each array item directly instead of writing brackets by hand.'
        }
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />

      {parsed.length > 0 ? (
        parsed.map((item, index) => {
          const kind = inferJsonValueKind(item);

          return (
            <Box className="json-editorRow" key={`item:${index}`}>
              <TextField disabled label="Item" value={`#${index + 1}`} />
              <TextField
                label="Type"
                onChange={(event) =>
                  updateItem(index, {
                    kind: event.target.value as JsonValueKind,
                    value: kindResetValue(event.target.value as JsonValueKind),
                  })
                }
                select
                SelectProps={{ native: true }}
                value={kind}
              >
                <option value="text">Text</option>
                <option value="number">Number</option>
                <option value="boolean">True / false</option>
                <option value="json">Nested JSON</option>
                <option value="null">Null</option>
              </TextField>
              {kind === 'boolean' ? (
                <TextField
                  label="Value"
                  onChange={(event) => updateItem(index, { value: event.target.value })}
                  select
                  SelectProps={{ native: true }}
                  value={String(item === true)}
                >
                  <option value="false">false</option>
                  <option value="true">true</option>
                </TextField>
              ) : kind === 'null' ? (
                <TextField disabled label="Value" value="null" />
              ) : (
                <TextField
                  label="Value"
                  minRows={kind === 'json' ? 3 : 1}
                  multiline={kind === 'json'}
                  onChange={(event) => updateItem(index, { value: event.target.value })}
                  sx={
                    kind === 'json'
                      ? { '& textarea': { fontFamily: 'ui-monospace, SFMono-Regular, monospace' } }
                      : undefined
                  }
                  type={kind === 'number' ? 'number' : 'text'}
                  value={rawJsonValue(item)}
                />
              )}
              <Button color="error" onClick={() => removeItem(index)} variant="text">
                Remove
              </Button>
            </Box>
          );
        })
      ) : (
        <Alert severity="info" variant="outlined">
          No items yet. Add an item row or open raw JSON for a custom array structure.
        </Alert>
      )}

      <Button onClick={addItem} size="small" startIcon={<AddRounded />} variant="outlined">
        Add item
      </Button>

      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available for nested array structures or precise recovery.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 6,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function SeoEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const seo = parseObjectValue(value);

  if (seo === null) {
    return rawJsonTextField({
      error: error ?? 'SEO data is not a valid JSON object.',
      helperText: 'SEO data is not a valid JSON object. Edit the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 6,
      onChange,
      value,
    });
  }

  const updateSeo = (patch: Record<string, unknown>) => {
    const next = { ...seo, ...patch };
    const compact = Object.fromEntries(
      Object.entries(next).filter(([, entryValue]) => {
        if (typeof entryValue === 'string') {
          return entryValue.trim().length > 0;
        }
        return entryValue !== null && entryValue !== undefined;
      }),
    );
    onChange(Object.keys(compact).length > 0 ? JSON.stringify(compact, null, 2) : '');
  };

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={error ?? field.helperText ?? 'Set the public metadata without switching to raw JSON.'}
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />
      <TextField
        error={Boolean(error)}
        helperText="Recommended: keep this under roughly 60 characters."
        label="Meta title"
        onChange={(event) => updateSeo({ meta_title: event.target.value })}
        value={toStringValue(seo.meta_title)}
      />
      <TextField
        helperText="Recommended: keep this under roughly 160 characters."
        label="Meta description"
        minRows={3}
        multiline
        onChange={(event) => updateSeo({ meta_description: event.target.value })}
        value={toStringValue(seo.meta_description)}
      />
      <TextField
        label="Canonical URL"
        onChange={(event) => updateSeo({ canonical_url: event.target.value })}
        value={toStringValue(seo.canonical_url)}
      />
      <TextField
        label="Indexing mode"
        onChange={(event) => updateSeo({ index_mode: event.target.value })}
        select
        SelectProps={{ native: true }}
        value={toStringValue(seo.index_mode) || 'index'}
      >
        <option value="index">index</option>
        <option value="noindex">noindex</option>
      </TextField>

      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available if you need extra SEO keys.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 6,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function EntrySettingsEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const settings = parseObjectValue(value);

  if (settings === null) {
    return rawJsonTextField({
      error: error ?? 'Settings data is not a valid JSON object.',
      helperText:
        'Settings data is not a valid JSON object. Edit the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 6,
      onChange,
      value,
    });
  }

  const updateSettings = (patch: Record<string, unknown>) => {
    const next = { ...settings, ...patch };
    const compact = Object.fromEntries(
      Object.entries(next).filter(([, entryValue]) => {
        if (typeof entryValue === 'string') {
          return entryValue.trim().length > 0;
        }
        return entryValue !== null && entryValue !== undefined;
      }),
    );
    onChange(Object.keys(compact).length > 0 ? JSON.stringify(compact, null, 2) : '');
  };

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={
          error ?? field.helperText ?? 'Adjust rendering flags without manually editing the JSON payload.'
        }
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} flexWrap="wrap">
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.featured)}
              onChange={(_, checked) => updateSettings({ featured: checked })}
            />
          }
          label="Featured"
        />
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.pin_to_home)}
              onChange={(_, checked) => updateSettings({ pin_to_home: checked })}
            />
          }
          label="Pin to home"
        />
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.show_table_of_contents)}
              onChange={(_, checked) => updateSettings({ show_table_of_contents: checked })}
            />
          }
          label="Show table of contents"
        />
      </Stack>
      <TextField
        label="Hero variant"
        onChange={(event) => updateSettings({ hero_variant: event.target.value })}
        select
        SelectProps={{ native: true }}
        value={toStringValue(settings.hero_variant) || 'standard'}
      >
        <option value="standard">standard</option>
        <option value="spotlight">spotlight</option>
        <option value="minimal">minimal</option>
      </TextField>
      <TextField
        label="Editorial note"
        minRows={3}
        multiline
        onChange={(event) => updateSettings({ note: event.target.value })}
        value={toStringValue(settings.note)}
      />

      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available if you need extra rendering keys.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 6,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function FocalPointEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const point = parseObjectValue(value);

  if (point === null) {
    return rawJsonTextField({
      error: error ?? 'This field contains invalid JSON.',
      helperText:
        'Focal point data should be a JSON object with coordinates. Fix the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 4,
      onChange,
      value,
    });
  }

  const x = typeof point.x === 'number' ? point.x : 0.5;
  const y = typeof point.y === 'number' ? point.y : 0.5;
  const updatePoint = (patch: Record<string, number>) =>
    onChange(
      encodeJsonMap({
        ...point,
        ...patch,
      }),
    );

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={
          error ??
          field.helperText ??
          'Keep the visual subject centered in previews without writing coordinates manually.'
        }
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />
      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
        }}
      >
        <TextField
          helperText="0 = left edge, 1 = right edge"
          inputProps={{ max: 1, min: 0, step: 0.01 }}
          label="Horizontal focus"
          onChange={(event) => updatePoint({ x: Number(event.target.value) })}
          type="number"
          value={x}
        />
        <TextField
          helperText="0 = top edge, 1 = bottom edge"
          inputProps={{ max: 1, min: 0, step: 0.01 }}
          label="Vertical focus"
          onChange={(event) => updatePoint({ y: Number(event.target.value) })}
          type="number"
          value={y}
        />
      </Box>
      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available if you store more focal-point data.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 4,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function ThemeSettingsEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const settings = parseObjectValue(value);

  if (settings === null) {
    return rawJsonTextField({
      error: error ?? 'This field contains invalid JSON.',
      helperText:
        'Theme settings should be a JSON object. Fix the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 6,
      onChange,
      value,
    });
  }

  const updateSettings = (patch: Record<string, unknown>) =>
    onChange(
      encodeJsonMap({
        ...settings,
        ...patch,
      }),
    );

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={
          error ??
          field.helperText ??
          'Shape the public theme with named controls before dropping to raw JSON.'
        }
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />
      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
        }}
      >
        <TextField
          label="Palette"
          onChange={(event) => updateSettings({ palette: event.target.value })}
          select
          SelectProps={{ native: true }}
          value={toStringValue(settings.palette) || 'linen'}
        >
          <option value="linen">linen</option>
          <option value="sand">sand</option>
          <option value="slate">slate</option>
          <option value="studio">studio</option>
        </TextField>
        <TextField
          label="Accent"
          onChange={(event) => updateSettings({ accent: event.target.value })}
          select
          SelectProps={{ native: true }}
          value={toStringValue(settings.accent) || 'teal'}
        >
          <option value="teal">teal</option>
          <option value="rust">rust</option>
          <option value="gold">gold</option>
          <option value="ink">ink</option>
        </TextField>
        <TextField
          label="Logo mode"
          onChange={(event) => updateSettings({ logo_mode: event.target.value })}
          select
          SelectProps={{ native: true }}
          value={toStringValue(settings.logo_mode) || 'wordmark'}
        >
          <option value="wordmark">wordmark</option>
          <option value="mark">mark</option>
          <option value="lockup">lockup</option>
        </TextField>
        <TextField
          label="Header layout"
          onChange={(event) => updateSettings({ header_layout: event.target.value })}
          select
          SelectProps={{ native: true }}
          value={toStringValue(settings.header_layout) || 'split'}
        >
          <option value="split">split</option>
          <option value="stacked">stacked</option>
          <option value="minimal">minimal</option>
        </TextField>
      </Box>
      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available for advanced theme controls.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 6,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function EditorialSettingsEditorField({
  error,
  field,
  onChange,
  value,
}: {
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const [rawOpen, setRawOpen] = useState(false);
  const settings = parseObjectValue(value);

  if (settings === null) {
    return rawJsonTextField({
      error: error ?? 'This field contains invalid JSON.',
      helperText:
        'Editorial settings should be a JSON object. Fix the raw JSON directly to recover it.',
      label: field.label,
      minRows: field.minRows ?? 6,
      onChange,
      value,
    });
  }

  const updateSettings = (patch: Record<string, unknown>) =>
    onChange(
      encodeJsonMap({
        ...settings,
        ...patch,
      }),
    );

  return (
    <Stack spacing={1.5}>
      <JsonEditorHeader
        description={
          error ??
          field.helperText ??
          'Make review and preview policy explicit without hand-editing the JSON.'
        }
        label={field.label}
        onToggleRaw={() => setRawOpen((current) => !current)}
        rawOpen={rawOpen}
      />
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5} flexWrap="wrap">
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.review_required)}
              onChange={(_, checked) => updateSettings({ review_required: checked })}
            />
          }
          label="Require review"
        />
        <FormControlLabel
          control={
            <Switch
              checked={toBooleanFlag(settings.comments_enabled)}
              onChange={(_, checked) => updateSettings({ comments_enabled: checked })}
            />
          }
          label="Comments enabled"
        />
      </Stack>
      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
        }}
      >
        <TextField
          label="Preview mode"
          onChange={(event) => updateSettings({ preview_mode: event.target.value })}
          select
          SelectProps={{ native: true }}
          value={toStringValue(settings.preview_mode) || 'live'}
        >
          <option value="live">live</option>
          <option value="draft_only">draft_only</option>
          <option value="published_only">published_only</option>
        </TextField>
        <TextField
          label="Release window"
          onChange={(event) => updateSettings({ release_window: event.target.value })}
          value={toStringValue(settings.release_window)}
        />
      </Box>
      {rawOpen
        ? rawJsonTextField({
            error,
            helperText: 'Raw JSON stays available for extra policy controls.',
            label: `${field.label} JSON`,
            minRows: field.minRows ?? 6,
            onChange,
            value,
          })
        : null}
    </Stack>
  );
}

function BlockEditorField({
  assetOptions,
  error,
  field,
  onChange,
  value,
}: {
  assetOptions: RelationOption[];
  error?: string;
  field: FieldConfig;
  onChange: (value: string) => void;
  value: string;
}) {
  const blocks = parseBlockDrafts(value);

  if (blocks === null) {
    return rawJsonTextField({
      error: error ?? 'Existing block data is not in the expected array format.',
      helperText:
        'Existing block data is not in the expected array format. Edit the raw JSON directly.',
      label: field.label,
      minRows: field.minRows ?? 8,
      onChange,
      value,
    });
  }

  const updateBlocks = (nextBlocks: typeof blocks) => {
    onChange(nextBlocks.length > 0 ? serializeBlocks(nextBlocks) : '');
  };

  const addBlock = () => updateBlocks([...blocks, defaultBlockDraft()]);
  const replaceBlock = (index: number, nextBlock: (typeof blocks)[number]) => {
    const nextBlocks = [...blocks];
    nextBlocks[index] = nextBlock;
    updateBlocks(nextBlocks);
  };
  const deleteBlock = (index: number) =>
    updateBlocks(blocks.filter((_, current) => current !== index));
  const moveBlock = (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= blocks.length) {
      return;
    }
    const nextBlocks = [...blocks];
    const [item] = nextBlocks.splice(index, 1);
    nextBlocks.splice(target, 0, item);
    updateBlocks(nextBlocks);
  };

  return (
    <Stack spacing={1.5}>
      <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={1.5}>
        <Stack spacing={0.25}>
          <Typography variant="subtitle1">{field.label}</Typography>
          <Typography color="text.secondary" variant="body2">
            {error ?? field.helperText ?? 'Compose the entry body as ordered content blocks.'}
          </Typography>
        </Stack>
        <Button onClick={addBlock} size="small" startIcon={<AddRounded />} variant="outlined">
          Add block
        </Button>
      </Stack>

      {blocks.length > 0 ? (
        blocks.map((block, index) => {
          const assetValue =
            assetOptions.find((option) => option.id === block.assetId) ??
            (block.assetId ? { id: block.assetId, label: `#${block.assetId}` } : null);

          return (
            <Box className="editor-block" key={`${index}:${block.type}`}>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={1.5}>
                <TextField
                  label="Block type"
                  onChange={(event) => replaceBlock(index, { ...block, type: event.target.value })}
                  required
                  select
                  SelectProps={{ native: true }}
                  sx={{ minWidth: { md: 220 } }}
                  value={block.type}
                >
                  {blockTypes.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </TextField>
                <TextField
                  fullWidth
                  label="Heading"
                  onChange={(event) => replaceBlock(index, { ...block, title: event.target.value })}
                  value={block.title}
                />
              </Stack>

              <TextField
                fullWidth
                label="Content"
                minRows={block.type === 'quote' ? 3 : 5}
                multiline
                onChange={(event) => replaceBlock(index, { ...block, content: event.target.value })}
                value={block.content}
              />

              {block.type === 'callout' ? (
                <TextField
                  label="Tone"
                  onChange={(event) => replaceBlock(index, { ...block, tone: event.target.value })}
                  select
                  SelectProps={{ native: true }}
                  value={block.tone}
                >
                  {blockTones.map((tone) => (
                    <option key={tone} value={tone}>
                      {tone}
                    </option>
                  ))}
                </TextField>
              ) : null}

              {block.type === 'hero' || block.type === 'image' ? (
                <Autocomplete
                  autoHighlight
                  clearOnEscape
                  fullWidth
                  getOptionLabel={(option) => option.label}
                  isOptionEqualToValue={(option, selected) => option.id === selected.id}
                  onChange={(_, option) =>
                    replaceBlock(index, { ...block, assetId: option?.id ?? '' })
                  }
                  options={assetOptions}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      helperText="Optional media asset linked to this block."
                      label="Linked asset"
                    />
                  )}
                  renderOption={(props, option) => (
                    <Box component="li" {...props}>
                      <RelationOptionLabel option={option} />
                    </Box>
                  )}
                  value={assetValue}
                />
              ) : null}

              <Stack direction="row" justifyContent="space-between" spacing={1}>
                <Stack direction="row" spacing={1}>
                  <Button
                    disabled={index === 0}
                    onClick={() => moveBlock(index, -1)}
                    size="small"
                    startIcon={<ArrowUpwardRounded />}
                    variant="text"
                  >
                    Up
                  </Button>
                  <Button
                    disabled={index === blocks.length - 1}
                    onClick={() => moveBlock(index, 1)}
                    size="small"
                    startIcon={<ArrowDownwardRounded />}
                    variant="text"
                  >
                    Down
                  </Button>
                </Stack>
                <Button
                  color="error"
                  onClick={() => deleteBlock(index)}
                  size="small"
                  startIcon={<DeleteOutlineRounded />}
                  variant="text"
                >
                  Remove
                </Button>
              </Stack>
            </Box>
          );
        })
      ) : (
        <Alert severity="info" variant="outlined">
          No content blocks yet. Add a block to start composing the page.
        </Alert>
      )}
    </Stack>
  );
}
