'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { useTranslations } from 'next-intl';
import { Button, SearchableList } from '@hatef/ui';
import { NativeDialog } from './native-dialog';
import {
  GeographyClient,
  GeographyError,
  geographyRetainedLimit,
  isGeographyQuery,
  type GeographyPlace,
  type LocationInput,
} from '../_lib/geography-client';

type Field = 'province' | 'locality';
type SearchState = {
  items: GeographyPlace[];
  revision?: string;
  cursor: string;
  phase: 'loading' | 'ready' | 'unavailable' | 'rateLimited' | 'catalogChanged' | 'queryTooLong';
};
const emptySearch: SearchState = { items: [], cursor: '', phase: 'loading' };

export function LocationSelector({
  value,
  onChange,
  disabled = false,
  client: suppliedClient,
}: {
  value: LocationInput | null;
  onChange: (value: LocationInput | null) => void;
  disabled?: boolean;
  client?: GeographyClient;
}) {
  const t = useTranslations('location');
  const [defaultClient] = useState(() => new GeographyClient());
  const client = suppliedClient ?? defaultClient;
  const provinceId = value?.province_id;
  const localityId = value?.locality_id;
  const [details, setDetails] = useState<Partial<Record<Field, GeographyPlace>>>({});
  const [lookupFailed, setLookupFailed] = useState(false);
  const [lookupAttempt, setLookupAttempt] = useState(0);
  const lookupGeneration = useRef(0);
  const selectedIds = useRef({ provinceId, localityId });
  selectedIds.current = { provinceId, localityId };
  const [announcement, setAnnouncement] = useState<{
    key: 'selected' | 'localityCleared' | 'provinceCleared' | 'selectionCleared' | 'skipped';
    name?: string;
    id?: string;
  }>();

  useEffect(() => {
    const generation = ++lookupGeneration.current;
    const controller = new AbortController();
    setLookupFailed(false);
    for (const [field, id] of [
      ['province', provinceId],
      ['locality', localityId],
    ] as const) {
      if (!id) continue;
      client
        .lookup(id, controller.signal)
        .then((place) => {
          if (
            controller.signal.aborted ||
            generation !== lookupGeneration.current ||
            selectedIds.current.provinceId !== provinceId ||
            selectedIds.current.localityId !== localityId
          )
            return;
          setDetails((current) => ({ ...current, [field]: place }));
        })
        .catch(() => {
          if (
            !controller.signal.aborted &&
            generation === lookupGeneration.current &&
            selectedIds.current.provinceId === provinceId &&
            selectedIds.current.localityId === localityId
          )
            setLookupFailed(true);
        });
    }
    return () => {
      controller.abort();
      ++lookupGeneration.current;
    };
  }, [client, provinceId, localityId, lookupAttempt]);

  function select(field: Field, place: GeographyPlace) {
    if (disabled || place.retired || !place.selectable) return;
    if (field === 'province' && place.type.id !== '2') return;
    if (field === 'locality' && !['5', '7'].includes(place.type.id)) return;
    if (field === 'locality' && (!provinceId || place.province.id !== provinceId)) return;
    if (field === 'province') {
      const preserveLocality = provinceId === place.id;
      onChange({
        country: 'IR',
        province_id: place.id,
        ...(preserveLocality && localityId ? { locality_id: localityId } : {}),
      });
      setAnnouncement(
        localityId && !preserveLocality
          ? { key: 'localityCleared' }
          : { key: 'selected', name: place.label, id: place.id }
      );
    } else {
      onChange({ country: 'IR', province_id: provinceId as string, locality_id: place.id });
      setAnnouncement({ key: 'selected', name: place.label, id: place.id });
    }
  }

  function clear(field: Field, skip = false) {
    if (disabled) return;
    if (field === 'province') {
      onChange(null);
      setAnnouncement({ key: localityId ? 'localityCleared' : 'provinceCleared' });
    } else if (provinceId) {
      onChange({ country: 'IR', province_id: provinceId });
      setAnnouncement({ key: skip ? 'skipped' : 'selectionCleared' });
    }
  }

  return (
    <div data-testid="location-selector" className="min-w-0 space-y-6">
      {(['province', 'locality'] as const).map((field) => {
        const id = field === 'province' ? provinceId : localityId;
        const selected = details[field]?.id === id ? details[field] : undefined;
        return (
          <LocationPicker
            key={field}
            field={field}
            client={client}
            provinceId={provinceId}
            selectedId={id}
            selected={selected}
            disabled={disabled || (field === 'locality' && !provinceId)}
            onSelect={(place) => select(field, place)}
            onClear={() => clear(field)}
            onSkip={field === 'locality' ? () => clear(field, true) : undefined}
          />
        );
      })}
      {lookupFailed && (
        <div className="space-y-2" role="status">
          <p>{t('selectedLookupFailed')}</p>
          <Button
            type="button"
            variant="outline"
            className="h-auto min-h-11 max-w-full whitespace-normal"
            disabled={disabled}
            onClick={() => setLookupAttempt((attempt) => attempt + 1)}
          >
            {t('retryDetails')}
          </Button>
        </div>
      )}
      <p role="status" aria-live="polite" aria-atomic="true" className="break-words" dir="auto">
        {announcement &&
          (announcement.key === 'selected'
            ? (announcement.id === provinceId || announcement.id === localityId) &&
              t.rich('selected', {
                name: announcement.name ?? '',
                place: (chunks) => <bdi dir="auto">{chunks}</bdi>,
              })
            : t(announcement.key))}
      </p>
    </div>
  );
}

function PlaceDetails({ place }: { place: GeographyPlace }) {
  const t = useTranslations('location');
  return (
    <span className="block break-words">
      <bdi dir="auto" className="block font-medium">
        {place.label}
      </bdi>
      <span className="block text-sm leading-relaxed text-muted-foreground">
        <bdi dir="auto">{place.type.label}</bdi>
        {place.ancestors.length > 0 && (
          <span>
            {' '}
            ·{' '}
            {place.ancestors.map((ancestor, index) => (
              <span key={ancestor.id}>
                {index > 0 && ' / '}
                <bdi dir="auto">{ancestor.label}</bdi>
              </span>
            ))}
          </span>
        )}
      </span>
      <span className="block text-sm leading-relaxed text-muted-foreground">
        {t.rich('placeId', {
          id: place.id,
          value: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
        })}
      </span>
    </span>
  );
}

function LocationPicker({
  field,
  client,
  provinceId,
  selectedId,
  selected,
  disabled,
  onSelect,
  onClear,
  onSkip,
}: {
  field: Field;
  client: GeographyClient;
  provinceId?: string;
  selectedId?: string;
  selected?: GeographyPlace;
  disabled: boolean;
  onSelect: (place: GeographyPlace) => void;
  onClear: () => void;
  onSkip?: () => void;
}) {
  const t = useTranslations('location');
  const id = useId();
  const [open, setOpen] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [query, setQuery] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [search, setSearch] = useState<SearchState>(emptySearch);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const context = useRef({ provinceId, disabled });
  context.current = { provinceId, disabled };
  const relevantProvince = field === 'locality' ? provinceId : undefined;

  function invalidate() {
    ++generation.current;
    controller.current?.abort();
  }

  function changeOpen(next: boolean) {
    if (next && disabled) return;
    if (!next) {
      invalidate();
      setMobile(false);
      setQuery('');
      setSearch(emptySearch);
    }
    setOpen(next);
  }

  function changeQuery(next: string) {
    invalidate();
    setQuery(next.slice(0, 160));
    setSearch({ ...emptySearch, phase: isGeographyQuery(next) ? 'loading' : 'queryTooLong' });
  }

  useEffect(() => {
    ++generation.current;
    controller.current?.abort();
    setQuery('');
    setOpen(false);
    setMobile(false);
    setSearch(emptySearch);
  }, [relevantProvince, disabled]);

  useEffect(() => {
    if (!open || disabled || !isGeographyQuery(query)) return;
    const requestGeneration = ++generation.current;
    const abort = new AbortController();
    controller.current = abort;
    setSearch(emptySearch);
    const timer = setTimeout(() => {
      client
        .list(field, { query, provinceId: relevantProvince, signal: abort.signal })
        .then((page) => {
          if (
            abort.signal.aborted ||
            requestGeneration !== generation.current ||
            context.current.disabled ||
            (field === 'locality' && context.current.provinceId !== relevantProvince)
          )
            return;
          setSearch({
            items: page.items,
            revision: page.catalog_revision,
            cursor: page.next_cursor,
            phase: 'ready',
          });
        })
        .catch((error: unknown) => {
          if (
            !abort.signal.aborted &&
            requestGeneration === generation.current &&
            !context.current.disabled &&
            (field !== 'locality' || context.current.provinceId === relevantProvince)
          )
            setSearch({ ...emptySearch, phase: failurePhase(error) });
        });
    }, 250);
    return () => {
      clearTimeout(timer);
      abort.abort();
      ++generation.current;
    };
  }, [client, field, relevantProvince, open, disabled, query, attempt]);

  async function more() {
    if (!search.cursor || search.phase !== 'ready' || search.items.length >= geographyRetainedLimit)
      return;
    const requestGeneration = ++generation.current;
    const abort = new AbortController();
    controller.current?.abort();
    controller.current = abort;
    const previous = search;
    setSearch({ ...previous, phase: 'loading' });
    try {
      const page = await client.list(field, {
        query,
        provinceId: relevantProvince,
        cursor: previous.cursor,
        signal: abort.signal,
      });
      if (
        abort.signal.aborted ||
        requestGeneration !== generation.current ||
        context.current.disabled ||
        (field === 'locality' && context.current.provinceId !== relevantProvince)
      )
        return;
      if (page.catalog_revision !== previous.revision || page.next_cursor === previous.cursor)
        throw new GeographyError('catalog_changed');
      const items = [...previous.items];
      const ids = new Set(items.map((item) => item.id));
      for (const item of page.items)
        if (!ids.has(item.id)) {
          items.push(item);
          ids.add(item.id);
        }
      setSearch({
        items: items.slice(0, geographyRetainedLimit),
        revision: page.catalog_revision,
        cursor: page.next_cursor,
        phase: 'ready',
      });
    } catch (error) {
      if (
        !abort.signal.aborted &&
        requestGeneration === generation.current &&
        !context.current.disabled &&
        (field !== 'locality' || context.current.provinceId === relevantProvince)
      )
        setSearch({ ...emptySearch, phase: failurePhase(error) });
    }
  }

  const hint =
    field === 'locality' && !provinceId
      ? t('provinceFirst')
      : t(field === 'province' ? 'provinceHint' : 'localityHint');
  const status =
    search.phase !== 'ready'
      ? t(search.phase)
      : search.items.length === 0
        ? t('empty')
        : search.items.length >= geographyRetainedLimit && search.cursor
          ? t('retainedLimit')
          : t('results', { count: search.items.length });
  const picker = (
    <SearchableList
      label={t(field)}
      query={query}
      onQueryChange={changeQuery}
      open={open}
      onOpenChange={changeOpen}
      disabled={disabled}
      busy={search.phase === 'loading'}
      selectedId={selectedId}
      placeholder={t('search')}
      closeOnBlur={!mobile}
      maxLength={160}
      descriptionId={mobile ? `${id}-status` : open ? `${id}-hint ${id}-status` : `${id}-hint`}
      options={search.items.map((place) => ({
        id: place.id,
        label: <PlaceDetails place={place} />,
      }))}
      onSelect={(key) => {
        const place = search.items.find((item) => item.id === key);
        if (place) onSelect(place);
      }}
    >
      <div className="mt-3 space-y-3">
        <p id={`${id}-status`} role="status" aria-live="polite" aria-atomic="true">
          {status}
        </p>
        {search.phase === 'ready' &&
          search.cursor &&
          search.items.length < geographyRetainedLimit && (
            <Button
              type="button"
              variant="outline"
              className="h-auto min-h-11 w-full whitespace-normal"
              onClick={() => void more()}
            >
              {t('more')}
            </Button>
          )}
        {['unavailable', 'rateLimited', 'catalogChanged'].includes(search.phase) && (
          <Button
            type="button"
            variant="outline"
            className="h-auto min-h-11 w-full whitespace-normal"
            onClick={() => {
              invalidate();
              setSearch(emptySearch);
              setAttempt((current) => current + 1);
            }}
          >
            {t('retry')}
          </Button>
        )}
      </div>
    </SearchableList>
  );

  return (
    <section data-location-field={field} className="min-w-0 space-y-3">
      <div className="hidden md:block">{!mobile && picker}</div>
      <div className="space-y-2 md:hidden">
        <p id={`${id}-label`} className="text-sm font-medium">
          {t(field)}
        </p>
        <Button
          type="button"
          variant="outline"
          className="h-auto min-h-11 w-full justify-start whitespace-normal text-start"
          aria-labelledby={`${id}-label`}
          aria-describedby={`${id}-hint`}
          aria-haspopup="dialog"
          data-focus-return={`location-${field}`}
          disabled={disabled}
          onClick={() => {
            setMobile(true);
            changeOpen(true);
          }}
        >
          {t(field === 'province' ? 'chooseProvince' : 'chooseLocality')}
        </Button>
      </div>
      <p id={`${id}-hint`} className="text-sm leading-relaxed text-muted-foreground">
        {hint}
      </p>
      <div data-location-selected={field} className="rounded-md border p-3">
        {selected ? (
          <PlaceDetails place={selected} />
        ) : selectedId ? (
          <p>
            {t.rich('selectedId', {
              id: selectedId,
              value: (chunks) => <bdi dir="ltr">{chunks}</bdi>,
            })}
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">
            {t(field === 'province' ? 'noProvince' : 'noLocality')}
          </p>
        )}
        {selected &&
          (selected.retired ||
            !selected.selectable ||
            (field === 'locality' && selected.province.id !== provinceId)) && (
            <p role="status" className="mt-2 text-sm">
              {t('selectedUnavailable')}
            </p>
          )}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          className="h-auto min-h-11 max-w-full whitespace-normal"
          disabled={disabled || !selectedId}
          onClick={() => {
            changeOpen(false);
            onClear();
          }}
        >
          {t(field === 'province' ? 'clearProvince' : 'clearLocality')}
        </Button>
        {onSkip && (
          <Button
            type="button"
            variant="outline"
            className="h-auto min-h-11 max-w-full whitespace-normal"
            disabled={disabled}
            onClick={() => {
              changeOpen(false);
              onSkip();
            }}
          >
            {t('skip')}
          </Button>
        )}
      </div>
      {mobile && open && !disabled && (
        <NativeDialog
          title={t(field)}
          description={hint}
          layout="review"
          testId={`location-${field}-dialog`}
          onCancel={() => {
            changeOpen(false);
            setMobile(false);
          }}
          footer={
            <div className="flex flex-wrap gap-2">
              {onSkip && (
                <Button
                  type="button"
                  variant="outline"
                  className="h-auto min-h-11 max-w-full whitespace-normal"
                  onClick={() => {
                    changeOpen(false);
                    onSkip();
                  }}
                >
                  {t('skip')}
                </Button>
              )}
              <Button
                type="button"
                variant="outline"
                className="h-auto min-h-11 max-w-full whitespace-normal"
                disabled={!selectedId}
                onClick={() => {
                  changeOpen(false);
                  onClear();
                }}
              >
                {t(field === 'province' ? 'clearProvince' : 'clearLocality')}
              </Button>
              <Button
                type="button"
                variant="outline"
                className="h-auto min-h-11 w-full whitespace-normal"
                onClick={() => {
                  changeOpen(false);
                  setMobile(false);
                }}
              >
                {t('close')}
              </Button>
            </div>
          }
        >
          {picker}
        </NativeDialog>
      )}
    </section>
  );
}

function failurePhase(error: unknown): SearchState['phase'] {
  return error instanceof GeographyError && error.code === 'catalog_changed'
    ? 'catalogChanged'
    : error instanceof GeographyError && error.code === 'rate_limited'
      ? 'rateLimited'
      : 'unavailable';
}
