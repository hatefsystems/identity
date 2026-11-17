export type LocationInput = { country: 'IR'; province_id: string; locality_id?: string };
export type GeographySummary = { id: string; label: string; type_id: string; type_label: string };
export type GeographyPlace = {
  id: string;
  label: string;
  type: { id: string; label: string };
  province: GeographySummary;
  ancestors: GeographySummary[];
  retired: boolean;
  selectable: boolean;
  catalog_revision: string;
};
export type GeographyPage = {
  catalog_revision: string;
  items: GeographyPlace[];
  next_cursor: string;
};
export type GeographyFailure =
  'invalid_request' | 'not_found' | 'catalog_changed' | 'unavailable' | 'rate_limited';

export class GeographyError extends Error {
  constructor(
    public readonly code: GeographyFailure,
    public readonly retryAfter?: number
  ) {
    super(code);
    this.name = 'GeographyError';
  }
}

const maxBigint = '9223372036854775807';
const maxResponseBytes = 2 * 1024 * 1024;
export const geographyPageSize = 20;
export const geographyRetainedLimit = 100;

export function isGeographyId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[1-9][0-9]{0,18}$/.test(value) &&
    (value.length < maxBigint.length || value <= maxBigint)
  );
}

function boundedText(
  value: unknown,
  codepoints: number,
  bytes: number,
  nonempty = false
): value is string {
  if (
    typeof value !== 'string' ||
    value.length > codepoints * 2 ||
    (nonempty && value.trim().length === 0)
  )
    return false;
  const characters = [...value];
  return (
    characters.length <= codepoints &&
    new TextEncoder().encode(value).length <= bytes &&
    characters.every((character) => {
      const point = character.codePointAt(0) as number;
      return point >= 32 && point !== 127 && (point < 0xd800 || point > 0xdfff);
    })
  );
}

export function isGeographyQuery(value: string): boolean {
  return boundedText(value, 80, 256);
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function summary(value: unknown): value is GeographySummary {
  return (
    record(value) &&
    isGeographyId(value.id) &&
    isGeographyId(value.type_id) &&
    boundedText(value.label, 256, 1024, true) &&
    boundedText(value.type_label, 256, 1024, true)
  );
}

function place(value: unknown): value is GeographyPlace {
  if (
    !record(value) ||
    !isGeographyId(value.id) ||
    !isGeographyId(value.catalog_revision) ||
    !boundedText(value.label, 256, 1024, true) ||
    !record(value.type) ||
    !isGeographyId(value.type.id) ||
    !boundedText(value.type.label, 256, 1024, true) ||
    !summary(value.province) ||
    value.province.type_id !== '2' ||
    !Array.isArray(value.ancestors) ||
    value.ancestors.length > 32 ||
    !value.ancestors.every(summary) ||
    typeof value.retired !== 'boolean' ||
    typeof value.selectable !== 'boolean' ||
    (value.retired && value.selectable)
  )
    return false;
  const ids = value.ancestors.map((ancestor) => ancestor.id);
  return (
    !ids.includes(value.id) &&
    new Set(ids).size === ids.length &&
    (value.type.id !== '2' || (value.province.id === value.id && ids.length === 0)) &&
    (value.type.id === '2' ||
      (ids[0] === value.province.id &&
        value.ancestors[0].type_id === '2' &&
        value.ancestors[0].label === value.province.label &&
        value.ancestors[0].type_label === value.province.type_label)) &&
    (!value.selectable || ['2', '5', '7'].includes(value.type.id))
  );
}

export class GeographyClient {
  constructor(private readonly fetcher: typeof fetch = (...args) => fetch(...args)) {}

  async list(
    kind: 'province' | 'locality',
    input: {
      query: string;
      provinceId?: string;
      cursor?: string;
      signal: AbortSignal;
    }
  ): Promise<GeographyPage> {
    if (
      !isGeographyQuery(input.query) ||
      (kind === 'locality' && !isGeographyId(input.provinceId)) ||
      (input.cursor !== undefined && !boundedText(input.cursor, 2048, 2048))
    )
      throw new GeographyError('invalid_request');
    const params = new URLSearchParams({
      country: 'IR',
      q: input.query,
      limit: String(geographyPageSize),
    });
    if (kind === 'locality') params.set('province_id', input.provinceId as string);
    if (input.cursor) params.set('cursor', input.cursor);
    const data = await this.get(
      `/api/v1/geography/${kind === 'province' ? 'provinces' : 'localities'}?${params}`,
      input.signal
    );
    if (
      !record(data) ||
      !isGeographyId(data.catalog_revision) ||
      !Array.isArray(data.items) ||
      data.items.length > geographyPageSize ||
      !boundedText(data.next_cursor, 2048, 2048) ||
      !data.items.every(
        (item) =>
          place(item) &&
          item.catalog_revision === data.catalog_revision &&
          !item.retired &&
          item.selectable &&
          (kind === 'province'
            ? item.type.id === '2'
            : ['5', '7'].includes(item.type.id) && item.province.id === input.provinceId)
      ) ||
      new Set(data.items.map((item) => item.id)).size !== data.items.length
    )
      throw new GeographyError('unavailable');
    return data as GeographyPage;
  }

  async lookup(id: string, signal: AbortSignal, revision?: string): Promise<GeographyPlace> {
    if (!isGeographyId(id) || (revision !== undefined && !isGeographyId(revision)))
      throw new GeographyError('invalid_request');
    const params = new URLSearchParams({ country: 'IR' });
    if (revision) params.set('revision', revision);
    const data = await this.get(`/api/v1/geography/places/${id}?${params}`, signal);
    if (!place(data) || data.id !== id || (revision && data.catalog_revision !== revision))
      throw new GeographyError('unavailable');
    return data;
  }

  private async get(path: string, signal: AbortSignal): Promise<unknown> {
    try {
      const response = await this.fetcher(path, {
        method: 'GET',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        headers: { Accept: 'application/json' },
        signal,
      });
      if (!response.ok) {
        // Status is authority; response error prose never enters presentation.
        const code: GeographyFailure =
          response.status === 409
            ? 'catalog_changed'
            : response.status === 429
              ? 'rate_limited'
              : response.status === 404
                ? 'not_found'
                : response.status === 400
                  ? 'invalid_request'
                  : 'unavailable';
        const retry = response.headers.get('Retry-After');
        const retryAfter =
          retry && /^[0-9]{1,5}$/.test(retry) ? Math.min(Number(retry), 3600) : undefined;
        await response.body?.cancel();
        throw new GeographyError(code, retryAfter);
      }
      if (
        !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') ||
        Number(response.headers.get('Content-Length') ?? '0') > maxResponseBytes ||
        !response.body
      ) {
        await response.body?.cancel();
        throw new GeographyError('unavailable');
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8', { fatal: true });
      let text = '';
      let bytes = 0;
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength;
          if (bytes > maxResponseBytes || signal.aborted) throw new GeographyError('unavailable');
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      } finally {
        await reader.cancel();
        reader.releaseLock();
      }
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
      return JSON.parse(text);
    } catch (error) {
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
      if (error instanceof GeographyError) throw error;
      throw new GeographyError('unavailable');
    }
  }
}
