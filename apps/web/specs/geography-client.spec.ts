/** @jest-environment node */
import {
  GeographyClient,
  GeographyError,
  isGeographyId,
  isGeographyQuery,
  type GeographyPlace,
} from '../app/_lib/geography-client';

const province = {
  id: '9007199254740993',
  label: 'Synthetic province',
  type_id: '2',
  type_label: 'Province',
};
const locality: GeographyPlace = {
  id: '9223372036854775807',
  label: 'Synthetic village',
  type: { id: '7', label: 'Village' },
  province,
  ancestors: [province],
  retired: false,
  selectable: true,
  catalog_revision: '19',
};
const root: GeographyPlace = {
  ...locality,
  id: province.id,
  label: province.label,
  type: { id: '2', label: 'Province' },
  ancestors: [],
};
const json = (data: unknown, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const page = (items = [locality], overrides = {}) => ({
  catalog_revision: '19',
  items,
  next_cursor: '',
  ...overrides,
});
const signal = () => new AbortController().signal;

it('uses anonymous same-origin bounded GETs with exact decimal IDs and no bootstrap or locale headers', async () => {
  const fetcher = jest
    .fn()
    .mockResolvedValueOnce(json(page([root])))
    .mockResolvedValueOnce(json(page([locality], { next_cursor: 'opaque_cursor' })))
    .mockResolvedValueOnce(json({ ...locality, selectable: false }));
  const client = new GeographyClient(fetcher);
  await client.list('province', { query: '', signal: signal() });
  await client.list('locality', {
    query: 'ي ک %_\\',
    provinceId: province.id,
    cursor: 'opaque_cursor',
    signal: signal(),
  });
  const found = await client.lookup(locality.id, signal(), '19');
  expect(found.id).toBe('9223372036854775807');
  expect(fetcher).toHaveBeenCalledTimes(3);
  const path = fetcher.mock.calls[1][0];
  const url = new URL(path, 'https://synthetic.example.test');
  expect(url.pathname).toBe('/api/v1/geography/localities');
  expect(Object.fromEntries(url.searchParams)).toEqual({
    country: 'IR',
    q: 'ي ک %_\\',
    limit: '20',
    province_id: province.id,
    cursor: 'opaque_cursor',
  });
  for (const [path, init] of fetcher.mock.calls) {
    expect(path).toMatch(/^\/api\/v1\/geography\//);
    expect(init).toMatchObject({
      method: 'GET',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      headers: { Accept: 'application/json' },
    });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  }
  expect(fetcher.mock.calls[2][0]).toBe(
    `/api/v1/geography/places/${locality.id}?country=IR&revision=19`
  );
});

it.each(['0', '-1', '01', '1.0', '1e3', '9223372036854775808', '۹', 1, null])(
  'rejects lossy or invalid ID %p',
  (id) => {
    expect(isGeographyId(id)).toBe(false);
  }
);

it('bounds Unicode query codepoints and bytes independently without changing bytes', async () => {
  expect(isGeographyQuery('🙂'.repeat(64))).toBe(true);
  expect(isGeographyQuery('🙂'.repeat(65))).toBe(false);
  expect(isGeographyQuery('a'.repeat(80))).toBe(true);
  expect(isGeographyQuery('a'.repeat(81))).toBe(false);
  expect(isGeographyQuery('الف\u200cب')).toBe(true);
  expect(isGeographyQuery('a\n')).toBe(false);
  expect(isGeographyQuery('\ud800')).toBe(false);
  const fetcher = jest.fn();
  const client = new GeographyClient(fetcher);
  await expect(
    client.list('locality', { query: '', provinceId: '0', signal: signal() })
  ).rejects.toMatchObject({ code: 'invalid_request' });
  await expect(
    client.list('province', { query: 'a'.repeat(81), signal: signal() })
  ).rejects.toMatchObject({ code: 'invalid_request' });
  await expect(
    client.list('province', { query: '', cursor: 'x'.repeat(2049), signal: signal() })
  ).rejects.toMatchObject({ code: 'invalid_request' });
  await expect(client.lookup('1', signal(), '')).rejects.toMatchObject({ code: 'invalid_request' });
  expect(fetcher).not.toHaveBeenCalled();
});

it.each([
  page(Array.from({ length: 21 }, () => locality)),
  page([locality, locality]),
  page([locality], { catalog_revision: 19 }),
  page([locality], { next_cursor: 'x'.repeat(2049) }),
  page([{ ...locality, id: Number('9007199254740993') } as unknown as GeographyPlace]),
  page([{ ...locality, retired: true }]),
  page([{ ...locality, selectable: false }]),
  page([{ ...locality, catalog_revision: '20' }]),
  page([{ ...locality, label: 'x'.repeat(257) }]),
  page([{ ...locality, label: '' }]),
  page([{ ...locality, province: { ...province, id: '2' } }]),
  page([{ ...locality, ancestors: [] }]),
  page([{ ...locality, ancestors: Array.from({ length: 33 }, () => province) }]),
  page([{ ...locality, ancestors: [province, province] }]),
  page([{ ...locality, type: { id: '6', label: 'Technical type' } }]),
])('rejects malformed or unbounded list payload %#', async (data) => {
  const client = new GeographyClient(jest.fn().mockResolvedValue(json(data)));
  await expect(
    client.list('locality', { query: '', provinceId: province.id, signal: signal() })
  ).rejects.toMatchObject({ code: 'unavailable' });
});

it('allows successful empty results and rejects localities from province browse', async () => {
  const client = new GeographyClient(
    jest
      .fn()
      .mockResolvedValueOnce(json(page([])))
      .mockResolvedValueOnce(json(page()))
  );
  expect(await client.list('province', { query: '', signal: signal() })).toEqual(page([]));
  await expect(client.list('province', { query: '', signal: signal() })).rejects.toMatchObject({
    code: 'unavailable',
  });
});

it('allows retired metadata lookups but rejects mismatched identity or historical revision', async () => {
  const historical = { ...locality, retired: true, selectable: false };
  const client = new GeographyClient(
    jest
      .fn()
      .mockResolvedValueOnce(json(historical))
      .mockResolvedValueOnce(json(root))
      .mockResolvedValueOnce(json(locality))
  );
  expect(await client.lookup(locality.id, signal())).toEqual(historical);
  await expect(client.lookup(locality.id, signal())).rejects.toMatchObject({ code: 'unavailable' });
  await expect(client.lookup(locality.id, signal(), '20')).rejects.toMatchObject({
    code: 'unavailable',
  });
});

it.each([
  [400, 'invalid_request'],
  [404, 'not_found'],
  [409, 'catalog_changed'],
  [429, 'rate_limited'],
  [503, 'unavailable'],
  [500, 'unavailable'],
])('classifies status %s without exposing server error prose', async (status, code) => {
  const client = new GeographyClient(
    jest
      .fn()
      .mockResolvedValue(
        json({ error: 'private server diagnostic' }, status as number, { 'Retry-After': '60' })
      )
  );
  const failure = await client.lookup('1', signal()).catch((error) => error);
  expect(failure).toBeInstanceOf(GeographyError);
  expect(failure).toMatchObject({ code, retryAfter: 60 });
  expect(failure.message).not.toContain('private');
});

it('fails closed on network, wrong media type, malformed JSON and response byte limits', async () => {
  const responses = [
    Promise.reject(new Error('private connection diagnostic')),
    Promise.resolve(new Response('{}', { headers: { 'Content-Type': 'text/html' } })),
    Promise.resolve(new Response('{', { headers: { 'Content-Type': 'application/json' } })),
    Promise.resolve(json(page(), 200, { 'Content-Length': String(2 * 1024 * 1024 + 1) })),
    Promise.resolve(
      new Response(' '.repeat(2 * 1024 * 1024 + 1), {
        headers: { 'Content-Type': 'application/json' },
      })
    ),
    Promise.resolve(
      new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } })
    ),
  ];
  for (const response of responses) {
    const client = new GeographyClient(jest.fn().mockImplementation(() => response));
    await expect(client.lookup('1', signal())).rejects.toMatchObject({ code: 'unavailable' });
  }
});

it('rejects an aborted response even if the transport ignores cancellation', async () => {
  const controller = new AbortController();
  const client = new GeographyClient(
    jest.fn().mockImplementation(async () => {
      controller.abort();
      return json(locality);
    })
  );
  await expect(client.lookup(locality.id, controller.signal)).rejects.toMatchObject({
    name: 'AbortError',
  });
});
