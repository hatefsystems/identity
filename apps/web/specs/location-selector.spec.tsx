import { TextEncoder } from 'node:util';
import { useState } from 'react';
import { render as rawRender } from '@testing-library/react';
import { act, fireEvent, render, screen, within, I18nTestProvider } from '../i18n/testing';
import { LocationSelector } from '../app/_components/location-selector';
import {
  GeographyClient,
  GeographyError,
  type GeographyPage,
  type GeographyPlace,
  type LocationInput,
} from '../app/_lib/geography-client';

const provinceSummary = {
  id: '101',
  label: 'Synthetic north',
  type_id: '2',
  type_label: 'Province',
};
const province: GeographyPlace = {
  id: '101',
  label: 'Synthetic north',
  type: { id: '2', label: 'Province' },
  province: provinceSummary,
  ancestors: [],
  retired: false,
  selectable: true,
  catalog_revision: '10',
};
const otherProvince: GeographyPlace = {
  ...province,
  id: '102',
  label: 'Synthetic south',
  province: { ...provinceSummary, id: '102', label: 'Synthetic south' },
};
const locality: GeographyPlace = {
  ...province,
  id: '201',
  label: 'Synthetic town',
  type: { id: '5', label: 'Urban area' },
  ancestors: [provinceSummary],
};
const village: GeographyPlace = {
  ...locality,
  id: '202',
  label: 'Synthetic town',
  type: { id: '7', label: 'Village' },
  ancestors: [
    provinceSummary,
    { id: '301', label: 'Synthetic district', type_id: '3', type_label: 'County' },
  ],
};
const page = (
  items: GeographyPlace[],
  next_cursor = '',
  catalog_revision = '10'
): GeographyPage => ({ items, next_cursor, catalog_revision });
const api = { list: jest.fn(), lookup: jest.fn() };
const client = api as unknown as GeographyClient;
const changed = jest.fn();
function Fixture({ initial = null }: { initial?: LocationInput | null }) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <LocationSelector
        value={value}
        onChange={(next) => {
          changed(next);
          setValue(next);
        }}
        client={client}
      />
      <output data-testid="value">{JSON.stringify(value)}</output>
    </>
  );
}
const value = () => JSON.parse(screen.getByTestId('value').textContent ?? 'null');
const field = (name: 'province' | 'locality') =>
  within(document.querySelector(`[data-location-field="${name}"]`) as HTMLElement);
const input = (name: 'province' | 'locality') =>
  field(name).getByRole('combobox') as HTMLInputElement;
async function tick(ms = 250) {
  await act(async () => {
    jest.advanceTimersByTime(ms);
  });
}
async function open(name: 'province' | 'locality') {
  fireEvent.focus(input(name));
  await tick();
}
function select(name: 'province' | 'locality', index = 0) {
  fireEvent.click(field(name).getAllByRole('option')[index]);
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
const encoder = Object.getOwnPropertyDescriptor(globalThis, 'TextEncoder');
const showModal = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'showModal');
const closeDialog = Object.getOwnPropertyDescriptor(HTMLDialogElement.prototype, 'close');
beforeAll(() => {
  Object.defineProperty(globalThis, 'TextEncoder', { configurable: true, value: TextEncoder });
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {
    configurable: true,
    value() {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {
    configurable: true,
    value() {
      this.open = false;
    },
  });
});
afterAll(() => {
  if (encoder) Object.defineProperty(globalThis, 'TextEncoder', encoder);
  else Reflect.deleteProperty(globalThis, 'TextEncoder');
  for (const [key, descriptor] of [
    ['showModal', showModal],
    ['close', closeDialog],
  ] as const) {
    if (descriptor) Object.defineProperty(HTMLDialogElement.prototype, key, descriptor);
    else Reflect.deleteProperty(HTMLDialogElement.prototype, key);
  }
});
beforeEach(() => {
  jest.useFakeTimers();
  jest.clearAllMocks();
  api.list
    .mockReset()
    .mockImplementation(async (kind) =>
      page(kind === 'province' ? [province, otherProvince] : [locality, village])
    );
  api.lookup
    .mockReset()
    .mockImplementation(async (id) =>
      [province, otherProvince, locality, village].find((place) => place.id === id)
    );
});
afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

it.each([
  [
    'en',
    'Province (required)',
    'City, urban area, or village (optional)',
    'Skip city, urban area, or village',
  ],
  [
    'fa-IR',
    'استان (الزامی)',
    'شهر، منطقه شهری یا روستا (اختیاری)',
    'رد شدن از انتخاب شهر، منطقه شهری یا روستا',
  ],
] as const)(
  'supports the explicit keyboard journey in %s with optional locality',
  async (locale, provinceName, localityName, skipName) => {
    render(<Fixture />, { locale });
    expect(screen.getByRole('combobox', { name: provinceName })).toBeTruthy();
    expect(
      (screen.getByRole('combobox', { name: localityName }) as HTMLInputElement).disabled
    ).toBe(true);
    expect(api.list).not.toHaveBeenCalled();
    expect(api.lookup).not.toHaveBeenCalled();
    await open('province');
    expect(changed).not.toHaveBeenCalled();
    fireEvent.keyDown(input('province'), { key: 'ArrowDown' });
    fireEvent.keyDown(input('province'), { key: 'Enter' });
    expect(value()).toEqual({ country: 'IR', province_id: '101' });
    await tick();
    expect(input('locality').disabled).toBe(false);
    await open('locality');
    fireEvent.keyDown(input('locality'), { key: 'ArrowDown' });
    fireEvent.keyDown(input('locality'), { key: 'ArrowDown' });
    fireEvent.keyDown(input('locality'), { key: 'Enter' });
    expect(value()).toEqual({ country: 'IR', province_id: '101', locality_id: '202' });
    await tick();
    expect(document.querySelector('[data-location-selected="locality"]')?.textContent).toContain(
      'Synthetic district'
    );
    fireEvent.click(screen.getByRole('button', { name: skipName }));
    expect(value()).toEqual({ country: 'IR', province_id: '101' });
  }
);

it('separates draft text from selection, never auto-selects and closes on Escape', async () => {
  render(<Fixture />);
  await open('province');
  fireEvent.change(input('province'), { target: { value: 'Synthetic north' } });
  fireEvent.keyDown(input('province'), { key: 'Enter' });
  expect(value()).toBeNull();
  await tick();
  expect(value()).toBeNull();
  fireEvent.keyDown(input('province'), { key: 'Escape' });
  expect(screen.queryByRole('listbox')).toBeNull();
  expect(changed).not.toHaveBeenCalled();
});

it('changes or clears province explicitly and announces incompatible locality removal', async () => {
  render(<Fixture initial={{ country: 'IR', province_id: '101', locality_id: '201' }} />);
  await tick();
  await open('province');
  select('province', 1);
  expect(value()).toEqual({ country: 'IR', province_id: '102' });
  expect(
    screen.getByText('The city, urban area, or village was cleared because the province changed.')
  ).toBeTruthy();
  await tick();
  fireEvent.click(screen.getByRole('button', { name: 'Clear province' }));
  expect(value()).toBeNull();
  expect(input('locality').disabled).toBe(true);
  expect(document.querySelector('[data-location-selected="locality"]')?.textContent).not.toContain(
    locality.label
  );
});

it('preserves compatible locality when the same province is explicitly selected', async () => {
  render(<Fixture initial={{ country: 'IR', province_id: '101', locality_id: '201' }} />);
  await tick();
  await open('province');
  select('province');
  expect(value()).toEqual({ country: 'IR', province_id: '101', locality_id: '201' });
});

it('clears locality without clearing its province', async () => {
  render(<Fixture initial={{ country: 'IR', province_id: '101', locality_id: '201' }} />);
  await tick();
  fireEvent.click(screen.getByRole('button', { name: 'Clear city, urban area, or village' }));
  expect(value()).toEqual({ country: 'IR', province_id: '101' });
  expect(screen.getByText('The city, urban area, or village selection was cleared.')).toBeTruthy();
});

it('debounces 250ms and aborts immediately when a newer draft replaces an in-flight request', async () => {
  const old = deferred<GeographyPage>();
  api.list.mockReturnValueOnce(old.promise).mockResolvedValueOnce(page([otherProvince]));
  render(<Fixture />);
  fireEvent.focus(input('province'));
  await tick(249);
  expect(api.list).not.toHaveBeenCalled();
  await tick(1);
  const oldSignal = api.list.mock.calls[0][1].signal as AbortSignal;
  fireEvent.change(input('province'), { target: { value: 'south' } });
  expect(oldSignal.aborted).toBe(true);
  await tick();
  expect(api.list.mock.calls[1][1].query).toBe('south');
  await act(async () => old.resolve(page([province])));
  expect(field('province').getAllByRole('option')).toHaveLength(1);
  expect(field('province').getByRole('option').textContent).toContain('Synthetic south');
});

it('rejects stale errors after a newer successful request and cancels on closing', async () => {
  const old = deferred<GeographyPage>();
  api.list.mockReturnValueOnce(old.promise).mockResolvedValueOnce(page([otherProvince]));
  render(<Fixture />);
  await open('province');
  fireEvent.change(input('province'), { target: { value: 'south' } });
  await tick();
  await act(async () => old.reject(new GeographyError('unavailable')));
  expect(
    screen.queryByText('Locations are temporarily unavailable. Retry when you are ready.')
  ).toBeNull();
  const activeSignal = api.list.mock.calls[1][1].signal as AbortSignal;
  fireEvent.keyDown(input('province'), { key: 'Escape' });
  expect(activeSignal.aborted).toBe(true);
});

it('uses generation checks independently when cancellation does not abort the signal', async () => {
  jest.spyOn(AbortController.prototype, 'abort').mockImplementation(() => undefined);
  const old = deferred<GeographyPage>();
  api.list.mockReturnValueOnce(old.promise).mockResolvedValueOnce(page([otherProvince]));
  render(<Fixture />);
  await open('province');
  const oldSignal = api.list.mock.calls[0][1].signal as AbortSignal;
  fireEvent.change(input('province'), { target: { value: 'south' } });
  await tick();
  expect(oldSignal.aborted).toBe(false);
  await act(async () => old.resolve(page([province])));
  expect(screen.getByRole('option').textContent).toContain('Synthetic south');
});

it('does not overwrite selected metadata if the controlled owner declines a selection change', async () => {
  render(
    <LocationSelector
      value={{ country: 'IR', province_id: '101' }}
      onChange={changed}
      client={client}
    />
  );
  await tick();
  await open('province');
  select('province', 1);
  await tick();
  expect(changed).toHaveBeenCalledWith({ country: 'IR', province_id: '102' });
  expect(document.querySelector('[data-location-selected="province"]')?.textContent).toContain(
    'Synthetic north'
  );
  expect(api.lookup).toHaveBeenCalledTimes(1);
});

it('cancels locality queries and stale pages when province changes', async () => {
  const pending = deferred<GeographyPage>();
  api.list.mockImplementation((kind) =>
    kind === 'locality' ? pending.promise : Promise.resolve(page([otherProvince]))
  );
  const view = render(
    <LocationSelector
      value={{ country: 'IR', province_id: '101' }}
      onChange={changed}
      client={client}
    />
  );
  await open('locality');
  const oldSignal = api.list.mock.calls[0][1].signal as AbortSignal;
  view.rerender(
    <LocationSelector
      value={{ country: 'IR', province_id: '102' }}
      onChange={changed}
      client={client}
    />
  );
  expect(oldSignal.aborted).toBe(true);
  await act(async () => pending.resolve(page([locality])));
  expect(screen.queryByRole('option')).toBeNull();
  expect(input('locality').value).toBe('');
});

it('loads explicit bounded pages, deduplicates and does not replay after selection metadata lookups', async () => {
  api.list
    .mockResolvedValueOnce(page([province], 'next'))
    .mockResolvedValueOnce(page([province, otherProvince]));
  render(<Fixture />);
  await open('province');
  expect(api.list).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Load more results' }));
  await tick(0);
  expect(api.list.mock.calls[1][1].cursor).toBe('next');
  expect(field('province').getAllByRole('option')).toHaveLength(2);
  select('province', 1);
  await tick();
  expect(api.list).toHaveBeenCalledTimes(2);
  expect(api.lookup).toHaveBeenCalledWith('102', expect.any(AbortSignal));
  expect(document.querySelector('[data-location-selected="province"]')?.textContent).toContain(
    'Synthetic south'
  );
});

it('retains at most 100 results and requires a refined search at the bound', async () => {
  let batch = 0;
  api.list.mockImplementation(async () => {
    const start = batch++ * 20;
    return page(
      Array.from({ length: 20 }, (_, index) => ({
        ...province,
        id: String(1000 + start + index),
        label: `Synthetic province ${start + index}`,
      })),
      `cursor-${batch}`
    );
  });
  render(<Fixture />);
  await open('province');
  for (let i = 0; i < 4; i++) {
    fireEvent.click(screen.getByRole('button', { name: 'Load more results' }));
    await tick(0);
  }
  expect(screen.getAllByRole('option')).toHaveLength(100);
  expect(screen.queryByRole('button', { name: 'Load more results' })).toBeNull();
  expect(
    screen.getByText(
      'The result limit has been reached. Refine your search to find another location.'
    )
  ).toBeTruthy();
  fireEvent.change(input('province'), { target: { value: 'Refined' } });
  await tick();
  expect(screen.getAllByRole('option')).toHaveLength(20);
});

it.each(['catalog_changed', 'mismatched_revision'] as const)(
  'discards mixed catalogs on %s and retries from the first page',
  async (failure) => {
    api.list.mockResolvedValueOnce(page([province], 'next'));
    if (failure === 'catalog_changed')
      api.list.mockRejectedValueOnce(new GeographyError('catalog_changed'));
    else
      api.list.mockResolvedValueOnce(
        page([{ ...otherProvince, catalog_revision: '11' }], '', '11')
      );
    api.list.mockResolvedValueOnce(page([{ ...otherProvince, catalog_revision: '11' }], '', '11'));
    render(<Fixture />);
    await open('province');
    fireEvent.click(screen.getByRole('button', { name: 'Load more results' }));
    await tick(0);
    expect(screen.queryByRole('option')).toBeNull();
    expect(
      screen.getByText('The location catalog changed. Retry to browse the current catalog.')
    ).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await tick();
    expect(api.list.mock.calls[2][1].cursor).toBeUndefined();
    expect(screen.getByRole('option').textContent).toContain('Synthetic south');
  }
);

it('ignores an old pagination response after the search draft changes', async () => {
  const old = deferred<GeographyPage>();
  api.list
    .mockResolvedValueOnce(page([province], 'next'))
    .mockReturnValueOnce(old.promise)
    .mockResolvedValueOnce(page([otherProvince]));
  render(<Fixture />);
  await open('province');
  fireEvent.click(screen.getByRole('button', { name: 'Load more results' }));
  await tick(0);
  const oldSignal = api.list.mock.calls[1][1].signal as AbortSignal;
  fireEvent.change(input('province'), { target: { value: 'south' } });
  await tick();
  expect(oldSignal.aborted).toBe(true);
  await act(async () => old.resolve(page([province])));
  expect(screen.getAllByRole('option')).toHaveLength(1);
  expect(screen.getByRole('option').textContent).toContain('Synthetic south');
});

it.each([
  [
    'en',
    'unavailable',
    'Locations are temporarily unavailable. Retry when you are ready.',
    'Retry',
  ],
  [
    'fa-IR',
    'unavailable',
    'مکان‌ها موقتاً در دسترس نیستند. هر زمان آماده بودید دوباره تلاش کنید.',
    'تلاش دوباره',
  ],
  ['en', 'rate_limited', 'Too many location requests. Wait before retrying.', 'Retry'],
  [
    'fa-IR',
    'rate_limited',
    'درخواست‌های مکان بیش از حد مجاز است. پیش از تلاش دوباره صبر کنید.',
    'تلاش دوباره',
  ],
] as const)(
  'renders %s %s feedback and retries only explicitly',
  async (locale, code, feedback, retryName) => {
    api.list
      .mockRejectedValueOnce(new GeographyError(code))
      .mockResolvedValueOnce(page([province]));
    render(<Fixture />, { locale });
    await open('province');
    expect(screen.getByText(feedback)).toBeTruthy();
    await tick(1000);
    expect(api.list).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: retryName }));
    await tick();
    expect(screen.getByRole('option')).toBeTruthy();
    expect(changed).not.toHaveBeenCalled();
  }
);

it('distinguishes empty and invalid-query states without issuing overlong requests', async () => {
  api.list.mockResolvedValue(page([]));
  render(<Fixture />);
  await open('province');
  expect(screen.getByText('No matching locations. Try a different name.')).toBeTruthy();
  fireEvent.change(input('province'), { target: { value: 'a'.repeat(81) } });
  await tick();
  expect(
    screen.getByText(
      'Search must be at most 80 characters and 256 bytes, without control characters.'
    )
  ).toBeTruthy();
  expect(api.list).toHaveBeenCalledTimes(1);
  fireEvent.change(input('province'), { target: { value: 'a'.repeat(10000) } });
  await tick();
  expect(input('province').value.length).toBe(160);
  expect(input('province').maxLength).toBe(160);
  expect(api.list).toHaveBeenCalledTimes(1);
});

it('uses current IDs to reject stale lookup details and preserves the controlled value on failure', async () => {
  const old = deferred<GeographyPlace>();
  api.lookup.mockReturnValueOnce(old.promise).mockResolvedValueOnce(otherProvince);
  const view = render(
    <LocationSelector
      value={{ country: 'IR', province_id: '101' }}
      onChange={changed}
      client={client}
    />
  );
  view.rerender(
    <LocationSelector
      value={{ country: 'IR', province_id: '102' }}
      onChange={changed}
      client={client}
    />
  );
  await tick();
  await act(async () => old.resolve(province));
  expect(document.querySelector('[data-location-selected="province"]')?.textContent).toContain(
    'Synthetic south'
  );
  expect(document.querySelector('[data-location-selected="province"]')?.textContent).not.toContain(
    'Synthetic north'
  );
  expect(changed).not.toHaveBeenCalled();
});

it('keeps retired metadata visible, exact IDs LTR and lookup failures explicitly retryable', async () => {
  api.lookup
    .mockRejectedValueOnce(new GeographyError('not_found'))
    .mockResolvedValueOnce({ ...province, retired: true, selectable: false });
  render(<Fixture initial={{ country: 'IR', province_id: '101' }} />);
  await tick();
  expect(
    screen.getByText(
      'The selected location details could not be loaded. Your selection is unchanged.'
    )
  ).toBeTruthy();
  expect(screen.getByText('101').getAttribute('dir')).toBe('ltr');
  fireEvent.click(screen.getByRole('button', { name: 'Retry selected location details' }));
  await tick();
  expect(
    screen.getByText(
      'This saved location is not available for a new selection. Choose a current location.'
    )
  ).toBeTruthy();
  expect(value()).toEqual({ country: 'IR', province_id: '101' });
  expect(changed).not.toHaveBeenCalled();
});

it('changes locale in place without replaying API calls, resetting drafts or losing selection', async () => {
  const view = rawRender(
    <I18nTestProvider locale="en">
      <Fixture initial={{ country: 'IR', province_id: '101' }} />
    </I18nTestProvider>
  );
  await tick();
  await open('locality');
  fireEvent.change(input('locality'), { target: { value: 'Synthetic' } });
  await tick();
  const requests = api.list.mock.calls.length;
  const lookups = api.lookup.mock.calls.length;
  view.rerender(
    <I18nTestProvider locale="fa-IR">
      <Fixture initial={{ country: 'IR', province_id: '101' }} />
    </I18nTestProvider>
  );
  await tick(1000);
  expect(screen.getByRole('combobox', { name: 'شهر، منطقه شهری یا روستا (اختیاری)' })).toBeTruthy();
  expect(input('locality').value).toBe('Synthetic');
  expect(api.list).toHaveBeenCalledTimes(requests);
  expect(api.lookup).toHaveBeenCalledTimes(lookups);
  expect(value()).toEqual({ country: 'IR', province_id: '101' });
  expect(
    document.querySelector('[data-location-selected="province"] bdi')?.getAttribute('dir')
  ).toBe('auto');
});

it.each([
  ['en', 'Province (required)', 'Close picker'],
  ['fa-IR', 'استان (الزامی)', 'بستن انتخاب‌گر'],
] as const)(
  'uses the spacious native mobile dialog in %s with focus containment and restoration',
  async (locale, title, close) => {
    jest
      .spyOn(HTMLElement.prototype, 'getClientRects')
      .mockReturnValue([{ width: 100, height: 44 } as DOMRect] as unknown as DOMRectList);
    render(<Fixture />, { locale });
    const opener = screen.getByRole('button', { name: title });
    act(() => opener.focus());
    fireEvent.click(opener);
    const dialog = screen.getByRole('dialog', { name: title });
    expect(dialog.getAttribute('data-layout')).toBe('review');
    expect(document.activeElement).toBe(within(dialog).getByRole('heading'));
    const closeButton = within(dialog).getByRole('button', { name: close });
    act(() => closeButton.focus());
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(within(dialog).getByRole('combobox'));
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(closeButton);
    fireEvent.click(closeButton);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(opener.className).toContain('min-h-11');
  }
);

it('cancels the mobile dialog with Escape and never issues work after unmount', async () => {
  const pending = deferred<GeographyPage>();
  api.list.mockReturnValue(pending.promise);
  const view = render(<Fixture />);
  fireEvent.click(screen.getByRole('button', { name: 'Province (required)' }));
  const dialog = screen.getByRole('dialog');
  fireEvent.focus(within(dialog).getByRole('combobox'));
  await tick();
  const signal = api.list.mock.calls[0][1].signal as AbortSignal;
  fireEvent.keyDown(within(dialog).getByRole('combobox'), { key: 'Escape' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(signal.aborted).toBe(true);
  view.unmount();
  await act(async () => pending.resolve(page([province])));
  expect(changed).not.toHaveBeenCalled();
});

it.each([
  ['en', 'City, urban area, or village (optional)', 'Skip city, urban area, or village'],
  ['fa-IR', 'شهر، منطقه شهری یا روستا (اختیاری)', 'رد شدن از انتخاب شهر، منطقه شهری یا روستا'],
] as const)(
  'supports mobile locality selection and skip in %s without changing province',
  async (locale, title, skipName) => {
    render(<Fixture initial={{ country: 'IR', province_id: '101' }} />, { locale });
    await tick();
    fireEvent.click(screen.getByRole('button', { name: title }));
    await tick();
    let dialog = screen.getByRole('dialog', { name: title });
    fireEvent.click(within(dialog).getAllByRole('option')[1]);
    await tick();
    expect(value()).toEqual({ country: 'IR', province_id: '101', locality_id: '202' });
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: title }));
    dialog = screen.getByRole('dialog', { name: title });
    fireEvent.click(within(dialog).getByRole('button', { name: skipName }));
    expect(value()).toEqual({ country: 'IR', province_id: '101' });
    expect(screen.queryByRole('dialog')).toBeNull();
  }
);
