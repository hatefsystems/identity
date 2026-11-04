import { useEffect, useState } from 'react';
import { act, fireEvent, render, screen, waitFor, I18nTestProvider } from '../i18n/testing';
import { PreferenceControls } from '../i18n/preferences';
import { saveDisplayPreferences } from '../i18n/actions';
import { useMessage } from '../i18n/use-message';
import { useDisplayPreferences } from '../i18n/provider';

jest.mock('../i18n/actions', () => ({ saveDisplayPreferences: jest.fn() }));
const save = jest.mocked(saveDisplayPreferences);

beforeEach(() => save.mockReset());

describe('explicit display preference controls', () => {
  it('does not persist or infer preferences on mount', () => {
    render(<PreferenceControls />);
    expect(save).not.toHaveBeenCalled();
    expect((screen.getByRole('combobox', { name: 'Language' }) as HTMLSelectElement).value).toBe(
      'en'
    );
    expect(screen.getByText('Display settings')).toBeTruthy();
  });

  it('serializes rapid saves and retains the old presentation on failure', async () => {
    let finish!: (result: { ok: boolean }) => void;
    save.mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        })
    );
    render(<PreferenceControls />);
    const language = screen.getByRole('combobox', { name: 'Language' });
    fireEvent.change(language, { target: { value: 'fa-IR' } });
    fireEvent.change(language, { target: { value: 'en' } });
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ locale: 'fa-IR', calendar: 'auto', timeZone: 'UTC' });
    expect((language as HTMLSelectElement).disabled).toBe(true);
    await act(async () => finish({ ok: false }));
    expect(
      screen.getByText('Preferences could not be saved. Your previous settings are unchanged.')
    ).toBeTruthy();
    expect((language as HTMLSelectElement).value).toBe('en');
    expect((language as HTMLSelectElement).disabled).toBe(false);
  });

  it('localizes save failures without displaying exceptions', async () => {
    save.mockRejectedValue(new Error('private server failure'));
    render(<PreferenceControls />, { locale: 'fa-IR' });
    fireEvent.change(screen.getByRole('combobox', { name: 'زبان' }), { target: { value: 'en' } });
    await waitFor(() =>
      expect(
        screen.getByText('ذخیرهٔ تنظیمات ممکن نشد. تنظیمات قبلی شما تغییر نکرده است.')
      ).toBeTruthy()
    );
    expect(screen.queryByText('private server failure')).toBeNull();
  });

  it('submits concrete display settings only through explicit controls', async () => {
    save.mockResolvedValue({ ok: true });
    render(<PreferenceControls />, {
      locale: 'fa-IR',
      preferences: { calendar: 'gregory', timeZone: 'Asia/Tehran' },
    });
    fireEvent.click(screen.getByText('تنظیمات نمایش'));
    fireEvent.change(screen.getByLabelText('تقویم'), { target: { value: 'persian' } });
    await waitFor(() => expect(screen.getByText('تنظیمات ذخیره شد.')).toBeTruthy());
    expect(save).toHaveBeenLastCalledWith({
      locale: 'fa-IR',
      calendar: 'persian',
      timeZone: 'Asia/Tehran',
    });
    expect(document.querySelector('[data-ui-preferences] form')).toBeNull();
    expect(
      screen.getByRole('button', { name: 'استفاده از منطقهٔ زمانی دستگاه' }).getAttribute('type')
    ).toBe('button');
  });

  it('updates feedback and preferences without remounting or resetting local state', () => {
    const mount = jest.fn();
    const unmount = jest.fn();
    function Probe() {
      const [draft, setDraft] = useState('unchanged draft');
      const translate = useMessage();
      const preferences = useDisplayPreferences();
      useEffect(() => {
        mount();
        return unmount;
      }, []);
      return (
        <>
          <input
            aria-label="test draft"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
          <p>{translate({ key: 'common.pageError' })}</p>
          <output>
            {preferences.calendar}/{preferences.timeZone}
          </output>
        </>
      );
    }
    const view = render(
      <I18nTestProvider locale="en" preferences={{ calendar: 'gregory', timeZone: 'Asia/Tehran' }}>
        <Probe />
      </I18nTestProvider>
    );
    fireEvent.change(screen.getByRole('textbox', { name: 'test draft' }), {
      target: { value: 'preserved draft' },
    });
    view.rerender(
      <I18nTestProvider
        locale="fa-IR"
        preferences={{ calendar: 'gregory', timeZone: 'Asia/Tehran' }}
      >
        <Probe />
      </I18nTestProvider>
    );
    expect(screen.getByText('مشکلی پیش آمد')).toBeTruthy();
    expect((screen.getByRole('textbox', { name: 'test draft' }) as HTMLInputElement).value).toBe(
      'preserved draft'
    );
    expect(screen.getByText('gregory/Asia/Tehran')).toBeTruthy();
    expect(mount).toHaveBeenCalledTimes(1);
    expect(unmount).not.toHaveBeenCalled();
  });
});
