import { render as renderWithoutProvider } from '@testing-library/react';
import { fireEvent, render, screen } from '../i18n/testing';
import ErrorPage from '../app/error';
import GlobalError from '../app/global-error';
import NotFound from '../app/not-found';

jest.mock('next-intl/server', () => ({
  getTranslations: (...args: unknown[]) => jest.requireActual('../i18n/testing').getTestTranslations(...args),
}));

describe('CSP-compatible error pages', () => {
  it('renders a class-based not-found page with a home link', async () => {
    const { container } = render(await NotFound());

    expect(screen.getByRole('heading', { name: 'Page not found' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Return home' }).getAttribute('href')).toBe('/');
    expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
  });

  it('can reset an ordinary error without exposing exception details', () => {
    const reset = jest.fn();
    const { container } = render(
      <ErrorPage error={new Error('sensitive internal exception')} reset={reset} />
    );

    expect(screen.getByRole('heading', { name: 'Something went wrong' })).toBeTruthy();
    expect(screen.queryByText('sensitive internal exception')).toBeNull();
    expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(reset).toHaveBeenCalledTimes(1);
  });

  it('supplies an independent, class-based document for root errors', () => {
    renderWithoutProvider(<GlobalError />, { container: document });

    expect(document.documentElement.lang).toBe('en');
    expect(document.body.classList.contains('bg-background')).toBe(true);
    expect(screen.getByRole('heading', { name: 'Something went wrong' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reload page' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'بازخوانی صفحه' })).toBeTruthy();
    expect(document.querySelector('section[lang="fa-IR"][dir="rtl"]')).toBeTruthy();
    expect(document.querySelector('style, script, [style], [onclick]')).toBeNull();
  });

  it('renders Persian ordinary errors without exposing sensitive details', () => {
    const reset = jest.fn();
    render(<ErrorPage error={new Error('private exception')} reset={reset} />, { locale: 'fa-IR' });
    expect(screen.getByRole('heading', { name: 'مشکلی پیش آمد' })).toBeTruthy();
    expect(screen.queryByText('private exception')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'تلاش دوباره' }));
    expect(reset).toHaveBeenCalledTimes(1);
  });
});
