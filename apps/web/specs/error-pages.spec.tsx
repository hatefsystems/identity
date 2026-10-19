import { fireEvent, render, screen } from '@testing-library/react';
import ErrorPage from '../app/error';
import GlobalError from '../app/global-error';
import NotFound from '../app/not-found';

describe('CSP-compatible error pages', () => {
  it('renders a class-based not-found page with a home link', () => {
    const { container } = render(<NotFound />);

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
    render(<GlobalError />, { container: document });

    expect(document.documentElement.lang).toBe('en');
    expect(document.body.classList.contains('bg-background')).toBe(true);
    expect(screen.getByRole('heading', { name: 'Something went wrong' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reload page' })).toBeTruthy();
    expect(document.querySelector('style, script, [style], [onclick]')).toBeNull();
  });
});
