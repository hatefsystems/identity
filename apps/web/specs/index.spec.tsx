import { render, screen } from '@testing-library/react';
import Page from '../app/page';

describe('Page', () => {
  it('preserves the homepage heading and links to the sign-in and registration routes', () => {
    const { container } = render(<Page />);

    expect(screen.getByRole('heading', { level: 1, name: 'Hatef Identity Platform' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Sign in' }).getAttribute('href')).toBe('/login');
    expect(screen.getByRole('link', { name: 'Create an account' }).getAttribute('href')).toBe(
      '/register'
    );
    expect(screen.queryByRole('button')).toBeNull();
    expect(container.querySelector('style, script, [style], [onclick]')).toBeNull();
  });
});
