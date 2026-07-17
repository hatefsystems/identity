import React from 'react';
import { render, screen } from '@testing-library/react';

import { Button } from './button';

describe('Button', () => {
  it('should render successfully', () => {
    const { baseElement } = render(<Button>Click me</Button>);
    expect(baseElement).toBeTruthy();
  });

  it('should render its children', () => {
    render(<Button>Sign in</Button>);
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeTruthy();
  });

  it('should apply the default variant classes', () => {
    render(<Button>Default</Button>);
    const button = screen.getByRole('button', { name: 'Default' });
    expect(button.className).toContain('bg-primary');
  });

  it('should apply the outline variant classes', () => {
    render(<Button variant="outline">Outline</Button>);
    const button = screen.getByRole('button', { name: 'Outline' });
    expect(button.className).toContain('border-input');
  });

  it('should apply the destructive variant classes', () => {
    render(<Button variant="destructive">Delete</Button>);
    const button = screen.getByRole('button', { name: 'Delete' });
    expect(button.className).toContain('bg-destructive');
  });

  it('should merge custom class names', () => {
    render(<Button className="w-full">Wide</Button>);
    const button = screen.getByRole('button', { name: 'Wide' });
    expect(button.className).toContain('w-full');
  });

  it('should support the disabled attribute', () => {
    render(<Button disabled>Disabled</Button>);
    const button = screen.getByRole('button', { name: 'Disabled' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
  });

  it('should render as child element when asChild is true', () => {
    render(
      <Button asChild>
        <a href="/login">Login link</a>
      </Button>
    );
    const link = screen.getByRole('link', { name: 'Login link' });
    expect(link).toBeTruthy();
    expect(link.getAttribute('href')).toBe('/login');
  });
});
