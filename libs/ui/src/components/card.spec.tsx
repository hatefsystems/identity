import React from 'react';
import { render, screen } from '@testing-library/react';

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from './card';

describe('Card', () => {
  it('should render a full card composition', () => {
    render(
      <Card data-testid="card">
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Description</CardDescription>
        </CardHeader>
        <CardContent>Content</CardContent>
        <CardFooter>Footer</CardFooter>
      </Card>
    );

    expect(screen.getByTestId('card')).toBeTruthy();
    expect(screen.getByText('Title')).toBeTruthy();
    expect(screen.getByText('Description')).toBeTruthy();
    expect(screen.getByText('Content')).toBeTruthy();
    expect(screen.getByText('Footer')).toBeTruthy();
  });

  it('should apply base card classes', () => {
    render(<Card data-testid="card" />);
    const card = screen.getByTestId('card');
    expect(card.className).toContain('rounded-lg');
    expect(card.className).toContain('border');
  });

  it('should merge custom class names', () => {
    render(<Card data-testid="card" className="max-w-md" />);
    expect(screen.getByTestId('card').className).toContain('max-w-md');
  });
});
