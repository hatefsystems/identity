import { act, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { SearchableList, type SearchableListOption } from './searchable-list';

const options = [
  { id: '1', label: 'Alpha' },
  { id: '2', label: 'Disabled', disabled: true },
  { id: '3', label: 'Beta' },
];
function Fixture({
  onSelect = jest.fn(),
  items = options,
  disabled = false,
}: {
  onSelect?: (id: string) => void;
  items?: SearchableListOption[];
  disabled?: boolean;
}) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  return (
    <SearchableList
      label="Choose a result"
      query={query}
      onQueryChange={setQuery}
      open={open}
      onOpenChange={setOpen}
      options={items}
      onSelect={onSelect}
      disabled={disabled}
      selectedId="3"
      descriptionId="hint"
      busy={false}
    />
  );
}

it('exposes a labeled controlled combobox and a connected listbox', () => {
  render(<Fixture />);
  const input = screen.getByRole('combobox', { name: 'Choose a result' });
  expect(input.getAttribute('aria-expanded')).toBe('false');
  fireEvent.focus(input);
  const list = screen.getByRole('listbox', { name: 'Choose a result' });
  expect(input.getAttribute('aria-controls')).toBe(list.id);
  expect(input.getAttribute('aria-describedby')).toBe('hint');
  expect(input.getAttribute('dir')).toBe('auto');
  expect(input.className).toContain('min-h-11');
  expect(screen.getByRole('option', { name: 'Beta' }).getAttribute('aria-selected')).toBe('true');
});

it('wraps arrows, skips disabled results and selects explicitly with Enter', () => {
  const select = jest.fn();
  render(<Fixture onSelect={select} />);
  const input = screen.getByRole('combobox');
  fireEvent.keyDown(input, { key: 'ArrowDown' });
  expect(input.getAttribute('aria-activedescendant')).toBe(
    screen.getByRole('option', { name: 'Alpha' }).id
  );
  fireEvent.keyDown(input, { key: 'ArrowDown' });
  expect(input.getAttribute('aria-activedescendant')).toBe(
    screen.getByRole('option', { name: 'Beta' }).id
  );
  fireEvent.keyDown(input, { key: 'ArrowDown' });
  fireEvent.keyDown(input, { key: 'ArrowUp' });
  fireEvent.keyDown(input, { key: 'Enter' });
  expect(select).toHaveBeenCalledWith('3');
  expect(input.getAttribute('aria-expanded')).toBe('false');
});

it('never commits draft text or Enter without an active result', () => {
  const select = jest.fn();
  render(<Fixture onSelect={select} />);
  const input = screen.getByRole('combobox');
  fireEvent.change(input, { target: { value: 'Alpha' } });
  fireEvent.keyDown(input, { key: 'Enter' });
  expect(select).not.toHaveBeenCalled();
  expect((input as HTMLInputElement).value).toBe('Alpha');
  fireEvent.keyDown(input, { key: 'ArrowDown' });
  fireEvent.change(input, { target: { value: 'Other' } });
  expect(input.getAttribute('aria-activedescendant')).toBeNull();
});

it('closes on Escape without committing or deleting the draft', () => {
  const select = jest.fn();
  render(<Fixture onSelect={select} />);
  const input = screen.getByRole('combobox');
  fireEvent.change(input, { target: { value: 'Draft' } });
  fireEvent.keyDown(input, { key: 'ArrowUp' });
  fireEvent.keyDown(input, { key: 'Escape' });
  expect(screen.queryByRole('listbox')).toBeNull();
  expect((input as HTMLInputElement).value).toBe('Draft');
  expect(select).not.toHaveBeenCalled();
});

it('supports pointer and touch-generated clicks without selecting disabled options', () => {
  const select = jest.fn();
  render(<Fixture onSelect={select} />);
  fireEvent.focus(screen.getByRole('combobox'));
  fireEvent.click(screen.getByRole('option', { name: 'Disabled' }));
  expect(select).not.toHaveBeenCalled();
  const result = screen.getByRole('option', { name: 'Alpha' });
  expect(result.className).toContain('min-h-11');
  fireEvent.click(result);
  expect(select).toHaveBeenCalledWith('1');
});

it('reopens on click after Escape while retaining input focus without committing', () => {
  const select = jest.fn();
  render(<Fixture onSelect={select} />);
  const input = screen.getByRole('combobox');
  act(() => input.focus());
  fireEvent.keyDown(input, { key: 'Escape' });
  expect(document.activeElement).toBe(input);
  expect(input.getAttribute('aria-expanded')).toBe('false');
  fireEvent.click(input);
  expect(input.getAttribute('aria-expanded')).toBe('true');
  expect(input.getAttribute('aria-activedescendant')).toBeNull();
  expect(select).not.toHaveBeenCalled();
});

it('does not select a stale active result after the list changes', () => {
  const select = jest.fn();
  const view = render(<Fixture onSelect={select} />);
  const input = screen.getByRole('combobox');
  fireEvent.keyDown(input, { key: 'ArrowDown' });
  view.rerender(<Fixture onSelect={select} items={[{ id: '4', label: 'Gamma' }]} />);
  expect(input.getAttribute('aria-activedescendant')).toBeNull();
  fireEvent.keyDown(input, { key: 'Enter' });
  expect(select).not.toHaveBeenCalled();
});

it('handles empty results and ignores composition keys', () => {
  const select = jest.fn();
  render(<Fixture onSelect={select} items={[]} />);
  const input = screen.getByRole('combobox');
  fireEvent.keyDown(input, { key: 'ArrowDown' });
  fireEvent.keyDown(input, { key: 'Enter' });
  expect(select).not.toHaveBeenCalled();
  fireEvent.keyDown(input, { key: 'Escape', isComposing: true });
  expect(input.getAttribute('aria-expanded')).toBe('true');
});

it('keeps disabled controls closed', () => {
  render(<Fixture disabled />);
  expect((screen.getByRole('combobox') as HTMLInputElement).disabled).toBe(true);
  expect(screen.queryByRole('listbox')).toBeNull();
});

it('contains owner-supplied paging controls without closing on internal focus movement', () => {
  const change = jest.fn();
  render(
    <SearchableList
      label="Search"
      query=""
      onQueryChange={jest.fn()}
      open
      onOpenChange={change}
      options={options}
      onSelect={jest.fn()}
    >
      <button type="button">More</button>
    </SearchableList>
  );
  fireEvent.blur(screen.getByRole('combobox'), { relatedTarget: screen.getByRole('button') });
  expect(change).not.toHaveBeenCalled();
  fireEvent.blur(screen.getByRole('button'), { relatedTarget: null });
  expect(change).toHaveBeenCalledWith(false);
});
