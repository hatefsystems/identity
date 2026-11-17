'use client';

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { Input } from './input';
import { cn } from '../lib/utils';

export type SearchableListOption = {
  id: string;
  label: ReactNode;
  disabled?: boolean;
};

// The owner supplies presentation, transport state and the committed value.
export function SearchableList({
  label,
  query,
  onQueryChange,
  options,
  open,
  onOpenChange,
  onSelect,
  disabled = false,
  busy = false,
  selectedId,
  placeholder,
  descriptionId,
  children,
  closeOnBlur = true,
  maxLength,
}: {
  label: string;
  query: string;
  onQueryChange: (query: string) => void;
  options: readonly SearchableListOption[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (id: string) => void;
  disabled?: boolean;
  busy?: boolean;
  selectedId?: string;
  placeholder?: string;
  descriptionId?: string;
  children?: ReactNode;
  closeOnBlur?: boolean;
  maxLength?: number;
}) {
  const id = useId();
  const list = useRef<HTMLUListElement>(null);
  const [activeId, setActiveId] = useState<string>();
  const enabled = options.filter((option) => !option.disabled);
  const activeIndex = enabled.findIndex((option) => option.id === activeId);
  const active = open && !disabled && activeIndex >= 0 ? activeId : undefined;
  const optionId = (key: string) => `${id}-option-${key}`;

  useEffect(() => {
    if (active) {
      const element = list.current?.querySelector<HTMLElement>('[data-active="true"]');
      element?.scrollIntoView?.({ block: 'nearest' });
    }
  }, [active]);

  function select(key: string) {
    if (disabled || !options.some((option) => option.id === key && !option.disabled)) return;
    onSelect(key);
    setActiveId(undefined);
    onOpenChange(false);
  }

  return (
    <div
      onBlur={(event) => {
        if (closeOnBlur && !event.currentTarget.contains(event.relatedTarget)) {
          setActiveId(undefined);
          onOpenChange(false);
        }
      }}
    >
      <label htmlFor={`${id}-input`} className="mb-2 block text-sm font-medium">
        {label}
      </label>
      <Input
        id={`${id}-input`}
        role="combobox"
        aria-autocomplete="list"
        aria-expanded={open && !disabled}
        aria-controls={open && !disabled ? `${id}-list` : undefined}
        aria-activedescendant={active ? optionId(active) : undefined}
        aria-describedby={descriptionId}
        autoComplete="off"
        maxLength={maxLength}
        dir="auto"
        className="min-h-11 text-start"
        disabled={disabled}
        placeholder={placeholder}
        value={query}
        onFocus={() => onOpenChange(true)}
        onClick={() => onOpenChange(true)}
        onChange={(event) => {
          setActiveId(undefined);
          onQueryChange(event.target.value);
          onOpenChange(true);
        }}
        onKeyDown={(event) => {
          if (event.nativeEvent.isComposing) return;
          if (event.key === 'Escape') {
            if (open) {
              event.preventDefault();
              event.stopPropagation();
              setActiveId(undefined);
              onOpenChange(false);
            }
          } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            onOpenChange(true);
            if (!enabled.length) return;
            const next =
              event.key === 'ArrowDown'
                ? (activeIndex + 1) % enabled.length
                : activeIndex <= 0
                  ? enabled.length - 1
                  : activeIndex - 1;
            setActiveId(enabled[next].id);
          } else if (event.key === 'Enter' && open) {
            event.preventDefault();
            if (active) select(active);
          }
        }}
      />
      {open && !disabled && (
        <ul
          ref={list}
          id={`${id}-list`}
          role="listbox"
          aria-label={label}
          aria-busy={busy}
          className="mt-2 max-h-80 overflow-y-auto overscroll-contain rounded-md border bg-background p-1"
        >
          {options.map((option) => (
            <li
              key={option.id}
              id={optionId(option.id)}
              role="option"
              tabIndex={-1}
              aria-selected={option.id === selectedId}
              aria-disabled={option.disabled || undefined}
              data-active={option.id === active}
              className={cn(
                'min-h-11 cursor-pointer rounded px-3 py-3 text-start outline-none focus-visible:ring-2 focus-visible:ring-ring',
                option.id === active && 'bg-accent ring-2 ring-inset ring-ring',
                option.disabled && 'cursor-not-allowed opacity-50'
              )}
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => select(option.id)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  select(option.id);
                }
              }}
            >
              {option.label}
            </li>
          ))}
        </ul>
      )}
      {open && !disabled && children}
    </div>
  );
}
