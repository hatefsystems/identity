import { cn } from './utils';

describe('cn', () => {
  it('should merge class names', () => {
    expect(cn('px-2', 'py-2')).toBe('px-2 py-2');
  });

  it('should resolve conflicting Tailwind classes in favor of the last one', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4');
    expect(cn('bg-primary', 'bg-secondary')).toBe('bg-secondary');
  });

  it('should handle conditional class values', () => {
    expect(cn('base', { active: true, disabled: false })).toBe('base active');
  });

  it('should ignore falsy values', () => {
    expect(cn('base', undefined, null, false, '')).toBe('base');
  });

  it('should handle arrays of class names', () => {
    expect(cn(['a', 'b'], 'c')).toBe('a b c');
  });

  it('should return an empty string when called with no arguments', () => {
    expect(cn()).toBe('');
  });
});
