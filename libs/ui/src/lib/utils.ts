import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Merges Tailwind CSS class names, resolving conflicts in favor of the
 * later class (shadcn/ui convention).
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
