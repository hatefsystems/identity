'use server';

import { cookies } from 'next/headers';
import {
  preferenceCookie,
  preferenceMaxAge,
  serializePreferences,
  validatePreferences,
} from './config';

export async function saveDisplayPreferences(input: unknown): Promise<{ ok: boolean }> {
  const preferences = validatePreferences(input);
  if (!preferences) return { ok: false };
  const store = await cookies();
  store.set(preferenceCookie, serializePreferences(preferences), {
    secure: true,
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    maxAge: preferenceMaxAge,
  });
  // Setting cookies requests Next's state-preserving RSC rerender. No second refresh.
  return { ok: true };
}
