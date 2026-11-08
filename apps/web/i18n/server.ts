import 'server-only';
import { cookies, headers } from 'next/headers';
import {
  defaultPreferences,
  hasDuplicatePreferenceCookie,
  parsePreferences,
  preferenceCookie,
} from './config';

export async function getDisplayPreferences() {
  const [store, requestHeaders] = await Promise.all([cookies(), headers()]);
  // RequestCookies collapses duplicate names; check the original header first.
  if (hasDuplicatePreferenceCookie(requestHeaders.get('cookie'))) return { ...defaultPreferences };
  return parsePreferences(store.get(preferenceCookie)?.value);
}
