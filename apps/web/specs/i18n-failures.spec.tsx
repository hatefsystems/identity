import { useTranslations } from 'next-intl';
import { render, screen } from '../i18n/testing';
import { useMessage } from '../i18n/use-message';
import type { MessageDescriptor } from '../i18n/messages';

function MissingMessage() {
  const translate = useMessage();
  const descriptor: MessageDescriptor = {
    // @ts-expect-error Deliberately simulate runtime catalog drift; production keys are typed.
    key: 'private-fixture-missing-key',
    values: { value: 'private-fixture-interpolation' },
  };
  return <p>{translate(descriptor)}</p>;
}

it.each([
  ['en', 'This text is unavailable.'],
  ['fa-IR', 'این متن در دسترس نیست.'],
] as const)('sanitizes client catalog failures and provides a safe %s fallback', (locale, text) => {
  const warning = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  try {
    render(<MissingMessage />, { locale });
    expect(screen.getByText(text)).toBeTruthy();
    expect(warning.mock.calls).toEqual([['i18n', 'MISSING_MESSAGE']]);
    expect(document.body.textContent).not.toContain('private-fixture');
  } finally {
    warning.mockRestore();
  }
});

// This function is checked by the normal web:typecheck target, never invoked.
// ICU literal inference rejects incorrect arguments as well as unknown keys.
function typedArguments(t: ReturnType<typeof useTranslations<'audit'>>) {
  t('pageCount', { count: 2 });
  // @ts-expect-error Plural arguments require numbers, never preformatted digits.
  t('pageCount', { count: '۲' });
  // @ts-expect-error An unknown message cannot escape the English key contract.
  t('unregisteredMessage');
}
void typedArguments;
