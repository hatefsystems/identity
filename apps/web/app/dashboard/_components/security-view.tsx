'use client';

import { useTranslations } from 'next-intl';

import { PageHeading } from './controls';
import { PasskeysPanel } from './passkeys-panel';
import { RecoveryPanel } from './recovery-panel';

export function SecurityView() {
  const t = useTranslations();
  return (
    <>
      <PageHeading title={t('security.title')}>{t('security.description')}</PageHeading>
      <RecoveryPanel />
      <PasskeysPanel />
    </>
  );
}
