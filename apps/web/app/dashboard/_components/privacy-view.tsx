'use client';

import { useTranslations } from 'next-intl';
import type { Locale } from '../../../i18n/config';
import { useDisplayPreferences } from '../../../i18n/provider';

import { Button, Label } from '@hatef/ui';
import { useId, useRef, useState } from 'react';
import { errorMessage } from '../../_lib/portal/errors';
import { controlClass, PageHeading, Panel } from './controls';
import { usePortal } from './portal-provider';
import { StepUpDialog } from './step-up-dialog';

export function PrivacyView() {
  const t = useTranslations();
  const preferences = useDisplayPreferences();
  const notificationLocale = useRef<Locale>(preferences.locale);
  const { profile, deleteAccount } = usePortal();
  const [acknowledged, setAcknowledged] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const opening = useRef(false);
  const id = useId();

  return (
    <>
      <PageHeading title={t('privacy.title')}>{t('privacy.description')}</PageHeading>
      <Panel title={t('privacy.deleteTitle')} id={`${id}-delete`}>
        <h3 id={`${id}-consequences`} className="font-semibold">
          {t('privacy.before')}
        </h3>
        <ul className="list-disc space-y-3 ps-5 text-sm leading-relaxed">
          <li>{t('privacy.deactivate')}</li>
          <li>{t('privacy.window')}</li>
          <li>{t('privacy.mail')}</li>
          <li>{t('privacy.reserved')}</li>
        </ul>
        <p className="text-sm leading-relaxed">{t('privacy.erasureWarning')}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{t('privacy.verification')}</p>
        {!profile.deletion_enabled && (
          <p role="status" className="rounded-md border bg-muted/40 p-4 text-sm leading-relaxed">
            {t('privacy.disabled')}
          </p>
        )}
        <div className="flex items-start gap-3">
          <input
            id={`${id}-acknowledge`}
            type="checkbox"
            checked={acknowledged}
            disabled={!profile.deletion_enabled || confirm}
            onChange={(event) => setAcknowledged(event.target.checked)}
            aria-describedby={`${id}-acknowledgement-hint`}
            className="mt-3 size-5 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
          />
          <Label
            htmlFor={`${id}-acknowledge`}
            className="flex min-h-11 items-center text-sm leading-relaxed"
          >
            {t('privacy.acknowledge')}
          </Label>
        </div>
        <p id={`${id}-acknowledgement-hint`} className="text-sm text-muted-foreground">
          {t('privacy.acknowledgeHint')}
        </p>
        <Button
          type="button"
          variant="destructive"
          className={controlClass}
          disabled={!profile.deletion_enabled || !acknowledged || confirm}
          onClick={() => {
            if (!profile.deletion_enabled || !acknowledged || opening.current) return;
            opening.current = true;
            notificationLocale.current = preferences.locale;
            setConfirm(true);
          }}
        >
          {t('privacy.delete')}
        </Button>
      </Panel>
      <Panel title={t('privacy.remains')} id={`${id}-retention`}>
        <details className="rounded-md border px-3">
          <summary className="min-h-11 cursor-pointer py-3 text-sm">
            {t('privacy.policy')}
          </summary>
          <p className="pb-3 text-sm leading-relaxed text-muted-foreground">
            {t('privacy.retention')}
          </p>
        </details>
      </Panel>
      {confirm && (
        <StepUpDialog
          title={t('privacy.confirm')}
          description={t('privacy.confirmDescription')}
          mode="webauthn-only"
          onAuthorized={(grant, signal) => deleteAccount(grant, signal, notificationLocale.current)}
          actionError={(failure) => errorMessage(failure, 'webauthn')}
          onCancel={() => {
            opening.current = false;
            setConfirm(false);
            setAcknowledged(false);
          }}
        />
      )}
    </>
  );
}
