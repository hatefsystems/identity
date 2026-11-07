import { registrationEn } from './registration';
import { commonEn } from './common';
import { preferencesEn } from './preferences';
import { metadataEn } from './metadata';
import { authEn } from './auth';
import { portalEn } from './portal';
import { securityEn } from './security';
import { privacyEn } from './privacy';
import { errorsEn } from './errors';
import { adminEn } from './admin';
import { auditEn } from './audit';
import { integrityEn } from './integrity';
import { legalEn } from './legal';

const en = {
  registration: registrationEn,
  common: commonEn,
  preferences: preferencesEn,
  metadata: metadataEn,
  auth: authEn,
  portal: portalEn,
  security: securityEn,
  privacy: privacyEn,
  errors: errorsEn,
  admin: adminEn,
  audit: auditEn,
  integrity: integrityEn,
  legal: legalEn,
} as const;

export default en;
