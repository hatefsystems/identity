import type en from './en';
import type { CatalogShape } from '../i18n/types';
import { commonFa } from './common';
import { preferencesFa } from './preferences';
import { metadataFa } from './metadata';
import { authFa } from './auth';
import { portalFa } from './portal';
import { securityFa } from './security';
import { privacyFa } from './privacy';
import { errorsFa } from './errors';
import { adminFa } from './admin';
import { auditFa } from './audit';
import { integrityFa } from './integrity';
import { legalFa } from './legal';

const fa = {
  common: commonFa,
  preferences: preferencesFa,
  metadata: metadataFa,
  auth: authFa,
  portal: portalFa,
  security: securityFa,
  privacy: privacyFa,
  errors: errorsFa,
  admin: adminFa,
  audit: auditFa,
  integrity: integrityFa,
  legal: legalFa,
} as const satisfies CatalogShape<typeof en>;

export default fa;
