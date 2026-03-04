// ─── SCOG v1 자격증명 (admin / user / guest) ─────────────────────────────────
import adminV1 from '../../keys/v1/cred_3857_admin.json';
import userV1  from '../../keys/v1/cred_3857_user.json';
import guestV1 from '../../keys/v1/cred_3857_guest.json';

export const CREDENTIALS_V1 = { admin: adminV1, user: userV1, guest: guestV1 };

// ─── SCOG v2 자격증명 (admin / user / guest) ─────────────────────────────────
import adminV2 from '../../keys/v2/cred_3857_admin.json';
import userV2  from '../../keys/v2/cred_3857_user.json';
import guestV2 from '../../keys/v2/cred_3857_guest.json';

export const CREDENTIALS_V2 = { admin: adminV2, user: userV2, guest: guestV2 };

// ─── SCOG v3 자격증명 (admin / user / guest) ─────────────────────────────────
import adminV3 from '../../keys/v3/cred_3857_admin.json';
import userV3  from '../../keys/v3/cred_3857_user.json';
import guestV3 from '../../keys/v3/cred_3857_guest.json';

export const CREDENTIALS_V3 = { admin: adminV3, user: userV3, guest: guestV3 };

// ─── SCOG v4 자격증명 (admin / user / guest) ─────────────────────────────────
import adminV4 from '../../keys/v4/cred_3857_admin.json';
import userV4  from '../../keys/v4/cred_3857_user.json';
import guestV4 from '../../keys/v4/cred_3857_guest.json';

export const CREDENTIALS_V4 = { admin: adminV4, user: userV4, guest: guestV4 };

// ─── 하위 호환 (v1 기본) ─────────────────────────────────────────────────────
export const CREDENTIALS = CREDENTIALS_V1;

// ─── URL ─────────────────────────────────────────────────────────────────────
export const SCOG_V1_URL = 'http://localhost:8777/kompsat_3857.scog';
export const SCOG_V2_URL = 'http://localhost:8777/kompsat_3857.scog.tif';
export const SCOG_V3_URL = 'http://localhost:8777/kompsat_3857.v3.scog.tif';
export const SCOG_V4_URL = 'http://localhost:8777/kompsat_3857.v4.scog.tif';
export const COG_URL     = 'http://localhost:8777/kompsat_3857.tif';
export const SCOG_URL    = SCOG_V1_URL;  // 하위 호환

// ─── 공간 범위 (EPSG:3857) ───────────────────────────────────────────────────
export const EXTENT = [14103854.38, 4523240.64, 14105008.53, 4524219.68];
