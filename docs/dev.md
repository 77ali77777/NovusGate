
## Control-plane image sistem paketləri (2026-10-15)
- `postgresql16-client` (Alpine 3.19): panel backup-ları üçün `pg_dump`. Versiya `postgres:16-alpine` serveri ilə eynidir; köhnə `pg_dump` yeni serveri dump etmir.

## Web: paketlər, tiplər və tərcümələr (2026-10-15)
- **Yeni paketlər** (istifadəçi təsdiqi ilə):
  - `i18next@23.16.8`, `react-i18next@15.7.4`;
  - `openapi-typescript@7.13.0` (dev).
- **Silinən paketlər** (kodda istifadə olunmurdu): `jszip`, `file-saver`, `@types/file-saver`, `@headlessui/react`.
- **API tipləri:**
  - `npm run gen:api` `server/internal/controlplane/api/rest/testdata/openapi.json`-dan `web/src/api/openapi.d.ts` yaradır;
  - `src/types/index.ts`-dəki API tipləri bu faylın alias-larıdır;
  - backend API dəyişəndə əvvəl `server/scripts/update-contracts.sh`, sonra `npm run gen:api` işə salınır;
  - `tests/openapi.test.mjs` köhnəlmiş faylı tutur (server qovluğu olmayanda test keçilir).
- **Tərcümələr:**
  - fayllar `web/src/i18n/locales/<az|en>/<namespace>.json`-dadır və avtomatik yüklənir (`src/i18n/index.ts`);
  - komponentdə `const { t } = useTranslation('<namespace>')`, başqa namespace üçün `t('ns:key')`;
  - ortaq sözlər `common` namespace-indədir;
  - toast başlıqları `meta.errorTitle`/`successTitle`-də `'toasts:...'` kimi açar şəklində ötürülür.
  - Dil seçimi yan menyudadır: əvvəl saxlanılan seçim, sonra brauzer dili (`az*` → az), sonra en.
  - `tests/i18n.test.mjs` bunları yoxlayır: iki dildə eyni açarlar, boş tərcümə yoxdur, bütün açarlar mövcuddur, `.tsx`-də hardcoded UI mətni qalmayıb.
  - Tək faylı yoxlamaq üçün: `node tests/i18nScan.mjs <fayllar>`.
  - Backend-in qaytardığı xəta mesajları İngiliscə qalır.
