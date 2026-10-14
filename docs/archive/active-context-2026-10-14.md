# Active Context arxivi — 2026-10-14 (P2b–P4c sessiyaları)

> `docs/active-context.md`-dən köçürülüb (400 sətir limiti).

### 2026-10-14: P2b planı
- **Nəticə:** `docs/superpowers/plans/2026-10-14-p2b-observability.md` yazıldı. 5 tapşırıq:
  1. `slog` logger (`LOG_FORMAT`, `LOG_LEVEL`);
  2. request log + panic recovery, ikiqat middleware-in aradan qaldırılması;
  3. `/health`: DB, WireGuard interfeysləri, firewall engine;
  4. runtime `fmt.Print*`/`log.Print*` → `slog` (mənbə skan edən testlə);
  5. sənədlər.

  Kod dəyişməyib.
- **Qərarlar:**
  - `/health` həmişə 200 qaytarır (kontrakt), `status: degraded` səbəbi `checks`-də göstərir;
  - log mətnləri dəyişmir (runbook grep-ləri işləyir);
  - CLI çıxışı `fmt` olaraq qalır.
- **Davam:** P2b icrası.


### 2026-10-14: P2b icra olundu
- **Nəticə:** Task 1–4 commit-ləndi:
  - `b1fda2b`: logger;
  - `2683b73`: request log + recover, ikiqat middleware silindi;
  - `a626459`: `/health`;
  - `bdbce97`: runtime log-ları `slog`-a keçdi, 101 çağırış.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → `ok`: `cmd/control-plane`, `api/rest`, `firewall`, `store`, `nft`, `logging`, `wireguard`;
  - `health` kontraktına yalnız `checks` əlavə olundu;
  - runbook mesajları dəyişməyib.
- **Davranış dəyişikliyi:**
  - `docker logs` JSON yazır (`LOG_FORMAT=text` ilə köhnə görünüş);
  - `/health`-ə `checks` əlavə olundu, `status` `degraded` ola bilər;
  - handler panic-i 500 cavabına çevrilir.
- **Final review (opus):** "With fixes", 1 Important (+2 Important-a qaldırıldı). Hamısı RED→GREEN ilə düzəldildi (`db48c2a`):
  - xəta və xəbərdarlıqlar düzgün səviyyədə yazılır;
  - net/http xətaları Error səviyyəsində yazılır.

  Minor-lar ledger-də. Qoruyucu testin əhatəsinin genişləndirilməsi P2c-yə saxlanılıb.
- **Davam:** P2c (WireGuard interfeysi, reconciler, expiry).


### 2026-10-14: P2c planı
- **Nəticə:** `docs/superpowers/plans/2026-10-14-p2c-reconciler-and-expiry.md` yazıldı. 7 tapşırıq:
  1. `Node.Active`, B11-in handler düzəlişləri;
  2. `ExpireNodes`;
  3. reconciler (shadow/enforce, expire addımı, DB-ni yenidən yoxlama);
  4. loop, trigger və `/health`;
  5. tək `Up`;
  6. logging qoruyucusu bütün `internal/`-u əhatə edir;
  7. sənədlər və runbook.

  Kod dəyişməyib.
- **Kodda təsdiqlənən B11 səbəbləri:**
  - `handleUpdateNode` DB statusuna baxır, lazy expiry isə statusu saxlamır;
  - `syncPeerAllowedIPs` vaxtı keçmiş peer-ləri bərpa edir;
  - `handleCreateNetwork` interfeysi ikinci dəfə `Up` edir (hər dəfə uğursuz olur).
- **Qərarlar:**
  - `WG_RECONCILER` default olaraq `shadow`-dur;
  - expire addımı hər iki rejimdə işləyir;
  - naməlum peer-lər silinmir, allowed-ips daraldılmır;
  - `wgN.conf`-a peer yazılması P2c-2-yə saxlanılır.
- **Davam:** P2c icrası.


### 2026-10-14: P2c icra olundu
- **Nəticə:** Task 1–6 commit-ləndi:
  - `e5d346a`: B11 handler-ləri;
  - `c61bc4a`: `ExpireNodes`;
  - `07e63f1`: reconciler;
  - `149af2f`: loop, trigger və `/health`;
  - `e179bbb`: tək `Up`;
  - `24a499d`: logging qoruyucusu bütün `internal/`-u əhatə edir.
- **Yoxlama:** `bash server/scripts/test-with-postgres.sh` → `ok`: `cmd/control-plane`, `api/rest`, `firewall`, `reconciler`, `store`, `nft`, `logging`, `models`, `wireguard`. Kontrakt snapshot-ları dəyişməyib.
- **Default rejimdə davranış dəyişikliyi:**
  - `WG_RECONCILER=shadow`: fərq yalnız log-a yazılır;
  - vaxtı keçmiş node 15 saniyə ərzində `expired` olur və peer-i silinir, panel açılmasa belə;
  - müddəti uzadılan node-un peer-i geri qayıdır;
  - yeni şəbəkə yaradılanda yalançı "Failed to bring up" xətası artıq yazılmır.
- **Yoxlanmayıb:** real WireGuard. `docs/runbooks/p2c-reconciler.md` staging-də icra olunmalıdır.
- **Final review (opus):** "With fixes", 2 Important (+1 Important-a qaldırıldı). Hamısı RED→GREEN ilə düzəldildi:
  - vaxtı keçmiş peer DB yenidən oxunandan sonra silinir;
  - uğursuz silinmə növbəti tick-də təkrarlanır;
  - node silinəndə əvvəl DB sətri, sonra peer silinir.

  Minor-lar ledger-də.
- **Davam:** P2c-2 (`wgN.conf` peer-ləri) və ya P2d.


### 2026-10-14: P2d-1 planı
- **Seçim:** P2c-2 əvəzinə P2d. Səbəb:
  - P5 (UI kit) P2d-nin OpenAPI və xəta formatından asılıdır;
  - P2c-2 installer-in `wg0.conf`-una toxunur, riskli olduğu üçün sonraya qalır.
- **P2d bölündü:**
  - P2d-1: vahid xəta + node validasiyası;
  - P2d-2: OpenAPI;
  - P2d-3: servis qatı.
- **Nəticə:** `docs/superpowers/plans/2026-10-14-p2d1-unified-errors.md` yazıldı. 4 tapşırıq. Kod dəyişməyib.
- **Qərar:** xəta body-si `{"error":{"code","message"}}` olur, `message` mətni dəyişmir. Web hər iki formanı oxuyur, Center xəta body-sini oxumur.
- **Davam:** P2d-1 icrası.


### 2026-10-14: P2d-1 icra olundu
- **Nəticə:** Task 1–3 commit-ləndi:
  - `761dbc6`: vahid xəta body-si;
  - `b450921`: sabit xəta kodları;
  - `8325276`: node validasiyası.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → hamısı `ok`;
  - kontrakt fərqləri yalnız xəta body-lərindədir, iki yeni 400 snapshot əlavə olunub;
  - web-də `data.error`-u birbaşa oxuyan yer yoxdur.
- **API dəyişikliyi:** xəta body-si `{"error":{"code","message"}}` oldu. Bu, istifadəçinin "davam" təsdiqi ilə edilib.
- **Final review (opus):** Critical və Important yoxdur, 5 minor var. P2d-2-də ediləcəklər:
  - iptables import-un `conflict` kodu dəqiqləşdirilməlidir;
  - `/api` üçün NotFound və MethodNotAllowed handler-ləri əlavə olunmalıdır;
  - release qeydi: web və control-plane birlikdə yenilənməli, brauzer yenidən yüklənməlidir.
- **Davam:** P2d-2 (OpenAPI).


### 2026-10-14: P2d-2 planı
- **Nəticə:** `docs/superpowers/plans/2026-10-14-p2d2-openapi.md` yazıldı. 4 tapşırıq:
  1. `/api` üçün JSON 404/405 və `firewall_engine_enforcing` kodu;
  2. OpenAPI sənədi Go tiplərindən reflection ilə qurulur, `GET /api/v1/openapi.json` ilə verilir, golden faylı var, route coverage testi var;
  3. hər kontrakt cavabı sənədə qarşı yoxlanılır;
  4. sənədlər.

  Kod dəyişməyib.
- **Davranış dəyişikliyi:**
  - naməlum `/api` yolu SPA əvəzinə 404 JSON qaytarır;
  - səhv method 405 JSON və `Allow` başlığı qaytarır;
  - yeni endpoint: `/api/v1/openapi.json` (auth tələb edir).
- **Davam:** P2d-2 icrası.


### 2026-10-14: P2d-2 icra olundu
- **Nəticə:** Task 1–3 commit-ləndi:
  - `ceb50b5`: `/api` JSON 404/405, `firewall_engine_enforcing`;
  - `02ced53`: OpenAPI sənədi, golden faylı və route coverage testi;
  - `56d5462`: kontrakt cavablarının sxemə qarşı yoxlanması.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → hamısı `ok`;
  - sənəd 64 əməliyyatı əhatə edir;
  - route coverage ilk cəhddə tam idi;
  - müvəqqəti sabotajla validasiyanın həqiqətən işlədiyi sübut olundu.
- **Davranış dəyişikliyi:**
  - naməlum `/api` yolu 404 JSON qaytarır;
  - səhv method 405 JSON və `Allow` başlığı qaytarır;
  - yeni endpoint: `/api/v1/openapi.json`.
- **Final review (opus):** 2 Important tapıldı, hər ikisi RED→GREEN ilə düzəldildi:
  - request sxemlərində məcburi sahə yoxdur;
  - method-suz route-lar da coverage testinə düşür.

  9 minor ledger-də (HEAD 405, 206 sənədsiz, query parametrləri, X-API-Key sxemi və s.).
- **Davam:** P2d-3 (servis qatı + DTO-lar) və ya P5.

### 2026-10-14: P2d-3 planı və icrası (DTO-lar)
- **Plan:** `docs/superpowers/plans/2026-10-14-p2d3-dtos.md` (`0ed60a6`). Servis qatı P2d-3-dən çıxarıldı (səbəb P2 spec §5-dədir).
- **Nəticə:** bütün request/response body-ləri adlı DTO-lardır. Commit-lər:
  - `b761eef`: host-dan asılı və firewall cavabları snapshot-larla donduruldu (38 yeni snapshot, `fail2banLogExists` seam-i);
  - `7f39a0e`: request DTO-ları;
  - `a94c608`: auth/node/system/health DTO-ları və health-in `null`/`false` qolları üçün snapshot;
  - `850fe63`: fail2ban DTO-ları, 206 sənədə əlavə olundu;
  - `63e201e`: VPN apply cavabı donduruldu;
  - `8d33280`: firewall v1/v2/VPN DTO-ları.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → 9 paket `ok`;
  - Task 2–5-də heç bir kontrakt snapshot-u dəyişmədi (`git diff --stat testdata/contract` boş);
  - health snapshot-u köhnə `handlers.go` (`7f39a0e`) ilə də keçdi;
  - OpenAPI-də ümumi `object` sxemləri: 57 → 1.
- **Davranış dəyişikliyi:** yoxdur. OpenAPI sənədi zənginləşdi, 206 əlavə olundu.
- **Snapshot-la qorunmayanlar:**
  - `POST /networks/{id}/sync` 200 cavabı (`wg show`-un seam-i yoxdur);
  - iptables rejimində v1 firewall cavabları (eyni açarlar nft yolunda qorunur).
- **Final review (opus):** wire formatında regressiya tapılmadı. 1 Important RED→GREEN düzəldildi (`ecf44bb`): POST /networks və node request-ləri response komponentlərinin `required` siyahısını miras alırdı, indi `NetworkInput`/`NodeInfoInput` ayrıdır (`TestRequestBodiesReachNoRequiredFields`). 2 minor ledger-də.
- **Davam:** P2c-2 və ya P5.


### 2026-10-14: P4a planı və icrası (sessiyalar)
- **Qərarlar (istifadəçi):** P4 master spec §4.3-dəki kimi icra olunur. P5 npm paketləri təsdiqləndi. P2c-2 ləğv olundu.
- **Bölgü:** P4a (sessiyalar), P4b (enrollment, nginx proxy, B10/B23), P4c (açarların şifrələnməsi, `user_id` audit).
- **Plan:** `docs/superpowers/plans/2026-10-14-p4a-sessions.md`.
- **Commit-lər:**
  - `d4f41fc`: `sessions` cədvəli (007) və store;
  - `0314302`: sessiya auth-u, login/logout, dəqiq açıq yollar;
  - `de0925b`: login limiti;
  - `8917c80`: parol yalnız sessiya istifadəçisi üçün (B15 → 400), digər sessiyaların ləğvi, web logout.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → 9 paket `ok`;
  - web (node:20 konteyneri): `tsc --noEmit` exit 0; biome sayı dəyişmədi (100/31).
- **Davranış dəyişikliyi:**
  - token istifadəçi başına verilir, restartda itmir;
  - logout serverdə sessiyanı ləğv edir;
  - login cavabı real istifadəçi adını qaytarır;
  - parol dəyişməsi başqa hesaba təsir edə bilmir (əvvəl edə bilirdi);
  - səhv köhnə parol 400 qaytarır;
  - 10 uğursuz login-dən sonra 429 qayıdır.
- **Təhlükəsizlik tapıntısı:** `web/.env` git-də izlənir və build zamanı bundle-a düşür. Bax `docs/security.md`.
- **Final review (opus):** Review Focus-un 5 bəndi düzgündür. 1 Important RED→GREEN düzəldildi (`d99d788`): paralel login-lər limiti keçirdi, indi cəhd bir kilid altında yoxlanılır və sayılır. 8 minor ledger-də (parol dəyişmə + sessiya ləğvi bir tranzaksiyada deyil, limiter yaddaşı, köhnə şərhlər və s.).
- **Davam:** P4b.

### 2026-10-14: P4b planı və icrası (enrollment və same-origin)
- **İstifadəçi qərarı:** install skripti paneldən kopyalanır, public port açılmır.
- **Plan:** `docs/superpowers/plans/2026-10-14-p4b-enrollment-and-proxy.md`.
- **Commit-lər:**
  - `ae025ba`: `enrollment_tokens` (008);
  - `f5f40a5`: tokenli install skripti, VPN üzərindən checkin, `wireguard_*` label filtri;
  - `637bd24`: nginx `/api` proxy-si, `X-Real-IP` yalnız loopback-dən, CORS çıxarıldı;
  - `532d37d`: web relative API, bundle-da açar yoxdur, kopyalanan install skripti.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → 9 paket `ok`;
  - `bash -n` skript testi işləyir (PASS);
  - `nginx:alpine`-da həm `nginx -t`, həm də image-in öz entrypoint-i ilə template render yoxlandı;
  - `docker compose config` keçdi;
  - web: `tsc` exit 0, biome 100/31 (dəyişməyib), `vite build` ok, bundle-da `X-API-Key`/`VITE_API_*` yoxdur.
- **Davranış dəyişikliyi:**
  - Linux install əmri tokenli skriptlə əvəz olundu;
  - checkin sessiyasız da (tokenlə) işləyir;
  - CORS başlıqları yoxdur, `OPTIONS` 405 alır;
  - `web/.env` build-də oxunmur.
- **P7-yə keçirildi:** B10 (Center `join-vpn`).
- **Final review (opus):** 3 Important və 1 Minor→Important düzəldildi:
  - proxy arxasında firewall-un lockout qoruması və audit `127.0.0.1` görürdü, indi `clientIP` işlədir (RED→GREEN);
  - compose-da web açarının default-u control-plane ilə eyniləşdi;
  - API açarı aktiv olanda enrollment testi əlavə olundu;
  - skriptə `umask 077` əlavə olundu (RED→GREEN).

  10 minor ledger-də.
- **Davam:** P4c.

### 2026-10-14: P4c planı və icrası (key şifrələnməsi, audit user)
- **Plan:** `docs/superpowers/plans/2026-10-14-p4c-key-encryption-and-audit.md`.
- **Commit-lər:**
  - `f56afd5`: `secretbox` (AES-256-GCM);
  - `214d02b`: 009 migration, şifrələnmiş key sütunu, `has_config`, key miqrasiyası/bərpası, audit `user_id`;
  - `351c122`: API key qaytarmır, config/QR/install key-i store-dan oxuyur, startup miqrasiyası, `keys-to-labels` əmri, audit-də istifadəçi;
  - `24df425`: web `has_config`, compose `NOVUSGATE_MASTER_KEY`, Center `MASTER_KEY` generasiyası.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → 10 paket `ok` (yeni `secretbox` daxil);
  - Center `node --test` → 27/27;
  - web `tsc` 0, biome 100/31.
- **Kontrakt dəyişikliyi:** 5 node snapshot-unda label-dən key çıxdı, `has_config` əlavə olundu.
- **Deploy qeydi:** mövcud quraşdırmalarda `MASTER_KEY` olmayana qədər key-lər `plain:` saxlanılır. Center-in update-i açarı əlavə edir.
- **Final review (opus):** 3 Important RED→GREEN düzəldildi:
  - server yaratma body-si label ilə real key-i əvəz etdirə bilirdi;
  - dəyişmiş və ya silinmiş master açar startup-da aşkar olunmurdu;
  - rollback faylı key-ləri silə bilirdi, indi qoruyucu var.

  6 minor ledger-də.
- **Davam:** P5 (UI kit). Vizual maket istifadəçinin təsdiqini tələb edir.

