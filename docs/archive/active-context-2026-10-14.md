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


<!-- Moved from docs/active-context.md on 2026-10-17 -->
### 2026-10-14: Təxirə salınmış bütün kiçik məsələlərin bağlanması
- **Tapşırıq:** "heç bir kiçik heç nə qalmasın". P1–P4 final review-larından qalan bütün `minor (deferred)` bəndləri transkriptdən toplandı.
- **Plan:** `docs/superpowers/plans/2026-10-14-deferred-minors-cleanup.md`. 8 batch (A–H), 75 bənd. Bəziləri əvvəlki fazalarda artıq həll olunmuşdu, onlar `verified-closed` kimi qeyd olunub. Üç bənd səbəbi yazılmaqla bağlanıb:
  - ölçülməmiş performans dəyişikliyi;
  - reboot-da timeout-ların yenidən başlaması;
  - `Allow`-da OPTIONS.
- **Commit-lər:** `a79dfc4`..`3639795` (təxminən 20 commit).
- **Final review (opus):** 3 Important bağlandı:
  - geniş route-un node peer-ini bloklaması;
  - checkin body-sinin limitsiz oxunması;
  - `v1` key-lərlə uyğunluq.

  Minor-ların hamısı ya düzəldildi, ya da səbəbi yazılmaqla bağlandı.
- **Yoxlamalar:**
  - Go: `test-with-postgres.sh` → 10 paket `ok` (`NFT_CHECK=1` daxil);
  - `nft-versions-check.sh` → 1.0.2, 1.0.6, 1.0.9 `NFT-VERSIONS-OK`;
  - `setup-firewall_test.sh` → `OK`;
  - Center → 36/36;
  - web → `tsc` 0, biome 99/31, `vite build` ok.
- **Davranış dəyişiklikləri** (ətraflı siyahı plan faylındadır):
  - HEAD dəstəyi;
  - debug 404-ün vahid xəta formatına keçməsi;
  - `/30`-dan kiçik şəbəkələrin rədd edilməsi;
  - API açarının simvol yoxlaması;
  - IPv6 və səhv portlu VPN qaydalarının rədd edilməsi;
  - Center-in `web/.env`-ə açar yazmaması;
  - Center-də formdakı dəyərlərin yoxlanması.
- **Davam:** P5 (UI kit). Vizual maketin təsdiqi lazımdır.

### 2026-10-14: Açıq qərarlar və hand-off hazırlığı
- **Tapşırıq:** "hamısını hazırla, düzəlişləri et, sonra report ver". İstifadəçinin qərarları:
  - Postgres yalnız loopback-də;
  - Allow IP admin portlarını açmır (§6b.4);
  - `/health` detalları yalnız auth ilə.
- **Commit-lər:** `3bb858c`, `5510657`, `2b374d8`, `8d4b700`, `b1320ea`, `1840033`.
- **Nəticə:**
  - `web/.env` və `NovusGate Center/.env` git-dən çıxarıldı və ignore olundu; `server/deployments/docker/.env` də ignore olunur;
  - compose `127.0.0.1:5432:5432`;
  - CI faylı `docs/ci/ci.yml`-dədir, kopyalanmalıdır;
  - Allow IP: nft guard sətri, iptables mangle `NOVUSGATE-ADMIN` (IPv4 və IPv6), API 400, Center uninstall IPv6 guard-ı silir;
  - `/health` anonim çağırışa `{status, version}` qaytarır.
- **P5 mockup:** https://claude.ai/artifact/T3qJP3n5KZBgunekRtTSi1. Dörd artboard:
  - Foundations;
  - Components (light/dark tweak, işləyən dialog, tablar, switch);
  - Nodes (light);
  - Nodes (dark).

  Təsdiq gözləyir.
- **Yoxlamalar:**
  - Go 10/10 (`NFT_CHECK=1`);
  - `NFT-VERSIONS-OK`;
  - shell `OK`;
  - Center 38/38;
  - real iptables (nft və legacy backend) guard-ı yükləyir, iki dəfə işə salındıqdan sonra bir jump qalır;
  - WSL kernel-ində legacy ip6tables `mangle` yoxdur, skript xəbərdarlıq verib davam edir.
- **İcra olunmayıb:**
  - real hostda port bloklanmasının funksional testi;
  - CI-nin GitHub-da işə salınması.
- **Davam:** mockup təsdiqi → P5 planı.

### 2026-10-14: P5 mockup tam paritetlə yenidən quruldu
- **Tapşırıq:** istifadəçi mockup-un natamam olduğunu dedi. Mockup hazırkı paneldəki hər səhifəni, modalı, detalı, redaktə/silmə/əlavə axınını və config pəncərəsini əks etdirməlidir, heç nə əskik olmamalıdır.
- **Nəticə:** https://claude.ai/artifact/T3qJP3n5KZBgunekRtTSi1. 40 lövhə; mənbə `web/src`-in sətir-sətir inventarıdır. Repo kodu dəyişməyib.
  - **Ümumi:** Login, Dashboard, Feedback/vəziyyətlər.
  - **Networks:** 3 lövhə.
  - **Nodes:** 11 lövhə; detal, modallar və Connect-in 5 tabı daxil.
  - **Firewall:** 10 lövhə.
  - **Fail2Ban:** 10 lövhə.
  - **Settings.**
- **Yoxlamalar:**
  - inventarın 10 mətni `grep` ilə kodda təsdiqləndi;
  - xəta mətnləri və config şablonu backend-dən götürüldü;
  - render yoxlanmayıb.
- **Davam:** istifadəçinin mockup-a rəyi və ya təsdiqi → P5 planı.
- **Klikləmə prototipi (eyni gün):** mockup klikləmə ilə gəzilən panelə çevrildi. Kanvas Login-dən açılır (`launch: focused`). 36 lövhə interaktivdir:
  - yan menyu səhifələrə keçid edir;
  - düymələr modallara keçid edir;
  - tablar tab səhifələrinə keçid edir;
  - Cancel/Save əvvəlki səhifəyə qaytarır.

  Skript 106 keçidi yoxladı, sınıq keçid 0. Brauzerdə klik yoxlanmayıb.
- **İstifadəçi qərarı:** yeni dizayna ehtiyac olmadı. Hazırkı frontend və dizayn saxlanılır, P5 və P6 ləğv olundu (master spec §2-də qeyd edilib).

### 2026-10-14: Frontend baqları (hazırkı dizaynda)
- **B13:** `EditNodeModal` "Keep Current" ilə açılır; tarix sahəsi yalnız "Set Custom Date" seçiləndə görünür, ona görə keçmiş müddət artıq saxlamağı bloklamır.
  - Müddət hesabı `web/src/lib/nodeExpiry.ts`-ə çıxarıldı.
  - `alert` əvəzinə xəta formanın içində göstərilir.
  - Keçmiş müddətlə yenidən aktivləşdirəndə xəbərdarlıq çıxır.
- **B15:** backend artıq 400 qaytarır (P4a); frontend yalnız 401-də çıxış edir. Kodda əlavə dəyişiklik lazım olmadı.
- **Səssiz xətalar:** `App.tsx`-də `MutationCache` hər mutasiya xətasını serverin mesajı ilə toast kimi göstərir, `meta.successTitle` olanda uğuru da göstərir. Yeni `components/Toaster.tsx` mövcud store bildirişlərini Layout-da göstərir.
  - Hook-lara `meta` əlavə olundu (`api/client.ts`: 20, `Fail2Ban.tsx`: 5).
  - Formada xətanı özü göstərən mutasiyalar `inlineError` ilə işarələndi: create network, parol, istifadəçi yaratma.
  - Close Port-un ikiqat `alert`-i çıxarıldı.
- **Testlər:** `web/tests/nodeExpiry.test.mjs` (8). `npm test` Node 22 `--experimental-strip-types` ilə işləyir, yeni paket yoxdur; `docs/ci/ci.yml` web job-u Node 22-yə keçdi.
- **Yoxlamalar:**
  - Node 22: `tsc` OK, `npm test` 8/8, `vite build` OK, bundle-da açar yoxdur;
  - biome: 98 xəta / 31 xəbərdarlıq, əvvəl 99 / 31 idi; yeni xəta yoxdur, `package.json`-un sonuna sətir əlavə olundu.
- **Brauzerdə yoxlanmayıb:** toast-ların görünüşü, Edit Node axını.

### 2026-10-14: P3c — Firewall "Advanced (nftables)" tabı (hazırkı dizaynda)
- **Nəticə:** Firewall səhifəsinə yeni tab əlavə olundu (`pages/Firewall/AdvancedTab.tsx`). Mövcud v2 API-dən istifadə edir, backend dəyişməyib. Bölmələr:
  - engine statusu: rejim, qorunan SSH portları, internet interfeysi, host xətası;
  - gözləyən dəyişiklik: geri sayım və "Confirm change"; təsdiq olunmasa host özü geri qaytarır;
  - servislər (port aralığı, mənbələr, interfeys);
  - IP qaydaları: block/allow, portlar, bitmə vaxtı, mənşə;
  - port yönləndirmə;
  - full tunnel (egress), sidebar-da seçilmiş şəbəkənin node-ları üçün;
  - nft ruleset önizləməsi.

  `nft` rejimindən başqa rejimlərdə və təsdiq gözləyən dəyişiklik varkən dəyişiklik düymələri bağlıdır; önizləmə hər rejimdə işləyir.
- **Kod:** `api/client.ts`-ə 10 v2 metodu və hook əlavə olundu. State gözləyən dəyişiklik varkən 5 s-dən bir, əks halda 30 s-dən bir yenilənir. Tiplər `types/index.ts`-dədir; `pending` `null` ola bilər. Köməkçilər `lib/firewallV2.ts`-dədir.
- **Testlər:** `web/tests/firewallV2.test.mjs`, 4 test, əvvəl düşdü sonra keçdi; cəmi 12/12. `tsc` OK, biome 98/31 (yeni xəta yoxdur), `vite build` OK.
- **P3c-dən qalanlar** (P3 spec §5): Live (sayğaclar, drop log-u, conntrack) və History (diff, rollback) üçün backend endpoint-i yoxdur. Bunlar backend işi tələb edir. *(2026-10-15: hər ikisi edildi, aşağıya baxın.)*
- **Brauzerdə və real nft hostda yoxlanmayıb.**

### 2026-10-14: P7 — NovusGate Center
- **Commit-lər:** `0ff8d86`, `62a3601`, `2218adf`, `c7236cc`, `e33821e`.
- **`servers.json`:** `lib/store.js` hər dəyişiklikdə faylı yenidən oxuyur və atomik yazır (tmp + rename). Uzun install sonda köhnə məlumatla yazıb başqa dəyişiklikləri silmir. Korlanmış fayl boş siyahı ilə əvəz olunmur.
- **Bir server üçün eyni anda bir iş:** `lib/jobs.js`, digər iş gedərkən 409 qaytarır. Install, update, reinstall, migrate, uninstall, prune və join-vpn-ə aiddir.
- **Paralel arxiv:** hər install öz müvəqqəti arxivini yaradır (`lib/archive.js`, `execFile`).
- **Non-root SSH istifadəçisi:** bağlantıdakı bütün əmrlər `sudo -n` ilə işləyir (`lib/ssh.js connect`), Fail2Ban modulu da daxil.
- **Terminal:** key passphrase ötürülür; shell brauzerin ölçüsü ilə açılır və resize-ı izləyir (səhifə əvvəl resize göndərmirdi).
- **B10 Join VPN:** paneldəki install skripti (Nodes → Connect → Linux) yapışdırılır və 0700 fayl kimi yüklənir, ona görə token `ps`-də görünmür. Skript root kimi işləyir, sonra silinir, çıxış SSE ilə gəlir. Səhifədə Join VPN düyməsi və modal əlavə olundu.
- **Skriptlər:** `compose()` Compose v2-dən istifadə edir, v1 yalnız fallback-dir. `apt_get()` dpkg lock-u 10 dəqiqəyə qədər gözləyir. `setup-firewall.sh` də v2-yə keçdi.
- **Uninstall:**
  - artıq qlobal `docker system prune` və bütün cədvəllərin flush-u yoxdur;
  - yalnız NovusGate silinir: konteynerlər, volume-lar, yalnız qurduğu image-lər (`--rmi local`), wg interfeysləri (DB, PostUp imzası, wg0), INPUT, `NOVUSGATE-ADMIN`, nft cədvəli, boot unit, rollback timer, fail2ban jail faylı, `/etc/novusgate`, `/var/lib/novusgate`.
- **Update:**
  - dəyişiklikdən əvvəl backup: kod və `.env`, `/etc/wireguard`, `pg_dump` → `/var/backups/novusgate/update-<vaxt>` (son 5 saxlanılır);
  - xəta (`trap ERR`) və ya `/health` 1 dəqiqədə cavab verməsə avtomatik rollback; DB avtomatik geri qaytarılmır (miqrasiyalar yalnız genişləndirir).
- **Testlər:** Center 71/71 (yeni: store, jobs, archive, ssh, join, run, scripts); shell `OK`.
- **İcra olunmayıb:** real serverdə install, update, rollback, uninstall və join-vpn; brauzerdə terminal.
- **Spec §4.5-dən edilməyənlər:**
  - skriptlərin `scripts/*.sh` fayllarına çıxarılması: refaktor, istifadəçiyə görünən faydası yoxdur; `shellQuote` injection-u artıq bağlayır;
  - job log-larının saxlanması: install çıxışında parollar var, saxlamaq təhlükəsizlik qərarıdır;
  - tam preflight (OS, disk).

