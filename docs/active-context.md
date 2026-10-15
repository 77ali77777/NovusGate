# Active Context

## Son Sessiya
- **2026-10-13 sessiyaları** (P1, P3, P2a) `docs/archive/active-context-2026-10-13.md` faylına köçürülüb.

- **2026-10-14 sessiyaları (P2b–P4c)** `docs/archive/active-context-2026-10-14.md` faylına köçürülüb.

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

### 2026-10-15: P8 — yeni imkanlar
- **İstifadəçi qərarları:**
  - full tunnel `0.0.0.0/0` + DNS 1.1.1.1;
  - backup yalnız manual;
  - bildirişlər Telegram bot ilə;
  - trafik 5 dəqiqəlik nümunə ilə, 30 gün saxlanır.
- **Full tunnel (`c82b56b`):** egress-i açıq olan node-un config-i `AllowedIPs = 0.0.0.0/0` və `DNS = 1.1.1.1` alır (`rest.tunnelRouting`, `wireguard.GeneratePeerConfigDNS`).
- **Trafik tarixçəsi (`1bcae2a`):**
  - `traffic.Sampler` 5 dəqiqədən bir işləyir, köhnə nümunələr 30 gündən sonra silinir; miqrasiya 010;
  - `GET /nodes/{id}/traffic?range=24h|7d|30d`;
  - NodeDetail-də `TrafficHistoryCard` (recharts).
- **Backup-lar (`846fd9d`):**
  - `backup.Service` `pg_dump` və `/etc/wireguard`-ı `.tar.gz`-yə yığır, `/var/backups/novusgate/panel`-ə yazır;
  - `/api/v1/backups` CRUD;
  - Settings-də `BackupsCard`;
  - image-ə `postgresql16-client` əlavə olundu; restore addımları `deployment.md`-dədir.
- **Telegram bildirişləri (`8812781`, `3b64cd0`):**
  - `notify` paketi: sender, dedupe edən növbə, `PeerWatcher`, `Fail2BanWatcher`;
  - miqrasiya 011: token `MASTER_KEY` ilə möhürlənir və qaytarılmır;
  - `/api/v1/notifications/{settings,test}`;
  - firewall dəyişikliyi middleware-i və reconciler `OnExpired` hook-u;
  - Settings-də `NotificationsCard`.
- **Yoxlamalar:**
  - Go `test-with-postgres.sh` → 13 paket `ok`, `go vet` OK;
  - web: `tsc` OK, `npm test` 17/17, biome 97/31 (baseline), `vite build` OK.
- **İcra olunmayıb:**
  - real Telegram bot ilə göndəriş;
  - real serverdə full tunnel ilə internet çıxışı;
  - `pg_dump`-dan restore;
  - brauzerdə kartların görünüşü.
- **Fail2Ban log rotasiyası:** `fail2ban.log` konteynerə tək fayl kimi mount olunub. Bu, sonradan `copytruncate` ilə həll olundu (aşağıdakı sessiyaya baxın).

### 2026-10-15: Qalan işlər — Fail2Ban rotasiyası, Center, Firewall Live/History
- **İstifadəçi qərarları:**
  - qalan dörd işin hamısı edilir;
  - Fail2Ban log-u üçün `copytruncate`;
  - Center iş log-ları saxlanmır.
- **Fail2Ban rotasiyası (`ba39d85`):** `setup-firewall.sh` `/etc/logrotate.d/fail2ban`-a marker sətri və `copytruncate` əlavə edir (təkrar işə salınanda yenidən əlavə etmir). Center uninstall bu iki sətri silir.
- **Center ilkin yoxlaması (`72307f1`):** Install hosta toxunmazdan əvvəl OS, arxitektura, RAM, disk, portlar və systemd-ni yoxlayır, uyğun gəlməsə exit 5 ilə dayanır.
- **Center skriptləri fayllarda (`36041ec`):** bash `NovusGate Center/scripts/*.sh`-dədir, `lib/scripts.js` `@@NAME@@` yerlərini doldurur. Çatışmayan və ya istifadə olunmayan placeholder xəta verir. Generasiya olunan skriptlər üç config üçün əvvəlki ilə bayt-bayt eynidir.
- **Firewall Live:**
  - `75f4d53`: ruleset `dropped_v4/v6` dinamik set-lərini doldurur;
  - `18b6375`: snapshot yeniləndi;
  - `ffd7188`: `GET /firewall/v2/live` — counter-lər, drop olunan mənbələr, conntrack.
- **Firewall History (`0777603`):** miqrasiya 012 `fw_history`, tarixçə yazılışı, `Describe`/`DiffLines`, `GET /firewall/v2/history`, `POST …/history/{id}/restore` (təsdiqlə).
- **UI (`cf31aee`):** Firewall-da "Live" və "History" tabları.
- **Yoxlamalar:**
  - Go: `test-with-postgres.sh` → 14 paket `ok`, `nft-versions-check.sh` → `NFT-VERSIONS-OK`;
  - shell: `setup-firewall_test.sh` → `OK`;
  - Center: 81/81;
  - web: `tsc` OK, 20/20, biome 96/31, `vite build` OK.
- **İcra olunmayıb:**
  - real hostda dinamik set-in dolması və 5.4 kernel-də yüklənməsi; `nft -c` WSL kernel-ində yoxlanıb;
  - real logrotate;
  - preflight real serverdə;
  - brauzerdə tablar.
- **Müstəqil review (opus):** 1 Important və 5 Minor tapıldı.
  - Düzəldildi (`ca8d628`, `a2aa734`):
    - uğursuz install-dan sonra wg0 51820-də qalırdı və retry preflight-da dayanırdı;
    - `install.sh`-də xam CR baytı;
    - baseline və dəyişiklik ayrı insert-lərlə yazılırdı;
    - history yazısında timeout yox idi;
    - restore təsdiqi fail2ban ban-larının da silindiyini demirdi.
  - Conffile riski `9eedb44`-də həll olundu: fail2ban öz qovluğuna yazır.

### 2026-10-15: Fail2Ban öz log qovluğu, Network Policies, System Rules
- **İstifadəçi qərarları:**
  - Fail2Ban üçün öz log qovluğu (conffile riskinə görə);
  - matris və System Rules edilir.
- **Fail2Ban (`9eedb44`):**
  - fail2ban `/var/log/novusgate/fail2ban.log`-a yazır (`fail2ban.d` drop-in, recidive `logpath`, öz logrotate faylı);
  - compose qovluğu mount edir; paketin conffile-ına toxunulmur, köhnə copytruncate silinir;
  - Center uninstall hamısını geri qaytarır.
  - Real fail2ban ilə (ubuntu:24.04) yoxlandı: logtarget dəyişdi, `logrotate -d` təmizdir, conffile dəyişməyib.
- **UI (`2069c84`):**
  - VPN Rules tabında şəbəkə×şəbəkə matrisi (allow/deny/partial, klik qayda modalını açır);
  - System Rules tabı (preview-dan, izahlarla).
- **Yoxlamalar:** Go 14 paket `ok`, shell `OK`, Center 83/83, web 27/27, `tsc` OK, `vite build` OK, biome 94/31.
- **İcra olunmayıb:** brauzerdə tablar; real serverdə Update ilə log köçürülməsi.

### 2026-10-15: İkinci review (9eedb44, 2069c84) və düzəlişlər
- **Review (opus):** 3 Important və 5 Minor tapıldı. Düzəldildi:
  - **F3, istifadəçi təsdiqi ilə (`5ac6b9a`):** iptables rejimində VPN drop/reject qaydaları wg ACCEPT-lərindən sonra gəldiyi üçün heç vaxt işləməmişdi. İndi `NOVUSGATE-VPN` zəncirindədirlər, FORWARD-ın başından çağırılırlar. Paket testi ilə yoxlandı.
  - **F2 (`5ac6b9a`):** qayda yaradılanda nft rejimində reconcile çağırılmırdı.
  - **F1, F6, F7 (`7396ddf`):**
    - matris backend-də hesablanır (`GET /firewall/policy-matrix`), node və custom ünvanlar həll olunur;
    - loading zamanı rejim təxmin edilmir;
    - klikdən yaranan qaydanın priority-si və ad uzunluğu düzəldi.
  - **F8 və F4 (`a48b55a`):**
    - recidive üçün `backend = auto` və log faylı əvvəlcədən yaradılır; bu olmadan fail2ban recidive ilə qalxmırdı (real 24.04-də yoxlandı);
    - update rollback log köçürməsini geri qaytarır.
  - Qalan: F5 — operatorun öz `logtarget`-i (`fail2ban.local`) drop-in ilə əvəz olunur, sənəddə qeyd var.
- **Yoxlamalar:** Go 14 paket `ok`, shell `OK`, Center 84/84, web 24/24, `tsc` OK, `vite build` OK.

### 2026-10-15: Center iş log-ları və P5/P6-nın yenidən analizi
- **İstifadəçi qərarları:**
  - Center log-ları `data/jobs`-da, maskasız və limitsiz saxlanılır;
  - P5/P6-dan bu işlər hazırkı dizaynda edilir: ErrorBoundary, paket təmizliyi, Audit, Sessions, Network detalı, Topologiya, i18n (az/en), OpenAPI tipləri.
- **Commit-lər:**
  - Center iş log-ları: `ef72424`;
  - ErrorBoundary və istifadə olunmayan 4 paketin silinməsi: `d57700e`;
  - audit middleware və sessiyalar (backend): `5e4f5f9`; UI: `ba7bb94`;
  - Network detalı və Topologiya: `b619180`;
  - OpenAPI-dən generasiya olunan tiplər: `9979f60`, `ea62479`;
  - i18n: `a685d0f` (12 namespace, səhifələri 5 paralel agent çevirdi);
  - matris izahlarının tərcüməsi: `ad3b99d`.
- **Yoxlamalar:**
  - Go 14 paket `ok`;
  - Center 88/88;
  - web 39/39 (OpenAPI drift testi daxil), `tsc` OK, `vite build` OK, biome 74/31 (əvvəl 91);
  - brauzer (vite preview + Playwright): login və Firewall Azərbaycanca göstərilir, dil keçidi səhifəni yeniləmədən işləyir.
- **Qeyd:** `registerNotificationRoutes` `8812781`-dən bəri iki dəfə çağırılırdı, `5e4f5f9`-da düzəldildi.
- **İcra olunmayıb:** brauzerdə real backend ilə bütün səhifələr; real serverdə Center log-ları.

### 2026-10-15: P9a — node qrupları və panel rolları (branch `feature/p9-control`)
- **Tapşırıq:** spec `docs/superpowers/specs/2026-10-15-p9-control-design.md` (`598e09d`), P9a mərhələsi.
- **Commit-lər:**
  - qruplar (013, store, nft set-ləri, iptables genişlənməsi, REST): `8d7867b`;
  - rollar (014, roleMiddleware, `/auth/me`, `/users/{id}/role`, son admin qoruması): `1ceb721`;
  - UI (Qruplar səhifəsi, VPN qaydasında qrup, istifadəçi rolları, rola görə düymələr): `6cfab62`.
- **Yoxlamalar:** Go 14 paket `ok`; web 41/41 (OpenAPI drift daxil), `tsc` OK, `vite build` OK, i18nScan 0, biome 73/30 (əvvəl 75).
- **İcra olunmayıb:** brauzerdə real backend ilə; real serverdə nft qrup set-ləri.
- **Review (opus) və düzəlişlər:**
  - Important: son admin yoxlaması UUID-in yazılışı ilə keçilirdi (böyük hərfli ID yeganə admini silirdi); GET-lər default olaraq viewer-ə açıq idi → `67beb5c`;
  - UI: Nodes-da qrup sütunu/filtr, bütün dəyişdirmə düymələri rola görə, cache və modal düzəlişləri → növbəti commit;
  - real olmayan tapıntı: ünvansız qrup üzvü (`virtual_ip NOT NULL`);
  - təxirə salınan minor: qrup set adlarının sürüşməsi (History diff səs-küyü), session ilə checkin operator üçün admin tələb edir.
- **Davam:** P9b.

### 2026-10-15: P9b — limit profilləri (sürət, bağlantı, vaxt cədvəli)
- **Commit-lər:** nft qatı `e6c4a81`; DB/store/engine `e9ed0f3`; REST `1a9b122`; real trafik testi və burst düzəlişi `6812061`; matris `10b40e8`; UI `2c1eb43`.
- **Ölçmə ilə tapılanlar:**
  - nft `meta hour`-u prosesin TZ-i ilə çevirir (Bakı 08:00 → 04:00 UTC), `meta day`-i çevirmir → hər nft TZ=UTC ilə, pəncərələr Go-da UTC-yə çevrilir, DST anında reload;
  - kernel bucket-i `rate+burst` tutur: burst=rate ilk saniyədə 2× buraxırdı (8 Mbit → 10.9) → burst `max(rate/4, 16 KiB)`.
- **Yoxlamalar:** Go 14 paket `ok`; `nft-versions-check` (1.0.2/1.0.6/1.0.9, limit snapshot daxil) OK; `limits-functional-check.sh`: upload 7.88/8, download 3.90/4 Mbit/s, 4-cü bağlantı atılır, cədvəldən kənar bloklanır; TZ düzəlişi söndürüləndə test düşür (mutasiya); web 48/48, tsc, vite, i18nScan 0, biome 73.
- **İcra olunmayıb:** brauzerdə real backend; real serverdə (minimum Ubuntu 22.04, kernel 5.15).
- **Review (opus) və düzəlişlər** (`142925d`, `357a65e`):
  - Important: reload-dan sonra bağlantı limiti ikiqat olurdu (real trafiklə təkrarlandı), qrup silmə/ad dəyişmə limitləri yenidən tətbiq etmirdi;
  - Minor düzəldildi: gecə pəncərəsinin DST quyruğu, GRO üçün 64 KiB burst, lock altında DB sorğusuna 5 s limit, bağlamaların paralel sorğuları (row lock, testsiz), iptables rejimində node detalında qeyd, təkrarlanan React key-ləri;
  - qalan: models.go-dakı gofmt hizalaması (yalnız boşluq).
- **Davam:** P9c (kvota). Qeyd: nümunələr 30 gün saxlanılır, ona görə kvota sayğacı `node_quota_state`-də artımla aparılacaq.

### 2026-10-15: P9c — trafik kvotası
- **Commit-lər:** backend `08f8ec5` (016, quota paketi, Tracker, quota_v4, API, bildiriş); UI `a434f65`.
- **Ruling:** spesifikasiya kvotanı nümunələrdən cəmləməyi deyir; nümunələr 30 gün saxlanılır, ay 31 gün ola bilər → sayğac `node_quota_state`-də artımla aparılır.
- **Yoxlamalar:** Go 15 paket `ok` (quota: dövr sərhədi, Bakı gecə yarısı, sayğac sıfırlanması, 80/100%, yeni dövr, nümunəsiz rollover, sıfırlama; tracker; nft quota_v4; engine blok; REST); `nft-versions-check` OK; web 53/53, tsc, vite, i18nScan 0, biome 73.
- **İcra olunmayıb:** real serverdə kvota (WireGuard sayğacları ilə); brauzer; Telegram-a real göndəriş.
- **Review (opus) və düzəlişlər** (`3551916` + UI): Important: kvota artırılanda blok qalırdı; kvotasız dövrdən qalan baseline trafiki sayırdı; paralel "sıfırla" itə bilərdi; sıfırlama günü/TZ dəyişəndə sayğac silinirdi (017 `period_end`). Minor düzəldildi: iptables mətni, dövr sonunda reload, sampler xətasında rollover, throttle ≤ profil, UI validasiyası, bildiriş açarı, reset 204. Təxirə salındı (sənəddə): dövr sərhədində control-plane işləməyəndə trafikin bölünməsi, sayğac sıfırlanma heuristikası.
- **Davam:** P10a (server idarəsi).

### 2026-10-15: Qalan işlər, köhnə paketin review-u, brauzer testi
- **Qalan işlər:** sabit nft set adları (018 `set_no`, `e8fb974`); operator sessiya ilə checkin; kvota dövr sərhədində trafikin zamana görə bölünməsi (`37ca06c`).
- **Köhnə paketin review-u** (audit, sessiyalar, Center log-ları, i18n, OpenAPI tipləri): audit 429 spam + 180 gün saxlanma (`37ca06c`); Center log-ları best-effort və serverlə silinir (`a6b431b`); `strictNullChecks` açıldı, 33 null yeri düzəldildi (`b149f03`); topologiyada sürükləmə, ErrorBoundary `location.key`, audit-də konkret path, Live rəqəmləri dilə görə (`5354ed5`). Təxirə: login yazısında username, audit cursor bərabər vaxtda, Center log siyahısının sürəti, viewer öz digər sessiyalarını bitirə bilmir, modalda `role=dialog` yoxdur.
- **Minimum host:** Ubuntu 22.04 / Debian 12 (`323c177`).
- **Brauzer testi (real backend, izolə stack, NET_ADMIN, privileged yox):** giriş, Qruplar, Limitlər (az/en), Audit path, topologiya sürükləmə + 30 s sonra yer saxlanılır, Settings rolları, viewer rolunda gizlənən düymələr — hamısı işlədi. **Tapılan bug:** alpine image-də tzdata yox idi, UTC-dən başqa saat qurşağı 400 verirdi → `time/tzdata` (`f65bce3`). Bir dəfə gözləmə zamanı səhifə `/firewall`-a keçdi, təkrarlanmadı (stack restartı zamanı köhnə tab ehtimalı).

## Son Dəyişikliklər
| Tarix | Dəyişiklik | Fayllar | Səbəb |
|---|---|---|---|
| 2026-10-15 | Qalan işlər + köhnə paket review + brauzer testi: set_no, audit 429/retention, Center log, strictNullChecks, tzdata | migrations 018, store, firewall, rest, Center joblog, web, main.go | review və brauzer testi · `e8fb974`..`f65bce3` |
| 2026-10-15 | P9c: aylıq trafik kvotası (blok/yavaşlatma, 80% xəbərdarlıq, sıfırlama) | quota/, migrations 016, store/limits.go, firewall/limits.go, netctl/nft, traffic.go, main.go, web Limits/Nodes/Settings | P9 spec · `08f8ec5`, `a434f65` |
| 2026-10-15 | P9b: limit profilləri (nft meter/ct count/cədvəl, 015, API, Limits tabı) | netctl/nft, firewall/{limits,preview,engine,matrix}.go, store/limits.go, rest/limits_handlers.go, setup-firewall.sh, web Limits | P9 spec · `e6c4a81`..`2c1eb43` |
| 2026-10-15 | P9a review: son admin UUID, default-deny GET, rola görə UI, Nodes qrup filtri | store/roles.go, rest/roles.go, web/src/pages/** | review · `67beb5c` + UI commit |
| 2026-10-15 | P9a: node qrupları, panel rolları, UI | store/{groups,roles}.go, migrations 013/014, rest/{groups_handlers,roles}.go, netctl/nft, firewall/build.go, web/src/pages/Groups, Settings, Firewall | P9 spec · `8d7867b`, `1ceb721`, `6cfab62` |
| 2026-10-15 | i18n (az/en), OpenAPI tipləri, Audit, Sessions, Network detalı, Topologiya, ErrorBoundary, Center iş log-ları | web/src/**, server/.../rest/audit_handlers.go, store/{audit,sessions}.go, NovusGate Center/lib/joblog.js | P5/P6 yenidən analiz · `ef72424`..`ad3b99d` |
| 2026-10-15 | iptables VPN qaydaları öz zəncirində (drop/reject işləyir), create sync edir; matris backend-də; recidive və rollback düzəlişləri | firewall_handlers.go, firewall/matrix.go, api/rest/firewall_matrix.go, setup-firewall.sh, Center update/uninstall, web PolicyMatrix | ikinci review · `5ac6b9a`, `7396ddf`, `a48b55a` |
| 2026-10-15 | Network Policies matrisi, System Rules tabı | web/src/lib/{policyMatrix,systemRules}.ts, pages/Firewall/{PolicyMatrix,SystemRulesTab,Firewall}.tsx | P3c qalığı · `2069c84` |
| 2026-10-15 | Fail2Ban `/var/log/novusgate`-a yazır (conffile-a toxunulmur) | setup-firewall.sh (+test), compose, fail2ban_parse.go, main.go, Center uninstall/fail2ban.js | review: conffile riski · `9eedb44` |
| 2026-10-15 | Firewall Live (counter-lər, drop olunan mənbələr, conntrack) və History (diff, restore) | netctl/nft/{compile,live}.go, netctl/conntrack, firewall/{live,history,describe,engine}.go, store/firewall_history.go + 012, api/rest/firewall_{live,history}.go, web Firewall Live/History tabları | P3c qalığı · `75f4d53`..`cf31aee` |
| 2026-10-15 | Center: preflight, skriptlər `scripts/*.sh`-də | NovusGate Center/{lib/scripts.js,lib/run.js,scripts/,test/} | spec §4.5 · `72307f1`, `36041ec` |
| 2026-10-15 | Fail2Ban log-u rotasiyadan sonra da oxunur (copytruncate) | setup-firewall.sh (+test), Center scripts | bildiriş məhdudiyyəti · `ba39d85` |
| 2026-10-15 | Telegram bildirişləri: notify paketi, miqrasiya 011, `/api/v1/notifications/*`, firewall/expiry hook-ları, Settings kartı | server/internal/controlplane/{notify,store,api/rest,reconciler}, cmd/control-plane/main.go, web/src/{lib/notifications.ts,pages/Settings/*,api/client.ts,types}, docs | P8 · `8812781`, `3b64cd0` |
| 2026-10-15 | Manual backup-lar (pg_dump + WireGuard config) | server/internal/controlplane/backup, api/rest/backup_handlers.go, Dockerfile, compose, web BackupsCard, docs | P8 · `846fd9d` |
| 2026-10-15 | Node trafik tarixçəsi (5 dəq, 30 gün) | traffic/, store/traffic.go, miqrasiya 010, api/rest/traffic_handlers.go, web TrafficHistoryCard | P8 · `1bcae2a` |
| 2026-10-15 | Full tunnel config-i (0.0.0.0/0 + DNS) | wireguard, api/rest | P8 · `c82b56b` |
| 2026-10-14 | `.env` faylları git-dən çıxarıldı və ignore olundu | web/.gitignore, server/.gitignore, NovusGate Center/.gitignore | secret sızması · `3bb858c`, `5510657` |
| 2026-10-14 | Postgres yalnız `127.0.0.1:5432` | docker-compose.yml, docs/security.md | publish olunmuş port iptables INPUT-dan keçmir · `2b374d8` |
| 2026-10-14 | CI workflow `docs/ci/ci.yml`-də hazırlandı; `VITE_WS_URL` qeydi | docs/ci/ci.yml, web/.env.example | `.github` agentə bağlıdır · `8d4b700` |
| 2026-10-14 | Allow IP admin/API portlarını açmır (nft guard, iptables mangle guard, API 400) | nft/compile.go, api/rest/firewall_*.go, setup-firewall.sh (+test), Center scripts.js, docs/api.md, P3 spec §6b | §6b.4 istifadəçi qərarı · `b1320ea` |
| 2026-10-14 | `/health` detalları yalnız API key və ya sessiya ilə | api/rest/{handlers,dto_system}.go, testdata, docs/api.md | istifadəçi qərarı · `1840033` |
| 2026-10-13 | Close Port dəqiq uyğunluq | firewall_handlers.go, firewall_portmatch_test.go | A6 lockout · `abdb7b5` |
| 2026-10-13 | Startup-da peer bərpası, sync expired-i qaytarmır | peer_restore.go, handlers.go | A3, B11 · `1bb5700` |
| 2026-10-13 | Konteyner restart siyasəti | docker-compose.yml | A3 · `1bbc4c2` |
| 2026-10-13 | SSH port aşkarlanması, DROP sonda | setup-firewall.sh | A5 · `63cf05f` + `2ddf730` |
| 2026-10-13 | Center skriptləri moduldan çıxarıldı | lib/scripts.js, server.js | test oluna bilmə · `f7efd76` |
| 2026-10-13 | Reinstall DB/admin-vpn.conf saxlayır | lib/scripts.js | A1 · `7e1abd1` |
| 2026-10-13 | Install guard | lib/scripts.js, server.js | A2 · `b58853c` |
| 2026-10-13 | SSE xətası crash etmir | lib/sse.js, server.js | A4 · `dc582ea` + `8e9a449` |
| 2026-10-13 | Binary/konteyner adı, admin-vpn.conf | lib/scripts.js, server.js, index.html | B17–B19 · `70216b9` |
| 2026-10-13 | Shell skriptləri LF, Center test skripti | .gitattributes, package.json | LF üçün · `cde27c5` + `3fbfd54` |
| 2026-10-13 | Arxivdə lokal `server/data` göndərilmir | server.js, test/archive.test.js | final review: dev DB prod DB-ni əzə bilərdi · `d0e50d0` |
| 2026-10-13 | DB var, `.env` yoxdursa reinstall dayanır (exit 4) | lib/scripts.js, test/reinstall-db-guard.test.js | final review: yeni secret DB-ni kilidləyərdi · `e43fa22` |
| 2026-10-13 | Runbook: Update yolu və DB guard yoxlaması | docs/runbooks/p1-staging-acceptance.md | final review · `322ad1d` |
| 2026-10-13 | P3 firewall spec + P3a mühərrik planı | docs/superpowers/specs/2026-10-13-p3-firewall-design.md, docs/superpowers/plans/2026-10-13-p3a-firewall-engine.md | firewall-u tam idarə etmək · `709d1a6` |
| 2026-10-13 | P3a firewall mühərriki: model, kompilyator, SSH qoruması, executor, təsdiqli tətbiq, DB→model, `firewall preview` | server/internal/netctl/nft/*, server/internal/controlplane/firewall/*, server/cmd/control-plane/firewall_cmd.go, Dockerfile.control-plane, server/scripts/test-in-docker.sh, .gitattributes, docs/architecture.md | P3 firewall · `76b8e1b`..Task 6 |
| 2026-10-14 | P2d-2: OpenAPI sənədi (reflection), /api/v1/openapi.json, route coverage, kontrakt-sxem yoxlaması, /api JSON 404/405 | api/rest/{openapi,api_fallback}.go, testdata | P2d-2 planı · `ceb50b5`..`56d5462` |
| 2026-10-14 | P2d-3: request və response DTO-ları, tipli OpenAPI, 206 sənədləşdi, host/firewall cavabları snapshot-da | api/rest/{dto_*,handlers,config_handlers,firewall_*,openapi,fail2ban_parse}.go, testdata | P2d-3 planı · `b761eef`..`8d33280` |
| 2026-10-14 | P4a: sessions cədvəli, sessiya auth-u, logout, login limiti, parol yalnız sessiya istifadəçisi üçün (B15) | store/{sessions.go,migrations_*/007_*}, api/rest/{auth,handlers,openapi}.go, web/src/{App.tsx,api/client.ts,components/Layout.tsx}, docs/{api,security,data-model}.md | P4a planı · `d4f41fc`..`8917c80` |
| 2026-10-14 | P4b: enrollment tokenləri, tokenli install skripti (VPN üzərindən checkin), nginx `/api` proxy-si, CORS çıxarıldı, bundle-da API açarı yoxdur | store/{enrollment.go,migrations_*/008_*}, api/rest/{enrollment,auth,handlers,config_handlers,openapi}.go, web/{nginx,Dockerfile,.dockerignore,src}, compose, docs | P4b planı · `ae025ba`..`532d37d` |
| 2026-10-14 | P4c: node private key-ləri AES-GCM ilə ayrıca sütunda, API-də `has_config`, audit `user_id`, `MASTER_KEY` (compose, Center) | shared/secretbox, store/{node_keys.go,store.go,009_*}, api/rest/{config_handlers,firewall_handlers,auth}.go, cmd/control-plane/node_keys.go, web, Center/lib/scripts.js, docs | P4c planı · `f56afd5`..`24df425` |
| 2026-10-14 | Təxirə salınmış kiçik məsələlərin hamısı bağlandı (A–H) və final review düzəlişləri | server, web, NovusGate Center, setup-firewall.sh, docs | cleanup planı · `a79dfc4`..`3639795` |
| 2026-10-14 | P2d-1: vahid xəta body-si, sabit kodlar, PUT /nodes validasiyası | api/rest/*, testdata/contract | P2d-1 planı · `761dbc6`..`8325276` |
| 2026-10-14 | P2c: Node.Active, B11 handler-ləri, ExpireNodes, reconciler (shadow/enforce), loop və /health, tək Up, logging qoruyucusu | models, api/rest/*, store, reconciler/*, main.go, compose, logging test | P2c planı · `e5d346a`..`24a499d` |
| 2026-10-14 | P2b: slog logger, request log, panic recovery, /health yoxlamaları, runtime log-ların slog-a keçməsi | shared/logging, api/rest/{middleware,handlers}.go, cmd/control-plane/main.go, compose, 10 runtime fayl | P2b planı · `b1fda2b`..`bdbce97` |
| 2026-10-13 | P2a: kontrakt snapshot testləri, B14/B16/B21/B22, DB parolunun maskalanması, frontend xəta helper-i | api/rest/*, store/store.go, wireguard/manager.go, cmd/control-plane/main.go, web/src/api/errors.ts + 5 səhifə, scripts/update-contracts*.sh | P2a planı · `646ce20`..`f816289` |
| 2026-10-13 | P3b-2: hazır olma şərti, host yoxlaması, INPUT təhvili, REST minor-ları, legacy SSH qoruması, M5/M10, `setup-firewall.sh` (boot unit, fail2ban, geri qayıdış) | firewall/{engine,cutover}.go, api/rest/*, store/firewall.go, netctl/nft/{compile,validate}.go, scripts/nft-versions-*.sh, deployments/docker/setup-firewall.sh, web/src/api/client.ts | P3b-2 planı · `2854f01`..`f22aaaa` |
| 2026-10-13 | P3b-1 review fix: retry, legacy VPN sırası, allow/block ziddiyyəti, wg0 endpoint qoruması, runbook | server/internal/controlplane/firewall/{engine,iptables_import}.go, api/rest/{firewall_engine,firewall_handlers}.go, testlər, docs/runbooks/p3b1-firewall-engine.md, docs/api.md, docs/architecture.md, spec §6b | P3b-1 final review Important 1–4 |

**Final review sonrası testlər:** Center `# tests 24 · # pass 24 · # fail 0` (fix dalğasının implementer-i icra edib); Go və shell dəyişməyib (final reviewer təkrar icra etdi: yaşıl).

**P3/P7 planlarına ötürülənlər:** panel-dən xüsusi SSH portu bağlana bilər (`protectedPorts` yalnız 22) → P3; `unhandledRejection` handler-i gələcək asılmaları gizlədə bilər, reinstall catch-də SSH bağlantısı sızır → P7.
