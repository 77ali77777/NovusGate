# Active Context

## Son Sessiya
- **2026-10-13 sessiyaları** (P1, P3, P2a) `docs/archive/active-context-2026-10-13.md` faylına köçürülüb.

- **2026-10-14 sessiyaları (P2b–P4c)** `docs/archive/active-context-2026-10-14.md` faylına köçürülüb.
- **2026-10-14 sessiyalarının qalanı** (minor-lar, hand-off, P5, P3c, P7) `docs/archive/active-context-2026-10-14.md` faylına köçürülüb (2026-10-17).


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
### 2026-10-15: Təxirə salınmış minor-lar, web borcu, P10a (server idarəsi)
- **Minor-lar:** login yazısında sınanan username, audit cursor `before_id`, hər rol öz sessiyalarını görür və bitirir, modalda `role=dialog` + Escape (`1b88d5d`); Center API və socket yalnız öz origin-indən, log siyahısı 760 → 8 ms (`b605a72`).
- **Web borcu:** biome 97 → 0, TypeScript `strict` (`469569e`); modal fonunun və spinner-in class-ındakı `\` səhvi düzəldildi.
- **P10a backend:** hostadmin allow-list komandaları (`0a03592`), `/server/*` + step-up + 019 (`8ffb988`), klient DNS (`9bf1273`), `ip -j` OpenAPI tipi (`20980e2`), step-up 400 + təxmin limiti (`02cede9`), 500-də host çıxışı gizlədildi (`d802a99`).
- **P10a UI:** Server səhifəsi (Servislər, Şəbəkə, Kernel, Sistem), step-up pəncərəsi, sysctl geri sayım, upgrade log-u, reboot/upgrade söz təsdiqi, şəbəkədə klient DNS sahəsi (`3be393f`).
- **Yoxlamalar:** Go 16/16 paket `ok`; web tsc strict, 64/64, vite, biome təmiz, i18nScan 0; izolə real-backend brauzer testi: 403 → parol pəncərəsi, yanlış parolda çıxış olmur, düzgün parolda təkrar, ləğvdə toast yoxdur, DNS formu.
- **İcra olunmayıb:** host komandaları real serverdə (test konteynerində `nsenter` hosta çıxmır); brauzer testində kənar klik müdaxiləsi (`isTrusted` kliklər, başqa sessiya ehtimalı) — əvvəlki "/firewall-a keçid" də bundan idi, tətbiq kodu deyil.
- **Review (opus) və düzəlişlər** (`1d68402` + UI): Important: ikinci sysctl dəyişikliyi rollback-i köhnə dəyərlərlə əvəz edirdi (409 `sysctl_pending`); gec confirm uğur deyirdi (409 `sysctl_not_pending`); tab dəyişəndə geri sayım itirdi (`pending_until` serverdən); apt docker restart-ı ilə kəsilə bilərdi (`systemd-run` host unit-i, `RuntimeMaxSec`); split konfiqdə DNS Ubuntu-da `resolvconf` olmadan installer-i sındırırdı. Minor: iki parol pəncərəsi, səhv body limitə sayılırdı, IPv6 DNS sızması, upgrade zamanı reboot, sysctl faylının yarımçıq yazılması. PLAUSIBLE hissə (bitmiş timer-in eyni adı bloklaması) systemd 255-də təkrarlanmadı.
- **Lokal merge:** feature → rebuild/plans → main fast-forward (`d97b5d9`), push edilməyib.

### 2026-10-15: Center auditi və "?" kömək tələbi
- **Center auditi** (agent + mənim yoxlamam): əsas axın düzgündür (env, compose `pid: host`, migration-lar, update geri qaytarma). Düzəldildi: Join VPN hub-da işləmir; konteyner adı yoxlanılır; uninstall P10a sysctl izlərini silir; install `curl`, Debian 12 fail2ban journal, `https` ünvan, `.env`-də `VPN_IP`; update `rsync`, degraded/web xəbərdarlığı. Center 101/101, 4 skript `bash -n` ok. Real hostda sınanmayıb.
- **İstifadəçi tələbi:** hər input-a "?" kömək (nədir · kimə lazımdır · nə olur), az+en, panel və Center. Edildi (`ee34f57`, `ca5796c`, `d988976`): `HelpTip` komponenti, panelin hər input-u (105 açar, 9 `help*` namespace) və Center-in 15 sahəsi; `helpTips.test.mjs` köməksiz input-u build-də saxlayır. Mətnlər müstəqil yoxlamadan keçdi, 37 ifadə düzəldildi. Yoxlamanın tapdığı bug-lar: iptables rejimində `8000-9000` port aralığı tətbiq olunmurdu, ad limiti bayt sayırdı (`613bb8c`), Fail2Ban 206 "saxlandı" göstərirdi, protokol dəyişəndə port qalırdı, reinstall `.env`-i 600 deyildi, telefonda tip ekrandan çıxırdı. Bütün tip-lər əl ilə açılmayıb.

### 2026-10-16: Yoxlamalar, Center yeniləməsi, nftables tabları, UX planı
- **Tam yoxlama (koda toxunmadan):** Go 16/16, web 70, Center 102; nft 1.0.2/1.0.6/1.0.9 və iperf3 limit testi; köhnə versiyadan (f82f57a) yeni koda yeniləmə testi 16/16 (14 migration, data qorunur; köhnə istifadəçilər admin olur); Ubuntu 22.04/24.04/25.10/26.04, Debian 12/13 konteynerlərində paketlər, nft qaydaları, fail2ban — hamısı PASS.
- **README/README_AZ** hazırkı sistemə uyğunlaşdırıldı (`463d315`).
- **nftables tabları** iptables rejimində ~7 s yüklənirdi: 409 firewall_disabled təkrar soruşulurdu; indi təkrar yoxdur və EngineOff izah verir (`d33992e`).
- **Center:** yeniləmədə image əvvəl qurulur, sonra konteyner dəyişdirilir (`21bf230`); Center öz qovluğundan köhnədirsə səhifədə və log-da xəbərdarlıq; `.dockerignore` (data/jobs root 0700 build-i sındırırdı, servers.json image-ə düşürdü) (`c1a6989`).
- **UX auditi:** 28 ekran görüntüsü (izolə Playwright); plan `docs/superpowers/plans/2026-10-16-panel-ux-overhaul.md` (`68a0988`). İstifadəçi "et" dedi: Mərhələ 1 dörd agentə paylandı, nəticələr yoxlanmayıb, commit yoxdur.
- **Mərhələ 1 commit olundu** (`708b2c1`): layout (B1/B2, başlıqların sarılması, 390px-də 10 səhifədə üfüqi daşma yoxdur), istifadəçi menyusu, "Cihaz" termini, cihaz formasında şəbəkə, cihaz səhifəsində konfiq/QR/skript/bərpa, "Admin VPN", Firewall 5 tab, siyasət cədvəlində görünən səbəb, topologiya sığır (0/9 kənarda), audit cümlələri. fullweb 101/0/0, biome təmiz, yeni suppression yoxdur.
- **Review (`708b2c1`):** Critical yox, 10 tapıntı — hamısı `7ea10ec`-də düzəldi (operator üçün sürətli əməliyyatlar gizli, Refresh matrisi də yeniləyir, siyahıda IP+etiket çipləri, "Admin VPN" axtarışı, UserMenu a11y, ikon düymələrin adı, matris xanasında qərar, legend mətni, engineMode xətanı keşdən üstün tutur, uğursuz login filtrdə heç kimin deyil). `uxReview.test.mjs` RED→GREEN 4/4, fullweb 105/0, biome təmiz, brauzerdə hər biri yoxlandı.
- **nft segfault (real server, Ubuntu 26.04, kernel 7.0):** konteynerin Alpine nft 1.0.9-u hər çağırışda çökürdü (`list=139`), hostun nft 1.1.6-sı işləyir (`host_check=0`). Engine artıq hostun nft-sini nsenter ilə işlədir (`61d4b40`). Qeyd: əvvəlki "Ubuntu 22–26 PASS" testləri WSL kernel 6.6-da idi, host kernel-lərini əhatə etmirdi.
- **Analiz (istifadəçi ilə razılaşdırılacaq):** konfiqurasiyanın `AllowedIPs`-i VPN qaydalarından asılıdır, ona görə icazə dəyişəndə konfiqurasiya yenidən yüklənməlidir; iptables rejimində server şəbəkələr arası trafiki default buraxır (izolyasiya yalnız klientin konfiqurasiyasındadır). Təklif: AllowedIPs = bütün VPN CIDR-ləri, icazə yalnız serverdə; iptables-də default DROP; "konfiq köhnədir" nişanı; icazələr üçün bələdçi.
- **Tam tunel internetə çıxmırdı (hipotez, serverdə təsdiqlənməyib):** Docker 29 `ip filter FORWARD` policy DROP; wg0 (install.sh, PostUp yoxdur) üçün iptables ACCEPT yox idi. nft keçidi indi DOCKER-USER-ə `-i/-o wg+ ACCEPT` qoyur (`e4b074e`).
- **Mərhələ 2 edildi** (istifadəçi "et"): migration 020 (`networks.tunnel_mode`, `nodes.tunnel_override`, `fw_egress` → override), API `PUT /networks/{id}/tunnel`, `PUT /nodes/{id}/tunnel`, `POST /networks` `tunnel_mode` (`18c3b8c`); panel: kartda/şəbəkə səhifəsində rejim + admin "Dəyiş" dialoqu, yaratma formasında iki kart, cihaz səhifəsində override, siyahıda badge (`c7ac08c`). iptables rejimində yalnız konfiq dəyişir, Admin VPN-də tam tunel nft tələb edir. Yoxlamalar: Go 16/16, upgrade 019→020 15/15, köhnə versiya→indi 16/16, web 108/0, brauzer (iptables stack). nft təsdiq axını brauzerdə işlədilməyib; real cihazla internet testi istifadəçidədir. Review: 5 Important + 6 Minor, hamısı yoxlanıb düzəldilib (`fa5188f`): shadow rejimi, pending zamanı yaradılan cihaz, restore tunel ayarına toxunmur, DOCKER-USER Docker körpülərini RETURN edir və iptables rejimində silinir, migration təkrar işə düşür, UI təsdiq/geri qayıtma vəziyyəti.
- **Davam:** review tapıntıları; Mərhələ 4 (Center), Mərhələ 3 (nft açarı panelde) (şəbəkə tunel növü; tam tunel iptables-də də — tövsiyə, istifadəçi etiraz etməyib), 4, 3.
### 2026-10-16/17: Versiya 0.7.0, Center rəngləri, tam tunelin real serverdə analizi, WireGuard hostda
- **Versiya 0.7.0** hər yerdə (`80c60d1`): server `internal/shared/version`, web `package.json` (sidebar Vite define ilə), Center `package.json` (`/api/health`, footer). Testlər üçünü uyğun saxlayır.
- **Center web-in rənglərində** (`e2314e1`): açıq default, tünd sistemə görə.
- **Real server (Ubuntu 26.04, kernel 7.0, Docker 29) analizi:** tam tunel "qoşulur, internet yox". Sübutlar: `wg1` serverdə yox idi; müştəri konfiqi silinmiş köhnə wg1-ə (açar `CeWLI/...`) aid idi (audit: 14:38 DELETE, 14:48 POST); yeni şəbəkələr qalxmırdı — kernel log `apparmor="DENIED" operation="exec" profile="wg-quick" name="/bin/busybox"`: hostun `wg`/`wg-quick` AppArmor profilləri yol üzrə konteynerin binary-lərinə də yapışır.
- **Düzəliş** (`df52217`, `6e533ad`, review düzəlişləri `1ef45db`: oneshot unit-in "active" qalması, silmə/yoxlama yarışı və kilid, handover-dən əvvəl import, backoff, Server səhifəsindən restart sonrası peer bərpası, viewer üçün səbəb gizli; `eac979d`: PostUp `awk` olmadan — hostun wg-quick profili `gawk`-ı rədd edirdi): WireGuard hostda (`nsenter`), hər şəbəkə `wg-quick@wgN` systemd unit-i; açarlar Go-da; start/yaratma/`POST /networks/{id}/restart`/hər 30 s yoxlama interfeysi qaldırır və peer-ləri DB-dən qaytarır; şəbəkə JSON-da `interface_up`/`interface_error`, panelde real status + "Yenidən qaldır"; `WG_RECONCILER` default `enforce`. Go 16/16, web 111/0. **Real hostda yoxlanmayıb** (systemd/nsenter/AppArmor) — istifadəçi Update-dən sonra yoxlayacaq.
- **İstifadəçi addımları:** push; Center → Update; `systemctl list-units 'wg-quick@*'`, `wg show`; paneldə şəbəkə statusu; köhnə cihaz konfiqləri işləməz (şəbəkə yenidən yaradılıb) — yeni cihaz/konfiq; paylaşılmış private key-li cihazı sil.
- **Davam:** real server nəticəsi; Mərhələ 4 (Center), Mərhələ 3 (nft açarı paneldə); "Access Server" paketi (istifadəçi portalı, 2FA, sessiya timeout, qoşulma jurnalı) — istifadəçi qərarı gözləyir.
### 2026-10-19: VLAN tipli giriş nəzarəti — M1, M2 (plan `docs/superpowers/plans/2026-10-19-vlan-access-control.md`)
- **İstifadəçi tələbi:** şəbəkələr VLAN kimi ayrı olsun; şəbəkə, cihaz və qrup səviyyəsində icazə; bir tərəfli və ya qarşılıqlı; bilməyən də başa düşsün.
- **M1 (`6487890`):** hər cihaz konfiqi bütün VPN şəbəkələrini marşrutlayır (+ qaydada adı keçən kənar IP aralıqları; tam tunel `0.0.0.0/0`), qərarı yalnız hubun firewall-u verir; iptables rejimində də standart təcrid (`NOVUSGATE-VPN`: qaydalar → eyni şəbəkə RETURN → `wg+→wg+` DROP); DB 021 `nodes.config_routes`, API `config_outdated`, paneldə "konfiq köhnədir" nişanı və bildiriş.
- **M2 (`f7b9c8d` server, `f498d6a` web):** DB 022 `firewall_rules.bidirectional`; qarşılıqlı qayda nft-də əks VPNRule, iptables-də dəyişdirilmiş cüt kimi yazılır; matrix bunu `BuildRuleset` ilə görür. Panel qayda forması 5 addımdır (Kim? → Kimə? → Nəyə? → İstiqamət → Qərar), hazır xidmətlər (Veb, SSH, RDP, SMB, Ping), altda adi dildə nəticə cümləsi, ad boş qalsa "A ⇄ B" avtomatik; ad/sıra/qeyd "Ətraflı"da. Siyahıda və şəbəkə səhifəsində → / ⇄.
- **Yoxlamalar:** Go 16/16 ok; `TestMutualRuleInIptablesMode` iptables əks cütü söndürüləndə RED, bərpada GREEN; web tsc OK, 115 test, biome 0, vite OK, help/i18n skanı 0; test stack-də (iptables) brauzerdə qarşılıqlı RDP qaydası yaradıldı, API `bidirectional:true`, konteynerdə iptables-də hər iki istiqamət + təcrid DROP görüldü.
- **M3 (`4646d67` server, `339b6aa` web):** `GET /firewall/access-check` — iki şəbəkə/cihaz/qrup arasında hər iki istiqamət, matrisin qiymətləndirməsi cihaz-cihaz (qrup üzvlərinə açılır); `reason_key` əlavə `mixed`, `empty`. Qrup dəsti üzv cihazın /32-sini "tam" sayır (əvvəl "qismən" deyirdi). Paneldə Firewall → Şəbəkələr arası: "Kim kimi görür?" kartı (iki seçici, bir cümləlik cavab, hər istiqamət + səbəb + qaydalar, "Bu cüt üçün qayda yaz"). Brauzerdə 5 ssenari yoxlandı.
- **M4 (`028bdb4` server, `d306466` web):** `POST /nodes/{id}/rotate-key` — yeni açar cütü; əvvəl köhnə peer silinir (alınmasa heç nə dəyişmir), konfiq "köhnədir" olur. Cihaz səhifəsində "Yeni açar" (təsdiq dialoqu ilə); Admin VPN cihaz siyahısında izah: quraşdırıcının `admin-vpn.conf`-u yalnız wg0-u görür, bütün şəbəkələr üçün özünə Admin VPN-də cihaz yarat. **Qərar:** quraşdırıcının admin peer-i DB-yə idxal olunmadı və `install.sh` dəyişmədi — o peer `wg0.conf`-un `[Peer]` bölməsindədir, avtomatik fayl redaktəsi real serverdə admin girişini kəsə bilər; quraşdırmada yalnız wg0 olduğu üçün onun `AllowedIPs`-i onsuz da "bütün şəbəkələr"dir.
- **İcra olunmayıb:** nft rejimində real host yoxlaması; real serverdə M1 təcridi; test stack-də peer əməliyyatları (nsenter yoxdur — unit testlə örtülüb).
- **Müstəqil review (M1–M4) və düzəlişlər:** iptables rejimində şəbəkə/cihaz dəyişikliyindən sonra `NOVUSGATE-VPN` yenidən qurulmurdu (yeni şəbəkənin cihazları bir-birini görmürdü; silinmiş cihazın ACCEPT-i ünvanı alan yeni cihaza qalırdı) → `reconcileFirewall` iptables-də də zənciri qurur, qurulma mutex ilə seriyalaşır; kənar IP aralığı bütün cihazlara verilirdi → yalnız qaydanın digər tərəfinə; custom `0.0.0.0/0` rədd; köhnə `syncPeerAllowedIPs` silindi (`wg set` ilə silinmiş peer-i geri yarada bilirdi, M1-dən sonra faydasız idi; ip_forward saxlanıldı); rotate-key: öz cihazı 409, yeni peer alınmasa 500, cihaz üzrə kilid; Admin VPN izahı qaydaları da deyir. Təxirə salınan minor-lar cavabda.
- **Davam:** real serverdə yoxlama.

### 2026-10-19: Server tərəfli marşrut — konfiq bir dəfə (P1)
- **İstifadəçi tələbi:** istifadəçi tərəfində konfiq heç vaxt dəyişməsin, hər şeyi server idarə etsin. Hesabat: hovuz (P1), domen endpoint (P2), DNS hubda (P3), NETMAP (P4); split/tam tunel və açar dəyişikliyi qaçılmaz olaraq konfiq tələb edir. İstifadəçi "et" dedi; tövsiyələr qəbul olundu (hovuz 10.0.0.0/8, dəyişdirilə bilən).
- **P1:** DB 023 `vpn_settings.pool`; konfiq `AllowedIPs` = hovuz (+ hovuzdan kənar şəbəkələr, kənar aralıqlar); `POST /networks` CIDR boşdursa növbəti /24, hovuzdan kənar 400; `GET/PUT /settings/vpn`; panel: şəbəkə formasında CIDR avtomatik, Settings → "VPN ünvan hovuzu"; Center `install.sh` admin konfiqi hovuzu marşrutlayır.
- **Yoxlamalar:** Go 16/16, web 118, Center 111, brauzerdə şəbəkə avtomatik 10.10.0.0/24 aldı, konfiq `AllowedIPs = 10.0.0.0/8`.
- **P2:** DB 024 `vpn_settings.endpoint_host`; konfiq `Endpoint` = domen:port (4 konfiq yeri bir köməkçidə: `nodeEndpoint`); "konfiq köhnədir" endpoint-i də izləyir (`config_routes` = `AllowedIPs @ Endpoint`); install.sh HEAD artıq qeyd yazmır; Settings → "Server ünvanı (domen)". Center quraşdırma formasına domen sahəsi əlavə olunmayıb (admin konfiqi IP ilə qalır).
- **P1/P2 review düzəlişləri:** endpoint hovuzun içindədirsə konfiq şəbəkələri adla yazır (əks halda tunel qalxmırdı), PUT bunu rədd edir; iptables-də hovuza gedən qaydasız trafik DROP (hubun 10.x LAN/VPC-si açıq qalırdı); yanlış IP (999.1.1.1) domen kimi keçmir; Center: server IP 10.x-dirsə admin konfiqi yalnız admin alt şəbəkəsini marşrutlayır. Təxirə salınan minor-lar: full tunel cihazları yenilənmədən sonra bir dəfə yalançı "köhnədir" göstərir; 192.168/16 hovuzu ev LAN-ları ilə toqquşa bilər; birgə PUT atomik deyil; 023 rollback-i 024-dən əvvəl edilməməlidir.
- **P3 (2026-10-20, istifadəçi "davam"):** `dnsfwd` paketi (`4e4e7be`) + qoşulma: konfiq DNS = hub ünvanı, hub şəbəkənin DNS serverlərinə ötürür; DNS serverlərini dəyişmək konfiqi dəyişmir; firewall-da wg-dən 53 açıq. Test stack-də real: ünvan `lo`-ya əlavə olunandan sonra dinləyici özü qalxdı, `nslookup example.com 10.20.0.1` cavab verdi, nft sintaksisi `nft -c` ilə OK.
- **P3 review düzəlişləri:** hub ünvanı DNS serveri kimi qadağan + siyahıdan atılır (döngü agent tərəfindən təkrarlanmışdı: 1 sorğu → minlərlə goroutine); dinləyici yalnız öz şəbəkəsinə cavab verir, firewall şəbəkə başına yalnız öz hub ünvanına (A şəbəkəsi B-nin DNS-ini işlədə bilmirdi təcridi pozmadan); TCP limit 64, Accept xətasında dayanmır; SERVFAIL; son işləyən server əvvəl; `SyncDNS` mutex. Real: öz şəbəkəsi UDP/TCP cavab aldı, başqa şəbəkə timeout, iptables `NOVUSGATE-DNS` düzgün. Təxirə salınan minor-lar: yenilənmədən sonra hamı bir dəfə "köhnədir" görür (format dəyişdi); dinləyici qalxana qədər konfiq birbaşa DNS-ə keçə bilər; split tunel + `client_dns` olan şəbəkədə bütün DNS indi hubdan keçir (hub/tunel düşəndə ad həlli də düşür).
- **Web boşluqları (2026-10-20):** API xəta kodları paneldə az/en (`apiErrors` namespace, `setErrorTranslator`); "konfiq köhnədir" və DNS sahəsi mətnləri yeniləndi; şəbəkə səhifəsində "Hub üzərindən DNS" vəziyyəti (`dns_served`/`dns_error`).
- **Center domen sahəsi:** quraşdırmada `vpnDomain` → admin konfiqi və `WG_SERVER_ENDPOINT` domeni işlədir (test 112/112; forma vizual yoxlanmayıb — qoşulmuş server tələb edir).
- **README/README_AZ/USER_GUIDE(_AZ):** standart təcrid, istiqamət, 5 addımlı forma, "Kim kimi görür?", hovuz, avtomatik CIDR, hubda DNS, server domeni, "Yeni açar", "konfiq bir dəfə" bölməsi; köhnə "qayda AllowedIPs-i dəyişir" iddiası düzəldildi.
- **Davam:** P4 (NETMAP) — dizayn sualı istifadəçidə; real serverdə yoxlama.
## Son Dəyişikliklər
| Tarix | Dəyişiklik | Fayllar | Səbəb |
|---|---|---|---|
| 2026-10-20 | Center: quraşdırmada server domeni; README və istifadəçi bələdçiləri yeni sistemə uyğun | NovusGate Center/{lib,scripts/install.sh,server.js,public/index.html}, README*.md, web/USER_GUIDE*.md | İstifadəçi: hamısını həll et |
| 2026-10-20 | Xəta kodları paneldə tərcümədə; hub DNS vəziyyəti şəbəkə səhifəsində | web/src/{api/errors.ts,i18n,lib/networkDisplay.ts,components/NetworkStatus.tsx,pages/Networks/NetworkDetail.tsx}, server models.go, rest/interfaces.go | İstifadəçi: web tərəfi tam olsun |
| 2026-10-20 | Hub DNS review: təcrid, döngü, TCP limit, SERVFAIL | server/internal/controlplane/{dnsfwd,api/rest/{dns_hub,network_dns,firewall_handlers,handlers}.go}, server/internal/netctl/nft/compile.go | Müstəqil review |
| 2026-10-20 | Hubda DNS: konfiq hubu göstərir, server ötürür | server/internal/controlplane/{dnsfwd,api/rest/dns_hub.go,api/rest/{routes,config_handlers,firewall_handlers,interfaces,network_dns,handlers}.go}, server/internal/netctl/nft/compile.go, cmd/control-plane/main.go, web i18n helpNetworks | Server tərəfli marşrut P3 · `4e4e7be`, `ee21e40` |
| 2026-10-19 | P1/P2 review: endpoint hovuzda, iptables hovuz DROP, Center admin konfiqi | server/internal/controlplane/api/rest/{pool,routes,firewall_handlers}.go, NovusGate Center/scripts/install.sh | Müstəqil review |
| 2026-10-19 | Server ünvanı domen ilə (DB 024), konfiq endpoint-i bir yerdə | server/internal/controlplane/{store/vpn_settings.go,api/rest/{pool,routes,config_handlers}.go}, web/src/pages/Settings/EndpointHostCard.tsx, i18n | Server tərəfli marşrut P2 · `4d7e471` |
| 2026-10-19 | Ünvan hovuzu: konfiq bir dəfə, şəbəkə CIDR avtomatik (DB 023) | server/internal/controlplane/{store/vpn_settings.go,api/rest/{pool,routes,handlers}.go}, NovusGate Center/scripts/install.sh, web/src/pages/{Networks,Settings}, i18n | Server tərəfli marşrut P1 · `87a1e0c` |
| 2026-10-19 | VLAN review düzəlişləri (iptables yenidən qurma, kənar marşrut, rotate-key) | server/internal/controlplane/api/rest/{firewall_engine,firewall_handlers,handlers,routes,rotate_key}.go, web/src/api/client.ts, i18n nodes | Müstəqil review |
| 2026-10-19 | Cihaz açarını yeniləmə (API + "Yeni açar"), Admin VPN izahı | server/internal/controlplane/{store/node_keys.go,api/rest/rotate_key.go}, web/src/{pages/Nodes/Nodes.tsx,lib/deviceActions.ts,api/client.ts}, i18n | VLAN planı M4 · `028bdb4`, `d306466` |
| 2026-10-19 | "Kim kimi görür?" yoxlayıcısı (API + panel kartı) | server/internal/controlplane/{firewall/access_check.go,firewall/matrix.go,api/rest/firewall_matrix.go}, web/src/{pages/Firewall/AccessChecker.tsx,lib/accessCheck.ts,lib/matrixReason.ts}, i18n | VLAN planı M3 · `4646d67`, `339b6aa` |
| 2026-10-19 | Qarşılıqlı VPN qaydası (DB 022) və 5 addımlı sadə qayda forması | server/internal/controlplane/{store,firewall,api/rest}, models.go, web/src/{lib/vpnRule.ts,pages/Firewall/{VPNRuleModal,VPNRulesTab,Firewall}.tsx,pages/Networks/NetworkDetail.tsx}, i18n | VLAN planı M2 · `f7b9c8d`, `f498d6a` |
| 2026-10-19 | Konfiq bütün VPN şəbəkələrini marşrutlayır, iptables-də də təcrid, `config_outdated` (DB 021) | server/internal/controlplane/{store,firewall,api/rest}, models.go, web/src/pages/Nodes | VLAN planı M1 · `6487890` |
| 2026-10-17 | WireGuard hostda (systemd unit-lər), interfeys statusu + restart, reconciler enforce | server/internal/{wireguard,controlplane/api/rest}, models.go, main.go, docker-compose.yml, web/src/{components/NetworkStatus.tsx,pages/Networks} | Ubuntu 26.04 AppArmor konteynerin wg-quick-ini bloklayırdı · `df52217`, `6e533ad` |
| 2026-10-16 | Versiya 0.7.0; Center web rənglərində | server/internal/shared/version, web, NovusGate Center | İstifadəçi · `80c60d1`, `e2314e1` |
| 2026-10-16 | Tunel rejimi review düzəlişləri | server/{cmd,internal/controlplane/{firewall,store,api/rest}}, web/src/{components/Tunnel.tsx,lib/tunnelMode.ts} | Müstəqil review · `fa5188f` |
| 2026-10-16 | Şəbəkə səviyyəsində tunel rejimi (DB 020, API, panel) | server/internal/controlplane/{store,api/rest}/*, models.go, web/src/{components/Tunnel.tsx,lib/tunnelMode.ts,pages/Networks,pages/Nodes}, i18n | İstifadəçi: tam tunel şəbəkə yaradanda/siyahıda seçilsin · `18c3b8c`, `c7ac08c` |
| 2026-10-16 | nft rejimində VPN trafiki Docker FORWARD DROP-dan keçir | server/internal/controlplane/firewall/cutover.go | Tam tunel internetə çıxmırdı · `e4b074e` |
| 2026-10-16 | nft engine hostun nft-sini işlədir (konteynerinkini yox) | server/internal/controlplane/firewall/{host.go,host_test.go}, server/cmd/control-plane/firewall_cmd.go | Kernel 7.0-da Alpine nft 1.0.9 segfault · `61d4b40` |
| 2026-10-16 | UX Mərhələ 1 review-unun 10 tapıntısı | web/src/{components/UserMenu.tsx, lib/{auditText,firewallV2,matrixReason,networkDisplay}.ts, pages/{Audit,Firewall,Networks,Nodes}/*}, i18n firewall.json, tests/uxReview.test.mjs | Müstəqil review · `7ea10ec` |
| 2026-10-16 | Panel UX Mərhələ 1: layout, istifadəçi menyusu, Cihaz termini, cihaz formaları/səhifəsi, Admin VPN, Firewall 5 tab, siyasət cədvəli, topologiya, audit cümlələri | web/src/components/{Layout,UserMenu}.tsx, pages/{Nodes,Networks,Firewall,Audit,Topology}/*, lib/{appStorage,topologyFit,networkDisplay,deviceActions,firewallTabs,auditText}.ts, i18n | UX auditi (28 ekran görüntüsü) · `708b2c1` |
| 2026-10-16 | nftables tabları iptables rejimində dərhal izah verir (təkrar sorğu yox) | web/src/lib/firewallV2.ts, api/client.ts, pages/Firewall/{EngineOff,AdvancedTab,HistoryTab,SystemRulesTab}.tsx | İstifadəçi: tablar yüklənib qalırdı · `d33992e` |
| 2026-10-16 | Center: build-sonra-dəyiş yeniləmə; köhnə Center xəbərdarlığı; .dockerignore | NovusGate Center/scripts/update.sh, lib/selfcheck.js, server.js, public/index.html, .dockerignore | Yeniləmə zamanı panel dayanırdı; Center skriptləri image-dədir · `21bf230`, `c1a6989` |
| 2026-10-16 | UX planı (4 mərhələ) | docs/superpowers/plans/2026-10-16-panel-ux-overhaul.md | İstifadəçi: peşəkar, başa düşülən panel · `68a0988` |
| 2026-10-16 | README və README_AZ hazırkı sistemə uyğunlaşdırıldı (tələblər, Center sahələri, panel ünvanı https, full tunnel, yeni imkanlar, nftables keçidi, yeniləmə, rollar) | README.md, README_AZ.md | README-lər rebuild-dən əvvəlki vəziyyətdə qalmışdı |
| 2026-10-15 | "?" kömək hər input-da (panel + Center), Center auditi düzəlişləri, iptables port aralığı, simvol sayan ad limiti | web/src/components/HelpTip.tsx, web/src/i18n/locales/*/help*.json, web/tests/help*.mjs, NovusGate Center/public/index.html + scripts, rest/firewall_handlers.go, firewall/limits.go | İstifadəçi tələbi; Center auditi; mətn yoxlaması · `656e141`..`ca5796c` |
| 2026-10-15 | P10a: server idarəsi (step-up, allow-list komandalar, sysctl geri qaytarma, upgrade/reboot), klient DNS, Server səhifəsi; minor-lar; web strict + biome 0 | hostadmin/, api/rest/{server_admin_handlers,network_dns,openapi}.go, migrations 019, web/src/pages/Server/, lib/serverAdmin.ts | P10a planı; review minor-ları · `1b88d5d`..`3be393f` |
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
