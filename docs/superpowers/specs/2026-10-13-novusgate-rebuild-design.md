# NovusGate Rebuild — Dizayn Spesifikasiyası

> **Tarix:** 2026-10-13 · **Status:** təsdiq gözləyir
> **Mənbə:** 2026-10-13 tam kod auditi. 4 sahə ayrıca agentlə oxundu, kritik tapıntılar sonra əl ilə təkrar yoxlandı. `.md` sənədləri sübut kimi istifadə olunmayıb.
> **Bu sənəd nə üçündür:** bütün alt-planlar (P1–P8) bu sənədə əsaslanır. Planların hər biri ayrıca işləyən və test olunan proqram verir.

---

## 1. Məqsəd

NovusGate-i (WireGuard hub-and-spoke VPN idarəetmə sistemi) peşəkar, etibarlı və rahat idarə olunan sistemə çevirmək. **Bu zaman mövcud funksiyaların heç biri itməməlidir** (bax §6 — Funksionallıq inventarı).

## 2. Təsdiqlənmiş qərarlar (istifadəçi, 2026-10-13)

| Mövzu | Qərar |
|---|---|
| Firewall texnologiyası | **nftables-ə keçid** (iptables-dən) |
| Frontend komponentləri | ~~Tam yeni UI kit~~ → **2026-10-14 qərarı: hazırkı frontend və dizayn saxlanılır.** P5 (UI kit) və P6 (səhifələrin yenidən yazılması) ləğv olundu. Qalan UI baqları (B13, B15-in frontend hissəsi) və P3c firewall UI hazırkı dizaynda edilir |
| NovusGate Center | **Ayrıca Node.js aləti kimi qalır**: skriptlər fayllara çıxarılır, job modeli qurulur |
| Təhdid modeli | Tək admin. Center lokaldır. Panel (3007) yalnız VPN (wg0) ilə, API (8080) yalnız `wg+` ilə açılır |

## 3. Sındırmamaq qaydaları (bütün planlar üçün məcburi)

1. **API kontraktı dondurulur.** Hər endpoint-in indiki cavab forması P2-də snapshot testlə bağlanır. Cavab forması dəyişməlidirsə, əvvəl yeni versiya və ya yeni sahə əlavə olunur, köhnə forma deprecate edilir.
2. **DB yalnız genişlənir.** Yeni sütunlar `DEFAULT` ilə əlavə olunur, sütun silinmir və adı dəyişmir. Hər migration-un yanında `*_rollback.sql` faylı olur.
3. **Yeni davranış əvvəl kölgədə işləyir.** Reconciler və nftables mühərriki əvvəl `shadow` rejimində olur: yalnız fərqi log-a yazır, heç nəyi dəyişmir. Ancaq bir müddət izlənəndən sonra `enforce` rejiminə keçir. Rejim env ilə seçilir.
4. **Mövcud vəziyyət "adopt" edilir.** Yeni mexanizm ilk dəfə işə düşəndə hostda tapdığı peer və qaydaları silmir, onları DB-yə idxal edir.
5. **Client config-ləri dəyişmir.** Mövcud açarlar, IP-lər və server public key-ləri toxunulmaz qalır. Heç bir mərhələ istifadəçidən config-i yenidən yükləməyi tələb etmir. Yeganə istisna istifadəçinin özünün aktiv etdiyi yeni imkanlardır, məsələn full tunnel.
6. **Hər dəyişiklikdən əvvəl backup.** Update/migration-dan əvvəl `pg_dump` + `/etc/wireguard` arxivi alınır.
7. **Staging-də qəbul.** Hər planın sonunda staging VM-də əl ilə qəbul runbook-u icra olunur: reboot, reinstall, update.
8. **Köhnə UI səhifəsi yenisi hazır olana qədər qalır.** P6-da hər səhifə yalnız §6-dakı paritet siyahısı tam ödənəndən sonra əvəz olunur.

## 4. Hədəf arxitektura

### 4.1 Backend (Go)
```
server/
  cmd/control-plane/        CLI: serve, migrate (init — yalnız boş host üçün, qorunmalı)
  internal/
    domain/                 Network, Node, Policy, User, Session — biznes tipləri
    store/                  repository-lər + tx; migrations_sql/ (yalnız additive)
    service/                NodeService, NetworkService, PolicyService, AuthService, HostFirewallService
    netctl/
      wg/                   WireGuard interfeysi (Manager interface; CLI implementasiyası)
      nft/                  nftables ruleset kompilyatoru + `nft -c/-f` icraçısı
    reconciler/             DB → host (interfeys, peer, nft) bərabərləşdirmə; shadow|enforce
    jobs/                   expiry, trafik nümunələri, backup
    api/rest/               nazik handler-lər, DTO, validasiya, vahid xəta formatı
```
- **Həqiqət mənbəyi = DB.** Reconciler hər 15 saniyədə, eləcə də hər yazma əməliyyatından sonra (trigger ilə) bunları edir:
  - `wgN.conf`-u DB-dən **peer-lərlə birlikdə** yenidən yaradır. Reboot-dan sonra hər şey bərpa olunur.
  - Yalnız aktiv node-ları peer kimi saxlayır. Vaxtı bitmiş və ya disabled node-lar avtomatik çıxarılır.
  - nftables ruleset-ini atomik tətbiq edir.
- **Vahid xəta formatı:** `{"error":{"code":"<snake_case>","message":"..."}}`. Köhnə `{"error":"..."}` forması P2-də deprecate olunur. Frontend hər iki formanı oxuyur.
- **Log:** `log/slog`, JSON. Request log-u middleware ilə yazılır (hazırkı no-op əvəzinə).
- **Health:** `/health` DB-ni, interfeysləri, reconciler-in son uğurlu işini və nft ruleset-in vəziyyətini yoxlayır.

### 4.2 nftables dizaynı (P3)
- **Öz cədvəlimiz:** `table inet novusgate`. Sistemdəki digər qaydalara (Docker, fail2ban, ufw) toxunulmur.
- **Vacib semantika:** nftables-də `accept` **yekun deyil**: paket eyni hook-dakı digər base chain-lərdən də keçir. `drop` isə yekundur. Ona görə siyasət **drop ilə tətbiq olunur**. Docker-in iptables-nft `FORWARD` siyasəti DROP ola bilər, ona görə wg trafiki üçün minimal iptables ACCEPT (indiki PostUp) saxlanılır, deny isə bizim cədvəldə olur.
- **Chain-lər:**
  - `input`: admin xidmətləri (3007, 5432 yalnız wg0-dan; 8080 yalnız wg+-dan); SSH portları sshd-dən avtomatik tapılır.
  - `forward`: şəbəkələr arası siyasət, default deny + conntrack established/related.
  - `postrouting` (nat): hər wg subnet-i üçün `masquerade`, `-s` ilə məhdudlaşdırılmış.
  - `egress`: full tunnel üçün (P8).
- **Set-lər:** `open_tcp`, `open_udp`, `blocked_v4` — Host Firewall UI bunları idarə edir. Sətir nömrəsi ilə silmə tamamilə aradan qalxır.
- **Kompilyator:** DB → nft mətni. Golden-file testlərlə yoxlanılır. `nft -c -f` ilə tətbiqdən əvvəl validasiya edilir, `nft -f` ilə atomik tətbiq olunur.
- **Docker-published 5432:** forward hook-da `ct original proto-dst 5432` + `iifname != "wg0"` → drop.
- **fail2ban:** `banaction = nftables-multiport`.
- **Migrasiya:** panel vasitəsilə yaradılmış iptables qaydaları (open port, blocked IP) set-lərə idxal olunur, sonra iptables-dən silinir. `setup-firewall.sh` artıq flush etmir.

### 4.3 Auth və install (P4)
- `sessions` cədvəli: `token_hash`, `user_id`, `expires_at`, `last_used_at`. Logout və istifadəçi silinməsi sessiyanı ləğv edir. Login rate limit tətbiq olunur.
- Node enrollment: bir dəfəlik, 15 dəqiqəlik token. `install.sh?t=…` və `checkin` bu token ilə işləyir.
- nginx `/api/` və `/health`-i `127.0.0.1:8080`-ə proxy edir. Frontend eyni origin işlədir, ona görə mixed content qalmır və `VITE_API_URL` artıq lazım deyil.
- Node private key-ləri DB-də AES-GCM ilə şifrələnir (master key env-də). API cavablarında `labels.wireguard_private_key` gizlədilir.
- Audit log-a `user_id` əlavə olunur.

### 4.4 Frontend (P5, P6)
- **Yeni UI kit** `web/src/ui/` altında:
  - Design token-ləri (CSS dəyişənləri, light/dark), tipoqrafiya, spacing.
  - Radix primitivləri üzərində komponentlər: Button, Input, Select, Dialog, ConfirmDialog, Drawer, Tabs, Tooltip, DropdownMenu, Toast, DataTable, Badge, StatusDot, EmptyState, Skeleton, PageHeader, Form sahələri.
  - Vizual istiqamət əvvəl maket (mockup) ilə təsdiqlənir.
- **Data qatı:**
  - Backend `openapi.yaml` dərc edir, TS tipləri ondan generasiya olunur.
  - Hər resurs üçün React Query hook-ları.
  - Mutasiya xətaları global toast kimi göstərilir.
  - 401 yalnız sessiya bitəndə logout edir.
- **Formlar:** react-hook-form + zod.
- **i18n:** i18next (az, en).
- **ErrorBoundary:** hər route-da.

### 4.5 Center (P7)
- Skriptlər `NovusGate Center/scripts/*.sh` fayllarına çıxarılır. Parametrlər `printf %q` ilə escape olunmuş env faylı kimi upload edilir.
- Hər addım idempotentdir: preflight (OS, root/sudo, apt lock gözləmə, SSH portu, disk) → install, reinstall, update, uninstall.
- Update: backup → yeni image-lər → migrate → health → uğursuzluqda əvvəlki versiyaya rollback.
- Job queue: hər server üçün eyni anda bir əməliyyat. Job tarixçəsi və log-u saxlanılır.
- `servers.json` atomik yazılır (tmp + rename) və mutex ilə qorunur.
- `docker compose` v2 istifadə olunur.

## 5. Yol xəritəsi

| Plan | Məzmun | Asılılıq | Qəbul şərti |
|---|---|---|---|
| **P1 Stabilizasiya** | Data itkisi, lockout, crash və reboot baqları + CI | — | Staging-də: reboot sonrası peer-lər qayıdır; reinstall DB-ni saxlayır; xüsusi SSH portu bağlanmır; Close Port başqa qaydaya toxunmur; Center xətada çökmür |
| **P2 Backend nüvəsi** | Kontrakt snapshot testləri, qatlara bölmə, `netctl/wg` interfeysi, reconciler (shadow → enforce), expiry job, vahid xəta, slog, OpenAPI | P1 | Bütün snapshot testləri yaşıl; reconciler shadow-da 0 gözlənilməz fərq; expiry panel bağlı olanda da işləyir |
| **P3 nftables** | §4.2-nin tamamı + iptables-dən migrasiya + fail2ban backend | P2 | VPN DROP qaydası real bloklayır; 5432 internetdən bağlıdır; Docker işləyir; uninstall təmiz silir |
| **P4 Auth + install** | §4.3 | P2 | Logout tokeni ləğv edir; one-line install real serverdə işləyir; join-vpn işləyir |
| **P5 UI kit** | §4.4 bünövrəsi: token-lər, komponentlər, i18n, tipli client, `/ui-kit` vitrin səhifəsi | P2 (OpenAPI) | Bütün komponentlər light/dark-da vitrində; `tsc` təmiz; a11y yoxlaması keçir |
| **P6 UI səhifələri** | §6-nın hamısı yeni kit ilə + §7 UI baqları + yeni səhifələr (Network detalı, Policy matrisi/topologiya, Audit, Sessions, Backups) | P5, P3, P4 | Hər səhifə üçün §6 paritet çeklisti 100% |
| **P7 Center** | §4.5 + Center baqları (§7.C) | P1 | Uğursuz update avtomatik rollback edir; paralel əməliyyat bloklanır |
| **P8 Yeni imkanlar** | Full tunnel (node üzrə), backup UI, bildirişlər, trafik tarixçəsi | P3, P6 | Ayrıca spesifikasiya ilə |

**Təsdiq tələb edən yeni paketlər** (`CLAUDE.md`: yeni paket → təsdiq):
- **P5:** `@radix-ui/*`, `class-variance-authority`, `tailwind-merge`, `react-hook-form`, `zod`, `@hookform/resolvers`, `i18next`, `react-i18next`, `@tanstack/react-table`, `sonner`, `openapi-typescript` (dev).
- **P2 (istəyə bağlı):** `golang.zx2c4.com/wireguard/wgctrl`.
- **P3:** yeni Go paketi yoxdur. Alpine image-ə `nftables` sistem paketi əlavə olunur.
- **Silinəcək (indi 0 yerdə istifadə olunur):** `jszip`, `file-saver`, `@types/file-saver`, `@headlessui/react`. `reactflow` P6 topologiyası üçün, `recharts` Dashboard üçün saxlanılır.

## 6. Funksionallıq inventarı (paritet çeklisti)

Bu siyahı "əskiksiz" tələbinin ölçüsüdür. Yeni sistemdə hər sətir ya **eyni işləməlidir**, ya da **daha yaxşı** işləməlidir. Bir funksiyanı silmək yalnız istifadəçinin açıq təsdiqi ilə mümkündür.

### 6.A Web panel (`web/src`)
| Səhifə | Funksiya | API |
|---|---|---|
| Login | İstifadəçi adı və parol ilə giriş | `POST /api/v1/auth/login` |
| Layout | Şəbəkə seçicisi (sidebar), "VPN Connected" nişanı, logout | `GET /networks` |
| Dashboard | Ümumi statistika, sistem məlumatı (CPU/RAM/disk/uptime), şəbəkə kartları | `GET /stats/overview`, `GET /system/info` |
| Networks | Siyahı, yaratma (ad, CIDR), silmə (wg0 qorunur) | `GET/POST /networks`, `DELETE /networks/{id}` |
| Nodes | Şəbəkə üzrə siyahı (status, IP, label-lar, son görünmə, rx/tx) | `GET /networks/{id}/nodes` |
| Nodes | Peer yaratma: ad + müddət (1 saat/1 gün/1 həftə/custom/limitsiz) → config modalı | `POST /networks/{id}/servers` |
| Nodes | Config modalı: platforma təlimatları, `.conf` yükləmə, QR, Linux install əmri | `GET /nodes/{id}/config`, `/qrcode`, `/install.sh` |
| Nodes | Redaktə: ad, müddəti uzatmaq/limiti götürmək/custom, status (active/disabled), cihaz məlumatı (os/arch/hostname) | `PUT /nodes/{id}` |
| Nodes | Silmə; node detal səhifəsi (`/nodes/:id`) | `DELETE /nodes/{id}`, `GET /nodes/{id}` |
| Firewall · Overview | Host firewall statistikası | `GET /firewall/host/rules` |
| Firewall · Open Ports | Port açmaq/bağlamaq (tcp/udp/both, mənbə IP) | `POST /firewall/host/port/open`, `/close` |
| Firewall · Blocked IPs | IP bloklamaq (port seçimi ilə), blokdan çıxarmaq | `POST /firewall/host/ip/block`, `/allow`, `/rules/delete` |
| Firewall · Host Rules | INPUT/FORWARD/OUTPUT siyahısı, qayda silmə, export, reset | `GET /firewall/host/rules`, `POST /rules/delete`, `GET /export`, `POST /reset` |
| Firewall · VPN Rules | CRUD (mənbə/hədəf: any/network/node/custom; protokol; port; action; priority; enabled), Apply, AllowedIPs izahı | `/firewall/vpn/rules*`, `POST /firewall/vpn/apply` |
| Fail2Ban | Status və jail-lər, ban/unban (o cümlədən permanent), jail ayarları (bantime/maxretry/findtime), whitelist, permanent ban siyahısı və silmə, loglar, ban tarixçəsi, reload, ping | `/system/fail2ban/*` (14 route) |
| Settings | Parol dəyişmə; istifadəçilər (siyahı/yaratma/silmə) | `PUT /auth/password`, `/users*` |

**Yalnız API-də olan funksiyalar** (UI-da yoxdur, saxlanılmalıdır): `POST /nodes/{id}/checkin`, `POST /networks/{id}/sync`, `GET /debug/wireguard/{id}`, `POST /firewall/host/import`, `POST /system/fail2ban/jail/control`, `GET /health`.

### 6.B NovusGate Center (`NovusGate Center/`)
| Bölmə | Funksiya | Endpoint |
|---|---|---|
| Serverlər | Əlavə etmə (ad, host, port, istifadəçi, parol, private key, passphrase), silmə, siyahı | `GET/POST /api/servers`, `DELETE /api/servers/:id` |
| Dashboard | Status polling (CPU/RAM/disk/uptime, quraşdırılıb-quraşdırılmayıb, konteynerlər) | `GET /:id/status` |
| Quraşdırma | Install (admin user/pass, şəbəkə adı/CIDR, VPN IP, DB adı/user/pass), Reinstall, Update, Migrate DB — canlı log ilə (SSE) | `POST /:id/install` (`reinstall`/`update`/`migrateOnly`) |
| Quraşdırma | Uninstall | `POST /:id/uninstall` |
| Giriş məlumatları | Credentials göstərmə, admin VPN config yükləmə | `GET /:id/credentials`, `/vpn-config` |
| Docker | Konteyner siyahısı, əməliyyatlar (action), canlı log axını, image siyahısı/silmə, volume siyahısı/silmə, prune | `/:id/docker*`, `/images*`, `/volumes*`, `/prune` |
| Fail2Ban | Status, unban | `GET /:id/fail2ban`, `POST /:id/fail2ban/unban` |
| Terminal | Brauzerdə SSH terminal (xterm + socket.io: `start-session`, `input`, `resize`) | socket.io |
| Tarixçə | Install/update tarixçəsi | `servers.json` |
| Yalnız API | Custom əmr, join-vpn | `POST /:id/command`, `/:id/join-vpn` |

## 7. Məlum baqlar — hansı planda bağlanır

**A. Kritik → P1:**
- A1: reinstall `find` əmri DB daxil hər şeyi silir.
- A2: quraşdırılmış serverdə "Install" yeni secret yaradır və sistem DB-yə qoşula bilmir.
- A3: reboot sonrası konteynerlər qalxmır və peer-lər itir.
- A4: SSE xətası Center-i çökdürür.
- A5: SSH portu 22 kimi sabit yazılıb və DROP siyasəti qaydalardan əvvəl qoyulur.
- A6: Close Port substring ilə uyğunlaşdırır.

**B. Funksional baqlar:**
| Kod | Baq | Plan |
|---|---|---|
| B7 | VPN DROP qaydası təsirsizdir (PostUp ACCEPT öndədir) | P3 |
| B8 | Birtərəfli qayda işləmir; `node` qaydası bütün şəbəkəyə tətbiq olunur | P3 (siyasət modeli) |
| B9 | Linux one-line install işləmir | P4 |
| B10 | join-vpn işləmir | P4, P7 — **2026-10-14-də bağlandı:** Center panelin node install skriptini serverdə işə salır (`62a3601`) |
| B11 | Expiry problemləri: lazy tətbiq; reaktivləşmə peer-i geri qaytarmır; rule sync vaxtı bitmiş peer-ləri bərpa edir | P1 (sync və bərpa üçün aktivlik filtri), P2 (reconciler) — **P2c-də bağlandı (`e5d346a`, `c61bc4a`, `07e63f1`, `149af2f`)** |
| B12 | Host rule delete: frontend və backend method/path uyğun gəlmir | P2 (alias), P6 |
| B13 | EditNodeModal expiry ilə saxlamağı bloklayır | P6 — **2026-10-14-də bağlandı** (hazırkı frontend): dialoq "Keep Current" ilə açılır, tarix sahəsi yalnız "Set Custom Date"-də görünür; `web/src/lib/nodeExpiry.ts` + `web/tests` |
| B14 | VPNRuleModal `null` gəldikdə çökür | P2 (`[]` qaytarmaq), P6 — **P2a-da bağlandı (`10f49ff`)**: səbəb node siyahısı idi |
| B15 | Köhnə parol səhv olanda logout baş verir | P4 (`400 invalid_old_password`), P5 (interceptor) — **bağlandı:** backend 400 qaytarır (P4a), frontend yalnız 401-də çıxış edir və xətanı formada göstərir |
| B16 | Fail2ban tarixçəsi boşdur; whitelist parse səhvdir | P2 — **P2a-da bağlandı (`7d798ff`)** |
| B17 | Migrate binary adı səhvdir | P1 |
| B18 | Center konteyner adları böyük/kiçik hərf uyğunsuzluğu | P1 |
| B19 | Update `admin-vpn.conf`-u silir | P1 |
| B20 | Firewall Reset Docker-i və girişləri pozur | P3 (Reset → bizim cədvəli yenidən qurur) |
| B21 | `/24` sabit yazılıb; broadcast və hub IP ayrılır | P2 — **P2a-da bağlandı (`4fb3ec9`)** |
| B22 | `GetPublicKey` `=` simvolunu kəsir; `parseRuleLine` panic edir | P2 / P3 — **P2a-da bağlandı (`5802f79`)** |
| B23 | Mixed content | P4 (nginx proxy) |

**C. Center əlavə → P7** (hamısı **2026-10-14-də bağlandı**, bax `docs/active-context.md` P7 bloku):
- `servers.json` yarışı — `lib/store.js`
- terminal-da passphrase və resize problemi — `lib/ssh.js`, `public/index.html`
- `$` və `"` escape problemi — `shellQuote` (cleanup planı)
- compose v1 asılılığı — `compose()` köməkçisi
- apt lock — `apt_get()` köməkçisi
- non-root istifadəçi — `sudo -n` bağlantı səviyyəsində
- paralel arxiv — `lib/archive.js`
- uninstall-un yan təsirləri — yalnız NovusGate silinir

## 8. Açıq sual (P1-dən sonra qərar)
- Postgres 5432-nin wg0 üzərindən açıqlığı saxlanılsın, yoxsa yalnız SSH tunel ilə olsun? Hazırda wg0-dan açıqdır, P3-də nftables ilə məhz bu davranış saxlanılır. Dəyişmək istifadəçinin qərarıdır.
