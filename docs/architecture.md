# Arxitektura

## Firewall mühərriki (P3a)
- `server/internal/netctl/nft` — NovusGate-in öz nftables cədvəli `table inet novusgate` (IPv4 + IPv6):
  - `Compile` modeli atomik `nft -f` skriptinə çevirir (`table` → `delete table` → yenidən təyin);
  - `Validate` nft sintaksisinə "inject"-in və təhlükəli portların qarşısını alır;
  - `CheckProtection` SSH lockout-a qarşı qoruyur (fail closed);
  - `Executor` nft CLI üzərindən `Check`, `Apply` və `Snapshot` edir;
  - `SafeApplier` snapshot + `systemd-run` host timer + prosesdaxili timer ilə "60 saniyəyə təsdiqlə, yoxsa geri qayıt" mexanizmini qurur.
- `server/internal/controlplane/firewall` — DB-dəki şəbəkələri və VPN qaydalarını mühərrik modelinə çevirir və host faktlarını (`sshd -T`, `ip route get`) aşkarlayır.
- `novusgate-server firewall preview [--check]` — DB-dən ruleset-i göstərir. Hostu **dəyişmir**: `--check` yalnız `nft -c` edir.
- Hazırda heç bir HTTP endpoint və ya startup kodu nft tətbiq etmir. Tətbiq P3b-də `FIREWALL_ENGINE` bayrağı ilə gələcək.
- Semantika: nftables-də `accept` yekun deyil, `drop` yekundur. Siyasət drop ilə tətbiq olunur, Docker-in və fail2ban-ın cədvəllərinə toxunulmur.
- Testlər: `server/scripts/test-in-docker.sh` (`NFT_CHECK=1` ilə kernel yoxlaması).

## Firewall engine inteqrasiyası (P3b-1)
- **`FIREWALL_ENGINE`:**
  - `iptables` — default, köhnə kod yolları dəyişmir;
  - `shadow` — startup-da yalnız `nft -c` icra olunur;
  - `nft` — engine tətbiq edir.
- **`firewall.Engine`:** `Change.Mutate` ilə dəyişikliyi yaddaşda qurur, tətbiq edir. `Change.Commit` ilə yalnız dəyişiklik canlı olandan sonra (dərhal və ya təsdiqdən sonra) DB-yə yazır, ona görə rollback olan dəyişiklik saxlanmır. Bitmə vaxtı olan IP qaydası üçün reconcile planlaşdırılır.
- **DB:** `fw_services`, `fw_ip_rules`, `fw_forwards`, `fw_egress`, `fw_meta` (migration 006). Rollback faylı `store/migrations_rollback/`-dadır və embed olunmur.
- **REST:** `/api/v1/firewall/v2/*` (bax `docs/api.md`). nft rejimində köhnə `/firewall/host/*` endpoint-ləri validasiyadan sonra adapterə keçir (`firewall_v1_nft.go`). Şəbəkə və node dəyişiklikləri reconcile edir.
- **Startup (nft):**
  - iptables-dən bir dəfəlik idxal (`fw_meta.iptables_imported`). "Əvvəlki ACCEPT sonrakı DROP-u üstələyir" ziddiyyəti olarsa, idxal rədd edilir;
  - reconcile;
  - köhnə `novusgate-vpn-*` FORWARD qaydaları yalnız ilk uğurlu apply-dan sonra silinir (`Engine.AfterApply`).
- **Retry:** uğursuz reconcile (pending təsdiq, aktiv rollback timer, aşkarlama xətası) `ReconcileOrRetry` ilə arxa planda təkrarlanır. Backoff 15 saniyədən başlayır, 5 dəqiqəyə qədər artır. Expiry, şəbəkə/node/VPN dəyişiklikləri və startup bu yoldan keçir.
- **Qoruma:** hər apply-da sorğu edənin ünvanından əlavə, `wg0` peer-lərinin canlı WireGuard endpoint-ləri də qorunur (`Engine.Protect`).
- **Boot faylı:** `/etc/novusgate/firewall.nft`. Onu `novusgate-firewall.service` yükləyir:
  - unit-i `setup-firewall.sh` qurur;
  - `Before=network-pre.target docker.service`;
  - fayl olmayanda unit heç nə etmir.

### Keçid (P3b-2)
- **Host yoxlaması (`firewall.CheckHost`).** nft rejiminin şərtləri:
  - host nft ≥ 1.0.2;
  - `novusgate-firewall.service` aktivdir (`enabled`);
  - iptables nf_tables backend-dədir.

  Şərt ödənmirsə, startup dayanır, iptables işləməyə davam edir və firewall dəyişiklikləri 409 qaytarır. Ubuntu 20.04 bu şərtlərə görə dəstəklənmir.
- **Hazır olma.** Startup iptables idxalını bitirib `MarkReady` çağırana qədər engine dəyişiklik qəbul etmir (`ErrNotReady`).
- **INPUT-un təhvili (`firewall.CutoverIptables`).** İlk uğurlu apply-dan sonra (`Engine.AfterApply`, prosesin hər başlanğıcında bir dəfə):
  1. iptables INPUT siyasəti `ACCEPT` olur;
  2. INPUT-dakı sadə `ACCEPT`/`DROP` qaydaları öz spec-i ilə silinir (nömrə ilə yox, ona görə fail2ban-ın eyni anda etdiyi dəyişiklik silinəni sürüşdürə bilməz). `REJECT` ban-ları və başqa alətlərin zəncirlərinə jump-lar (fail2ban, CrowdSec) saxlanılır və log-a yazılır;
  3. `netfilter-persistent save` icra olunur.

  Köhnə `novusgate-vpn-*` FORWARD qaydaları da eyni anda silinir.
- **`setup-firewall.sh`:**
  - hər rejimdə `nftables` paketini quraşdırır (`nftables.service` heç vaxt aktiv edilmir), boot unit-i qurur və fail2ban üçün `jail.d/novusgate.local` faylını yazır (bütün SSH portları; nft rejimində `nftables-multiport`);
  - nft rejimində, ruleset faylı mövcuddursa, iptables-ə və Docker-ə toxunmur;
  - iptables rejimində əvvəl baseline-ı qurur, sonra `table inet novusgate` cədvəlini və boot faylını silir. Geri qayıdış budur.
- **M5.** VPN-only istisnalar (API portları, rezerv portlarda servislər) yalnız DB-dəki şəbəkə interfeyslərinə və `wg0`-a aiddir.
- **Versiyalar arası yoxlama.** `server/scripts/nft-versions-check.sh` golden ruleset-ləri və nft 1.0.9 snapshot-unu nft 1.0.2, 1.0.6 və 1.0.9-da `nft -c` ilə yoxlayır.
- **DB testləri:** `server/scripts/test-with-postgres.sh` (`TEST_DATABASE_URL`, `-p 1`).

## Xəta formatı (P2d-1)
- Handler-lər xətanı `errorResponse(w, status, message)` (kod statusdan götürülür) və ya `errorWithCode(w, status, code, message)` ilə yazır. Body: `{"error":{"code","message"}}`. Kodlar sabitdir, siyahısı `docs/api.md`-dədir.

## OpenAPI (P2d-2)
- **Sənəd:** `openapi.go` `docOps` cədvəli və Go tiplərindən reflection ilə qurulan sxemlər, `GET /api/v1/openapi.json` ilə verilir.
- **Qoruyan testlər:** `TestEveryRouteIsDocumented` (route əhatəsi), `assertMatchesSpec` (hər kontrakt cavabı sxemə qarşı yoxlanılır).
- **`/api` fallback:** uyğun gəlməyən `/api` sorğuları JSON 404/405 alır (`api_fallback.go`).

## DTO qatı (P2d-3)
- **Fayllar:** `dto_requests.go` (12 request), `dto_system.go` (auth, node, health, system, stats, debug, sync), `dto_fail2ban.go`, `dto_firewall.go` (v1, v2; VPN apply `StatusMessageResponse` işlədir). Handler-lər `map` qaytarmır.
- **Şərti açarlar:** pointer + `omitempty` (mövcud olanda `0`/`false`/`""`/`[]` da yazılır); həmişə olan, amma `null` ola bilən açarlar pointer, `omitempty`-siz (`pending`, `last_run`).
- **Cavab formasını dəyişmədən tipə keçirmə üsulu:**
  1. əvvəl formanı kontrakt snapshot-u ilə dondur;
  2. sonra `docOps`-u yeni tipə yönəlt (`assertMatchesSpec` köhnə cavabı yeni sxemə qarşı yoxlayır);
  3. ən sonda handler-i çevir (snapshot dəyişməməlidir).
- **Servis qatı yoxdur:** biznes məntiqi hələ handler-lərdədir. Səbəb P2 spec §5-dədir.

## Test seam-ləri (P2a)
- **`api/rest`-də dəyişdirilə bilən funksiyalar:**
  - `execHostCommand`, `execCommand`: host və konteyner əmrləri;
  - `generateKeys`: WireGuard açarları;
  - `openFail2BanLog`: `/var/log/novusgate/fail2ban.log` (`Fail2BanLogPath`) (sətir-sətir oxunur);
  - `fail2banLogExists`: log faylının mövcudluğu (`GET /system/fail2ban/logs`);
  - `wgInit`, `wgTeardown`: WireGuard interfeysinə toxunan yerlər;
  - `legacySSHPorts`, `adminPeers`, `clearLegacyVPNRules`, `checkFirewallHost`, `cutoverIptables`.

  Testlər bunları stub edir, heç bir test host-a toxunmur.
- **Kontrakt testləri** bax `docs/api.md`. Golden fayllar `.gitattributes` qaydası (`server/**/testdata/** eol=lf`) ilə LF saxlanılır.
- **Yeni şəbəkənin hub ünvanı:** CIDR-in ilk host-u, CIDR-in öz prefiksi ilə (`hubAddress`).
- **`AllocateIP`:** network, `.1` və `.2` ünvanlarını ötürür, broadcast-ı heç vaxt vermir.
- **Startup log-u:** DB URL-dəki parol maskalanır (`maskDatabaseURL`): userinfo (kodlaşdırılmamış `#`, `/`, `@` daxil), `?password=` və DSN-dəki `password=` (dırnaqlı da).

## Log və müşahidə (P2b)
- **Logger:** `log/slog`, `internal/shared/logging.New`.
  - `LOG_FORMAT`: `json` (default) və ya `text`.
  - `LOG_LEVEL`: `debug`, `info` (default), `warn`, `error`.
  - Səhv dəyər verilsə server dayanmır: JSON/info-ya keçir və bir xəbərdarlıq yazır.
  - `slog.SetDefault` standart `log` paketini də bu logger-ə yönləndirir.
- **Request log-u (`LoggingMiddleware`):** hər sorğu üçün bir `http request` sətri yazılır: `method`, `path`, `status`, `bytes`, `duration_ms`, `remote`.
  - Query, header və body heç vaxt log-a düşmür.
  - `/health` `debug` səviyyəsində, 5xx cavablar `error` səviyyəsində yazılır.
- **`RecoverMiddleware`:** panic 500 (`{"error":"internal server error"}`) cavabına çevrilir və stack ilə log-a yazılır. `http.ErrAbortHandler` yenidən panic edilir.
- **Middleware sırası:** Logging → Recover → API key → Auth. Hər biri bir dəfə işləyir; `main.go`-dakı ikiqat bükmə silindi.
- **`http.Server.ErrorLog`** (accept xətaları, net/http panic-ləri) `slog`-a Error səviyyəsində yönləndirilir.
- **Səviyyə qaydası:** xəta, uğursuzluq və xəbərdarlıq mesajları Warn və ya Error səviyyəsində yazılır. Bunu `TestLogLevelsMatchMessages` qoruyur.
- **Runtime kodu yalnız `slog` ilə log yazır.** Mesaj mətnləri əvvəlki kimidir, ona görə runbook grep-ləri işləyir. Bunu `TestRuntimeCodeLogsThroughSlog` qoruyur.
  - CLI çıxışı (`migrate`, `init`, `version`, `firewall preview`) `fmt` olaraq qalır.
  - `migrate` slog-un mətn handler-i ilə yazır.

## Reconciler (P2c)
- **Paket:** `internal/controlplane/reconciler`. DB WireGuard peer-ləri üçün həqiqət mənbəyidir.
- **`WG_RECONCILER` rejimləri:**
  - `off`: köhnə davranış, goroutine işləmir;
  - `shadow` (default): yalnız log yazır;
  - `enforce`: fərqi tətbiq edir.

  Səhv dəyər verilsə server başlamır.
- **Nə vaxt işləyir:** hər 15 saniyədən bir. Node və şəbəkə yazmalarından sonra da trigger olunur (`triggerReconcile`). Ardıcıl trigger-lər bir işləməyə birləşir.
- **Expire addımı** (shadow və enforce): `ExpireNodes` vaxtı keçmiş node-ları DB-də `expired` kimi yazır. Peer-in silinməsi diff addımında olur. Bu, panelin lazy expiry-sinin vaxtında işləyən formasıdır, panel bağlı olsa da işləyir.
- **Diff addımı:**
  - aktiv node peer olmalıdır və onun `/32` ünvanı allowed-ips siyahısında olmalıdır;
  - qeyri-aktiv node-un peer-i silinir.
  - **Shadow:** vaxtı keçmiş node-ların peer-lərini silir (hər iki rejimdə; DB yenidən oxunur, uğursuz silinmə növbəti tick-də təkrarlanır). Əlavə və yeniləmə üçün yalnız `reconciler (shadow): would change peer` yazır.
  - **Enforce:** fərqi tətbiq edir. Hər dəyişiklikdən əvvəl node DB-dən yenidən oxunur, ona görə silinmiş node-un peer-i geri qayıtmır.
- **Qorumalar:**
  - DB-də olmayan peer heç vaxt silinmir. Log-a `reconciler: peer not in the database (left alone)` yazılır ("adopt" qaydası).
  - allowed-ips siyahısı heç vaxt daraldılmır: gateway route-ları qalır.
- **Aktivlik:** `models.Node.Active(now)`: açar və IP var, status `expired` deyil, `expires_at` keçməyib. `restorePeers`, `PUT /nodes/{id}` (`peerTransition`) və `syncPeerAllowedIPs` eyni tərifi işlədir (B11).
- **`/health`:** `checks.reconciler {ok, mode, last_run, pending}`.
- **P2c-2-yə saxlanılıb:** `wgN.conf`-a `[Peer]` bölmələrinin yazılması. `wg0.conf`-u installer yazır və bootstrap açarları ondan oxuyur. Reboot-dan sonra peer-ləri `restorePeers` bərpa edir.
- **Logging qoruyucusu:** `TestRuntimeCodeLogsThroughSlog` və `TestLogLevelsMatchMessages` artıq bütün `internal/` ağacını yoxlayır və import alias-larını tanıyır.

## Firewall Live və History (P3c, 2026-10-15)
- **Drop olunan mənbələr:** kompilyator `input` zəncirinin sonunda, default drop-dan əvvəl `update @dropped_v4 { ip saddr }` / `@dropped_v6` sətirlərini yazır. Set-lər dinamikdir, 1 saat timeout və 4096 element limiti var. Qəbul və drop qərarları dəyişmir; set dolanda sadəcə yeni mənbələr yazılmır. Kernel log və ya NFLOG lazım deyil.
- **Live:** `firewall.Engine.Live` iki əmr işlədir:
  - `nft -a list table` → `nft.ParseCounters` (qaydanın mətni, counter, comment, handle);
  - `nft -j list table` → `nft.ParseDropped`.

  `netctl/conntrack.Read` `/proc`-dan sayı, limiti, protokol və TCP state üzrə bölgünü oxuyur (control-plane host şəbəkəsindədir). Sayğaclar hər tətbiqdə sıfırlanır, çünki cədvəl yenidən yaradılır.
- **History:** `Engine.History` (`store`) `finish`-də, dəyişiklik host-da canlı olub DB-yə yazılandan sonra çağırılır. Yazı alınmasa yalnız log-a düşür.
  - Kim və hansı endpoint: `firewallActorMiddleware` request kontekstinə `firewall.Actor` qoyur.
  - `firewall.Describe` vəziyyəti oxunaqlı sətirlərə çevirir, `DiffLines` əlavə olunan və silinən sətirləri tapır.
  - Restore `proposeV2` ilə adi dəyişiklik kimi işləyir: təsdiq və avtomatik rollback eynidir. Commit `store.ReplaceFirewallState` ilə bir transaksiyada gedir.
  - Baseline və dəyişiklik bir transaksiyada yazılır; yazma 10 s ilə məhdudlaşdırılıb (engine lock altında işləyir).
  - **Məhdudiyyət:** engine-dən keçməyən dəyişikliklər ayrıca yazı almır. Məsələn, node silinəndə `fw_egress` cascade ilə silinir. Bu fərq növbəti dəyişikliyin diff-ində "removed" kimi görünür və həmin dəyişikliyi edən istifadəçinin adına düşür.
  - Restore ondan sonra əlavə olunan bütün IP qaydalarını, o cümlədən Fail2Ban-ın daimi ban-larını silir; UI təsdiqində bu yazılıb.

## Network Policies matrisi və System Rules (P3c, 2026-10-15)
- **Matris** backend-də hesablanır (`firewall.PolicyMatrix`, `GET /api/v1/firewall/policy-matrix`). Qaydaların ünvanları kompilyatordakı kimi həll olunur (node `/32`, custom prefiks) və hər şəbəkənin CIDR-i ilə müqayisə edilir. Mənbə VPN qaydalarıdır, API-nin verdiyi sıra ilə (`priority`, sonra `created_at`), ilk uyğun gələn qayda qalib gəlir — kompilyatordakı `vpn_policy` ilə eyni.
  - Default: nft-də eyni şəbəkə daxilində allow, şəbəkələr arasında deny; iptables və shadow rejimində allow (`NOVUSGATE-VPN` zəncirindən sonra wg ACCEPT-ləri gəlir).
  - Port, protokol, node və ya custom ünvanla məhdudlaşan qayda nəticədən fərqlənirsə, xana `partial` olur.
- **System Rules** (`web/src/lib/systemRules.ts`) `/firewall/v2/preview` skriptini parse edir. `svc:`/`ip:`/`rule:`/`fwd:` comment-li sətirlər istifadəçinin qaydalarıdır və göstərilmir. İzahlar regex cədvəlindədir. Tanınmayan qayda izahsız göstərilir, siyahıdan çıxarılmır. Bu view iptables rejimində (engine yoxdur) mövcud deyil.

## Kömək işarələri ("?", 2026-10-15)
- `web/src/components/HelpTip.tsx`: sahənin yanında "?"; hover, fokus və kliklə açılır (klik sabitləyir), Escape və ya başqa yerə klik bağlayır; ekrandan çıxmasın deyə `lib/helpTip.ts` `tipShift` ilə sürüşdürülür.
- Mətnlər `locales/{en,az}/help<Bölmə>.json`-dadır, hər açarın `what` / `who` / `effect` hissəsi var. `Input`/`Select` `help="ns:açar"` alır; xam `<input>` `data-help` daşıyır və eyni faylda `<HelpTip k=…>` olmalıdır.
- `tests/helpScan.mjs` + `helpTips.test.mjs`: köməksiz input və ya hər iki dildə tam olmayan mətn build-i sındırır. Yeni sahə mətni ilə birlikdə gəlir.
- Center (`public/index.html`, i18n yoxdur): eyni üç hissə ingiliscə, səhifənin öz script-i ilə.
