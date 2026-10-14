# Active Context

## Son Sessiya
- **Tarix:** 2026-10-13
- **Tapşırıq:** P1 Stabilizasiya (`docs/superpowers/plans/2026-10-13-p1-stabilization.md`)
- **Nəticə:** Task 1–10 commit-lənib (`cde27c5^..70216b9`, 13 commit: `cde27c5` `3fbfd54` `abdb7b5` `1bb5700` `1bbc4c2` `63cf05f` `2ddf730` `f7efd76` `7e1abd1` `b58853c` `dc582ea` `8e9a449` `70216b9`). Step 1 avtomatik testlər (Docker, `MSYS_NO_PATHCONV=1`):
  - Go — `docker run … golang:1.23 go test ./...` → `ok  github.com/novusgate/novusgate/internal/controlplane/api/rest 0.019s`; digər paketlər `[no test files]`; exit 0.
  - Center — `docker run … node:20-bookworm sh -c 'node --test test/*.test.js'` → `# tests 19` · `# pass 19` · `# fail 0`; exit 0.
  - Shell — `docker run … ubuntu:24.04 bash tests/setup-firewall_test.sh` → `OK`; exit 0.
  - Staging qəbulu icra olunmadı, səbəb: staging VM yoxdur — runbook istifadəçi tərəfindən icra olunmalıdır.
- **Davam:** P2 Backend nüvəsi planı yazılmalıdır (növbəti addım). İstifadəçinin tərəfində qalanlar:
  1. `.github/workflows/ci.yml` yaradılmalıdır — `.github` altına yazma icazə ayarlarına görə rədd edildi; YAML P1 planında Task 1 Step 5-dədir.
  2. `setup-firewall.sh` faylının LF ilə yenidən checkout-u rədd edildi — Task 5 (`63cf05f`) faylı artıq LF ilə yazdığı üçün məsələ bağlıdır.
  3. `docs/runbooks/p1-staging-acceptance.md` staging VM-də (təzə Ubuntu 24.04, root SSH) icra olunmalıdır; hər addımın əmr və çıxışı həmin faylın sonuna yazılmalıdır.

### Eyni sessiyanın davamı (2026-10-13): P3 firewall
- **Tapşırıq:** Linux firewall-unu (SSH-dan şəbəkəyə qədər) tam idarə etmək üçün analiz, dizayn və plan.
- **İstifadəçi qərarları:**
  - SSH public qalır;
  - port forwarding lazımdır;
  - full tunnel-in firewall hissəsi P3-də hazırlanır;
  - IPv6 IPv4 ilə eyni qaydaları alır.
- **Nəticə:** `docs/superpowers/specs/2026-10-13-p3-firewall-design.md` və `docs/superpowers/plans/2026-10-13-p3a-firewall-engine.md` commit-ləndi (`709d1a6`). Repo-da kod dəyişməyib. P3a kodu scratchpad-da prototip kimi yoxlanılıb:
  - `go vet`, `go build ./...` və testlər (`ok …/netctl/nft`, `…/controlplane/firewall`, `…/api/rest`) keçir;
  - yaradılan qaydalar nftables 1.0.2, 1.0.6 və 1.0.9-da `nft -c`-dən keçir;
  - kernel-də apply, snapshot və restore işləyir.
- **Aşkarlanan:** WSL docker shim-i argumentlərdəki `$`-ı genişləndirir, ona görə konteyner daxilində `$?` etibarsızdır. Test məntiqi `server/scripts/test-in-docker.sh` faylında olmalıdır.
- **Davam:** P3a planını icra etmək (icra üsulu istifadəçinin seçimidir), sonra P3b. PR üçün push-u istifadəçi edir.

### Eyni sessiyanın davamı (2026-10-13): P3a icra olundu
- **Tapşırıq:** `docs/superpowers/plans/2026-10-13-p3a-firewall-engine.md` (inline, executing-plans)
- **Nəticə:** Task 1–6 commit-ləndi (`76b8e1b` … Task 6). Tam yoxlama (`bash scripts/test-in-docker.sh`, Docker, `NFT_CHECK=1`) → `ok …/api/rest`, `ok …/controlplane/firewall`, `ok …/netctl/nft`; exit 0. Golden ruleset Ubuntu 22.04-də (nft 1.0.2) `KERNEL-CHECK-OK` verdi. Control-plane image yığıldı, içində `nftables v1.0.9` var.
- **End-to-end yoxlama:** real Postgres-də migration-lar icra olundu, şəbəkə, node və VPN qaydası əlavə edildi, `firewall preview --check` işlədildi. Nəticə: `nft -c: OK`, SSH portları `{ 22, 2222 }` real `sshd -T`-dən aşkarlandı, qayda düzgün çevrildi.
- **Davranış dəyişikliyi:** yoxdur. Hostda heç nə avtomatik tətbiq olunmur.
- **Final review (opus):** "With fixes" — 1 Critical, 7 Important. Hamısı RED→GREEN ilə düzəldildi (`e7eadc9`, `cf496f9`, `3c5ce3a`):
  - SSH portları `listenaddress` və canlı `ss` dinləyicilərindən aşkarlanır;
  - rollback faylı, timer və nft host-da işləyir;
  - restart, confirm və disarm yarışları aradan qaldırıldı;
  - wg0-un Docker postgres-ə çıxışı qorunur;
  - DHCPv6 cavabları qəbul olunur;
  - uzun ban-lar ruleset-i sındırmır;
  - UDP forward WireGuard portunu tuta bilmir;
  - IPv6 qaydaları xəbərdarlığa çevrilir.
  
  Fix-dən sonra suite exit 0, golden nft 1.0.2-də yüklənir. Minor-lar P3 spec §6a-ya köçürüldü.
- **Davam:** P3b planı (DB cədvəlləri, `/firewall/v2`, iptables-dən import, `FIREWALL_ENGINE` bayrağı, boot unit, fail2ban nftables).

### Eyni sessiyanın davamı (2026-10-13): P3b-1 planı
- **Nəticə:** `docs/superpowers/plans/2026-10-13-p3b1-firewall-backend.md` yazıldı. 5 tapşırıq var:
  1. IP qaydaları;
  2. DB cədvəlləri (006) + store;
  3. Engine + iptables idxalı;
  4. REST v2 + v1 adapterləri + `FIREWALL_ENGINE`;
  5. sənədlər və runbook.

  Kodun hamısı əvvəlcə scratchpad-da yazıldı. `bash scripts/test-with-postgres.sh` → `ok` `…/api/rest`, `…/firewall`, `…/store`, `…/nft` (real Postgres 16 və `nft -c` ilə). Repo-da kod dəyişməyib.
- **Davranış qərarı:** nft rejimində rezerv admin portlarını (3007, 5432, 8080, 8443) publik açmaq 400 ilə rədd olunur. Köhnə iptables yolu buna icazə verirdi. Default `iptables` rejimində heç nə dəyişmir.
- **Yoxlanmayıb:** privileged konteynerdə real kernel end-to-end sınağı. İstifadəçi bu sınağı rədd etdi, ona görə o, P3b-1 runbook-una (staging) köçürüldü.
- **Davam:** P3b-1 icrası, sonra P3b-2 (iptables → nft keçidi, fail2ban nftables, boot unit, installer).

### Eyni sessiyanın davamı (2026-10-13): P3b-1 icra olundu
- **Nəticə:** Task 1–4 commit-ləndi (`76a1316`, `70f656f`, `42fcd9b`, `b3d267f`), Task 5 sənədlərdir. `bash server/scripts/test-with-postgres.sh` → `ok` `…/api/rest` (0.669s, real DB), `…/firewall`, `…/store`, `…/nft`; exit 0. Compose config validdir. Köhnə fayllarda (`handlers.go`, `firewall_handlers.go`, `main.go`, compose) yalnız əlavələr var (88 sətir).
- **Default `FIREWALL_ENGINE=iptables`:** heç bir serverin davranışı dəyişmir.
- **Davam:** staging-də `docs/runbooks/p3b1-firewall-engine.md`. Sonra P3b-2 planı: iptables `INPUT DROP`-dan keçid, fail2ban nftables, boot unit, installer-in `nftables` paketi, nft-dən iptables-ə geri qayıdanda cədvəlin silinməsi.

### Eyni sessiyanın davamı (2026-10-13): P3b-1 final review
- **Review (opus):** "With fixes". Critical yoxdur, 4 Important var. Hamısı RED→GREEN ilə düzəldildi:
  1. Startup-da köhnə `novusgate-vpn-*` FORWARD qaydaları nft tətbiq olunmazdan əvvəl silinirdi. İndi yalnız ilk uğurlu apply-dan sonra silinir (`Engine.AfterApply`).
  2. Uğursuz reconcile (expiry, VPN, şəbəkə/node, startup) itirdi. İndi `ReconcileOrRetry` 15 saniyədən 5 dəqiqəyə qədər backoff ilə təkrar cəhd edir.
  3. Allow/block ziddiyyəti:
     - iptables-də əvvəlki ACCEPT-i sonrakı DROP üstələyən idxal rədd edilir;
     - blokun içindəki allow hər iki istiqamətdə 400 qaytarır;
     - `wg0` peer endpoint-ləri hər apply-da qorunur (`Engine.Protect`).
  4. Runbook-a nft rejiminin məhdudiyyətləri və iptables-ə qayıdışın məcburi addımları yazıldı.

  Suite: `ok` `…/api/rest`, `…/firewall`, `…/store`, `…/nft`. 7 yeni test `-v` ilə PASS-dır, heç biri skip olmayıb.
- **Minor-lar:** spec §6b-yə köçürüldü. Əvvəldən mövcud bug da oradadır: panel-in `DELETE /firewall/host/rules` çağırışına uyğun route yoxdur.

### Eyni sessiyanın davamı (2026-10-13): P3b-2 planı
- **Nəticə:** `docs/superpowers/plans/2026-10-13-p3b2-firewall-cutover.md` yazıldı. 7 tapşırıq:
  1. engine-in hazır olma şərti;
  2. host yoxlaması və iptables INPUT-un nftables-ə təhvili;
  3. REST minor-ları;
  4. legacy rejimdə xüsusi SSH portunun qorunması;
  5. M5 və M10;
  6. `setup-firewall.sh` (boot unit, fail2ban, revert);
  7. sənədlər və runbook.

  Kod dəyişməyib.
- **Davam:** planın icrası. Spec §6b.4 (Allow IP-nin admin portlarını açması) istifadəçinin qərarını gözləyir.

### Eyni sessiyanın davamı (2026-10-13): P3b-2 icra olundu
- **Nəticə:** 7 tapşırığın hamısı commit-ləndi (`2854f01`, `d3972ba`, `033d080`, `d252b87`, `331dc34`, `f22aaaa` + sənədlər).
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → `ok` `…/api/rest`, `…/firewall`, `…/store`, `…/nft`;
  - `setup-firewall_test.sh` → `OK`;
  - `nft-versions-check.sh` → `NFT-VERSIONS-OK` (nft 1.0.2, 1.0.6, 1.0.9, snapshot daxil);
  - web `tsc --noEmit` → exit 0.
- **Default iptables rejimində davranış dəyişikliyi:**
  - Close Port/Delete aşkarlanan SSH portlarını qoruyur (403);
  - `setup-firewall.sh` `nftables` paketini və boot unit-i quraşdırır (ruleset faylı olmadan unit heç nə etmir) və fail2ban `jail.d/novusgate.local` faylını yazır;
  - panel-in Delete düyməsi işləyir.
- **Yoxlanmayıb:** real host (reboot, Update, fail2ban, geri qayıdış). `docs/runbooks/p3b2-firewall-cutover.md` staging-də icra olunmalıdır.
- **Davam:** staging runbook. Sonra P2 və ya P5/P6 (UI kit), istifadəçinin seçiminə görə.
- **Final review (opus):** "With fixes", 1 Important və 10 Minor. 3 minor effektinə görə Important-a qaldırıldı. Hamısı RED→GREEN ilə düzəldildi:
  1. INPUT təhvili yalnız boot faylı yazılandan sonra baş verir. Əvvəl `Persist` xətası olsa, reboot-dan sonra host açıq qala bilərdi.
  2. Qaydalar nömrə ilə yox, spec ilə silinir. Bu, fail2ban ilə yarışın qarşısını alır.
  3. `REJECT` ban-ları və başqa alətlərin zəncirlərinə jump-lar saxlanılır.
  4. iptables rejimində apt/systemctl xətası `setup-firewall.sh`-ı dayandırmır, nft rejimində isə dayandırır.

  Qalan 7 minor P3c/P7 üçün ledger-dədir.

### Eyni sessiyanın davamı (2026-10-13): P2 bölgüsü və P2a planı
- **Nəticə:**
  - `docs/superpowers/specs/2026-10-13-p2-backend-core-design.md`: P2 dörd alt-plana bölündü:
    - P2a: kontrakt + baqlar;
    - P2b: müşahidə;
    - P2c: WireGuard + reconciler + expiry;
    - P2d: servis qatı + vahid xəta + OpenAPI.
  - `docs/superpowers/plans/2026-10-13-p2a-contract-and-bugs.md` yazıldı (8 tapşırıq).
  - Kod dəyişməyib.
- **Kod xəritəsindən yoxlanılan faktlar:**
  - startup log-u DB parolunu açıq yazır (`maskDatabaseURL` heç nə etmir);
  - fail2ban history-nin regex-i heç vaxt uyğun gəlmir, jail kimi PID götürülür;
  - `AllocateIP` broadcast ünvanını verir;
  - `parseRuleLine` 8–9 sahəli sətirdə panic edir və "opt" sütunsuz formatı səhv oxuyur.
- **Davam:** P2a planının icrası.

### Eyni sessiyanın davamı (2026-10-13): P2a icra olundu
- **Nəticə:** Task 1–7 commit-ləndi:
  - `646ce20`: kontrakt snapshot-ları;
  - `10f49ff`: B14;
  - `5802f79`: B22;
  - `7d798ff`: B16;
  - `4fb3ec9`: B21;
  - `42f79b2`: DB parolunun maskalanması;
  - `f816289`: frontend-in hər iki xəta formasını oxuması.
- **Yoxlamalar:**
  - `bash server/scripts/test-with-postgres.sh` → `ok` `cmd/control-plane`, `api/rest`, `firewall`, `store`, `nft`, `wireguard`;
  - kontrakt testi iki ardıcıl run-da eyni nəticə verdi;
  - golden fayllarda açar yoxdur;
  - web `tsc --noEmit` → exit 0;
  - biome diaqnostikalarının sayı dəyişməyib (23/4, hamısı köhnə).
- **Default rejimdə davranış dəyişikliyi:** yalnız spec §3-dəki baq düzəlişləri (`docs/api.md` → "P2a-da dəyişən cavablar").
- **Final review (opus):** "With fixes", 2 Important (+1 Important-a qaldırıldı). Hamısı RED→GREEN ilə düzəldildi (`30bdeb9`):
  - testlər WireGuard-a yalnız `wgInit` və `wgTeardown` seam-ləri vasitəsilə çatır;
  - fail2ban log-u axınla oxunur;
  - DB parolu bütün formalarda maskalanır.

  7 minor ledger-də, P2b–P2d üçün.
- **Davam:** P2b (müşahidə).


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


## Son Dəyişikliklər
| Tarix | Dəyişiklik | Fayllar | Səbəb |
|---|---|---|---|
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
| 2026-10-14 | P2d-1: vahid xəta body-si, sabit kodlar, PUT /nodes validasiyası | api/rest/*, testdata/contract | P2d-1 planı · `761dbc6`..`8325276` |
| 2026-10-14 | P2c: Node.Active, B11 handler-ləri, ExpireNodes, reconciler (shadow/enforce), loop və /health, tək Up, logging qoruyucusu | models, api/rest/*, store, reconciler/*, main.go, compose, logging test | P2c planı · `e5d346a`..`24a499d` |
| 2026-10-14 | P2b: slog logger, request log, panic recovery, /health yoxlamaları, runtime log-ların slog-a keçməsi | shared/logging, api/rest/{middleware,handlers}.go, cmd/control-plane/main.go, compose, 10 runtime fayl | P2b planı · `b1fda2b`..`bdbce97` |
| 2026-10-13 | P2a: kontrakt snapshot testləri, B14/B16/B21/B22, DB parolunun maskalanması, frontend xəta helper-i | api/rest/*, store/store.go, wireguard/manager.go, cmd/control-plane/main.go, web/src/api/errors.ts + 5 səhifə, scripts/update-contracts*.sh | P2a planı · `646ce20`..`f816289` |
| 2026-10-13 | P3b-2: hazır olma şərti, host yoxlaması, INPUT təhvili, REST minor-ları, legacy SSH qoruması, M5/M10, `setup-firewall.sh` (boot unit, fail2ban, geri qayıdış) | firewall/{engine,cutover}.go, api/rest/*, store/firewall.go, netctl/nft/{compile,validate}.go, scripts/nft-versions-*.sh, deployments/docker/setup-firewall.sh, web/src/api/client.ts | P3b-2 planı · `2854f01`..`f22aaaa` |
| 2026-10-13 | P3b-1 review fix: retry, legacy VPN sırası, allow/block ziddiyyəti, wg0 endpoint qoruması, runbook | server/internal/controlplane/firewall/{engine,iptables_import}.go, api/rest/{firewall_engine,firewall_handlers}.go, testlər, docs/runbooks/p3b1-firewall-engine.md, docs/api.md, docs/architecture.md, spec §6b | P3b-1 final review Important 1–4 |

**Final review sonrası testlər:** Center `# tests 24 · # pass 24 · # fail 0` (fix dalğasının implementer-i icra edib); Go və shell dəyişməyib (final reviewer təkrar icra etdi: yaşıl).

**P3/P7 planlarına ötürülənlər:** panel-dən xüsusi SSH portu bağlana bilər (`protectedPorts` yalnız 22) → P3; `unhandledRejection` handler-i gələcək asılmaları gizlədə bilər, reinstall catch-də SSH bağlantısı sızır → P7.
