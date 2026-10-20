# API

## Firewall v2 — `/api/v1/firewall/v2/*` (P3b-1)

Bütün sorğular `Authorization: Bearer <token>` tələb edir.

Dəyişiklik edən sorğular **default olaraq təsdiq gözləyir**: cavabda `pending.id` və `pending.deadline` (60 saniyə) qaytarılır.
- `POST /confirm/{id}` gəlməsə, host qaydaları avtomatik geri qaytarılır və heç nə DB-yə yazılmır.
- `?confirm=false` dəyişikliyi dərhal yekunlaşdırır.

| Method | Path | Body | Cavab |
|---|---|---|---|
| GET | `/firewall/v2/state` | — | `mode`, `services`, `ip_rules`, `forwards`, `egress_node_ids`, `pending`, `ssh_ports`, `egress_interface`, `host_error` |
| GET | `/firewall/v2/preview` | — | `script` (nft), `warnings`; bütün rejimlərdə işləyir |
| POST | `/firewall/v2/services` | `protocol` (tcp\|udp), `port_from`, `port_to`, `sources[]`, `interface`, `comment` | `item`, `pending`, `warnings` |
| DELETE | `/firewall/v2/services/{id}` | — | eyni |
| POST | `/firewall/v2/ip-rules` | `action` (block\|allow), `prefix`, `protocol`, `ports`, `expires_at`, `comment` | eyni |
| DELETE | `/firewall/v2/ip-rules/{id}` | — | eyni |
| POST | `/firewall/v2/forwards` | `protocol`, `public_port`, `target_ip` (VPN node), `target_port`, `comment` | eyni |
| DELETE | `/firewall/v2/forwards/{id}` | — | eyni |
| PUT / DELETE | `/firewall/v2/egress/{nodeId}` | — | node-un serverdən internetə çıxışını (full tunnel) açır və ya bağlayır. Açıq olanda node-un config-i (`/nodes/{id}/config`, `/qrcode`, `install.sh`) `AllowedIPs = 0.0.0.0/0` və `DNS = 1.1.1.1` ilə gəlir (P8, 2026-10-15); cihazda config yenidən yüklənməlidir |
| POST | `/firewall/v2/confirm/{id}` | — | `{"status":"confirmed"}` |
| GET | `/firewall/v2/live` | — | `mode`, `table_loaded`, `counters[]` (`chain`, `rule`, `comment`, `packets`, `bytes`), `dropped[]` (`address`, `seconds_ago`), `conntrack` (`available`, `count`, `max`, `by_protocol`, `tcp_states`, `truncated`), `error`. Bütün rejimlərdə 200 qaytarır; nft cədvəli yoxdursa yalnız conntrack doldurulur (P3c, 2026-10-15) |
| GET | `/firewall/v2/history?limit=50` | — | `entries[]`: `id`, `created_at`, `username`, `action` (`METHOD path`, `baseline` və ya `restore …`), `added[]`, `removed[]` (oxunaqlı sətirlər, əvvəlki yazı ilə müqayisədə). Ən yenisi birinci, `limit` ən çox 200. nft engine olmadan 409 `firewall_disabled` |
| POST | `/firewall/v2/history/{id}/restore` | — | adi dəyişiklik kimi işləyir: `item` (`{"id"}`), `pending`, `warnings`, `?confirm=false` də keçərlidir. Servislər, IP qaydaları və forward-lar qaytarılır; müddəti bitmiş IP qaydaları qaytarılmır. Tunel rejimləri (şəbəkə və cihaz ayarları) bərpa olunmur: internet çıxışı olan cihazlar hazırkı kimi qalır. Tapılmayan və ya səhv ID üçün 404 |

**Status kodları:**
- **400** — yanlış giriş və ya rədd edilmiş dəyişiklik (`firewall change rejected`). Səbəblər:
  - lockout cəhdi: sorğu edənin ünvanı və ya admin şəbəkəsi (`wg0`) peer-lərinin WireGuard endpoint-ləri;
  - rezerv admin portu;
  - WireGuard portu;
  - blokun içində qalan allow, hər iki istiqamətdə (bloklar allow-dan əvvəl yoxlanılır).
- **404** — qeyd tapılmadı.
- **409** — dəyişiklik indi qəbul oluna bilmir. Səbəblər:
  - engine `nft` rejimində deyil;
  - engine hələ başlayır (`firewall engine is starting`), yəni iptables idxalı bitməyib və ya host hazır deyil;
  - başqa bir dəyişiklik təsdiq gözləyir;
  - əvvəlki rollback timer hələ aktivdir;
  - eyni `protocol` və `public_port` üçün forward artıq var (`… is already forwarded`).
- **410** — dəyişikliyin müddəti bitib və o geri qaytarılıb.
- **500** — host-da tətbiq xətası.

## Köhnə firewall endpoint-ləri `FIREWALL_ENGINE=nft` rejimində

`/firewall/host/*` və `/system/fail2ban/*permanent*` endpoint-ləri eyni request və cavab formalarını saxlayır, amma engine cədvəllərindən istifadə edir. Fərqlər:
- `GET /firewall/host/rules` INPUT zəncirini sintetik qurur. Struktur qaydalar (SSH, WireGuard, admin portları) `protected: true` olur və `force` ilə də silinmir.
- Rezerv admin portlarını (3007, 5432, 8080, 8443) publik açmaq 400 qaytarır.
- `POST /firewall/host/import` 409 qaytarır. `GET /firewall/host/export` `nft list table inet novusgate` çıxışını verir.
- Siyahıda 51820–51900 aralığından kənarda olan şəbəkə portları ayrıca qorunan WireGuard sətri kimi görünür. Tək IPv6 ünvanı `/128`-siz göstərilir.

## Allow IP və admin portları (spec §6b.4, 2026-10-14)
Allow qaydası admin (3007, 5432) və API (8080, 8443) portlarını heç vaxt açmır. Bu iki rejimdə də belədir:
- `POST /firewall/v2/ip-rules` və `POST /firewall/host/ip/allow` bu TCP portlarından birini əhatə edən `ports` üçün **400** qaytarır: `port N is reserved for VPN-only admin services`. Block qaydaları və UDP təsirlənmir.
- Bütöv ünvana Allow (`ports` boş) qəbul olunur, amma admin və API portlarına şamil olunmur:
  - nft rejimində kompilyator allow-lardan əvvəl `tcp dport { 3007, 5432, 8080, 8443 } counter drop` qoyur;
  - iptables rejimində `setup-firewall.sh` mangle `PREROUTING`-də `NOVUSGATE-ADMIN` zəncirini qurur (IPv4 və IPv6).
- Bu dəyişiklikdən əvvəl yaradılmış allow qaydaları silinmir, sadəcə admin portlarına təsir etmir.

## Köhnə firewall endpoint-ləri `FIREWALL_ENGINE=iptables` rejimində
- Close Port və Delete aşkarlanan bütün SSH portlarını (`sshd -T`, `ss`) qoruyur və `force` olmadan **403** qaytarır. Əvvəllər yalnız 22 qorunurdu.
- Panel qaydanı `POST /firewall/host/rules/delete` ilə silir. Əvvəllər panel qeydiyyatdan keçməmiş `DELETE /firewall/host/rules` route-unu çağırırdı.

## Kontrakt testləri (P2a)
- **Snapshot-lar:** `server/internal/controlplane/api/rest/testdata/contract/*.json`. Hər faylda status, `Content-Type` və normallaşdırılmış body saxlanılır: UUID, vaxt, WireGuard açarı və token dəyişənlərlə əvəzlənir.
- **Test:** `TestContract` (`contract_test.go`) real Postgres üzərində işləyir. Host əmrlərinin hamısı stub-dır.
- **Yeniləmə:** `bash server/scripts/update-contracts.sh`. Bu skript yalnız `TestContract`-ı `-update` ilə işlədir. Hər fərq API dəyişikliyidir və commit-də əsaslandırılmalıdır.

## P2a-da dəyişən cavablar
- **Boş siyahılar `null` əvəzinə `[]` qaytarılır:** `GET /networks`, `GET /networks/{id}/nodes`, `GET /users`, `GET /system/fail2ban/ban-history` (`history`), `GET /system/fail2ban/permanent-bans` (`permanent_bans`).
- **`GET /system/fail2ban/ban-history`:**
  - Ban, "Restore Ban" və Unban qeydləri real olaraq qaytarılır, ən yenisi əvvəldə;
  - `jail` sahəsi `[jail]` adıdır, PID deyil;
  - `?jail=` yalnız filtrdir, shell-ə ötürülmür;
  - `?limit=` ən yeni N qeydi saxlayır.
- **`GET /system/fail2ban/logs`:** Unban sətirləri `"action":"unban"` kimi işarələnir.
- **`GET /system/fail2ban/whitelist`:** `whitelist`-də yalnız IP, CIDR və host adları qalır; başlıq sözləri və ağac simvolları çıxarılır.
- **Firewall v1 siyahısı:** "opt" sütunu olmayan iptables (nf_tables) formatı düzgün oxunur, qısa sətirlər panic etmir.

## `GET /health` (P2b)
Publikdir (auth tələb etmir) və **həmişə 200** qaytarır. Vəziyyət `status` sahəsindədir, səbəbi `checks` göstərir. Xəta mətni qaytarılmır.

**2026-10-14-dən (istifadəçi qərarı):** `checks` yalnız iki halda görünür: düzgün `X-API-Key` və ya etibarlı panel sessiyası (`Authorization: Bearer`). Digər çağırışlar yalnız `{"status":"…","version":"0.7.0"}` alır. `status` yenə bütün yoxlamalara əsasən hesablanır, ona görə monitorinq dəyişmir. Panelin nginx-i `/health`-ə API açarını əlavə etmir.

```json
{"status":"healthy","version":"0.7.0","checks":{
  "database":{"ok":true},
  "wireguard":{"ok":true,"interfaces":{"wg0":"up","wg1":"up"}},
  "firewall":{"ok":true,"mode":"nft","ready":true,"pending":false}}}
```
- **`status`:** `healthy` və ya `degraded`. Bunlardan biri olanda `degraded` qaytarılır: DB cavab vermir; bir şəbəkənin interfeysi `down`-dır; nft engine hazır deyil.
- **`checks.firewall.ready` və `pending`:** yalnız `FIREWALL_ENGINE=nft` olanda görünür.
- **Reconciler yoxlaması** P2c-də əlavə olunacaq.

## P2c dəyişiklikləri
- **`GET /health`:** reconciler işləyəndə `checks.reconciler {ok, mode, last_run, pending}` əlavə olunur. `pending` shadow rejimində enforce-un edəcəyi əlavə və yeniləmələrin sayıdır (vaxtı keçmiş peer-lərin silinməsi hər iki rejimdə edilir). `ok: false` olanda `status: degraded` qaytarılır.
- **`PUT /nodes/{id}`:** cavab forması dəyişmir. Node aktiv olanda (məsələn gələcək `expires_at` verildikdə) peer əlavə olunur, aktiv olmayanda silinir (B11).
- **`POST /nodes/{id}/rotate-key`** (operator, 2026-10-19, VLAN planı M4): cihaza yeni açar cütü. Əvvəl köhnə peer interfeysdən silinir (alınmasa 500, heç nə dəyişmir), sonra DB-də açar və `config_routes = ''`, aktiv cihaz üçün yeni peer. Cavab: node (`config_outdated: true`, `has_config: true`); yeni konfiq `GET /nodes/{id}/config` ilə alınır. Köhnə konfiq dərhal işləməz olur. 404: cihaz yoxdur. 409 `rotate_own_device`: sorğu bu cihazın özündən gəlir (açarı başqa cihazdan dəyişin). 500 `rotate_peer_not_added`: açar dəyişdi, amma yeni peer əlavə olunmadı ("Bağlantını bərpa et"). Eyni cihaz üçün rotasiyalar növbə ilə gedir.
- **Vaxtı keçmiş node** ən geci 15 saniyəyə `status: "expired"` alır və peer-i silinir, panel açılmasa belə.

## Xəta formatı (P2d-1)
Bütün `/api` xəta cavabları bu formadadır (`/api`, `/api/` ilə başlayan və sonunda `/` olan yollar da daxil). Bu formaya aid olmayanlar:
- SPA (`/` altındakı digər yollar);
- mux-un təmizlənməmiş yollar üçün verdiyi `301` yönləndirməsi (`//` və ya `..` olan yol).

Forma:

```json
{"error":{"code":"cidr_overlap","message":"CIDR 10.66.0.0/25 overlaps with existing network 'office' (10.66.0.0/24)"}}
```

- **`code`** sabit snake_case dəyərdir, client ona görə qərar verir. Bir dəfə buraxılan kod heç vaxt adını dəyişmir.
- **`message`** insan üçündür, mətni əvvəlki kimidir.
- **Köhnə `{"error":"..."}` forması artıq qaytarılmır.** Web hər iki formanı oxuyur (`web/src/api/errors.ts`). Center server qeydiyyatında yalnız `config` sahəsini oxuyur, xəta body-sinə baxmır.

**Default kodlar (HTTP statusa görə):** 400 `bad_request` · 401 `unauthorized` · 403 `forbidden` · 404 `not_found` · 405 `method_not_allowed` · 409 `conflict` · 410 `gone` · 500 `internal_error` · 502 `bad_gateway` · 503 `unavailable` · digərləri `error`.

**Xüsusi kodlar:**

| Kod | Status | Harada |
|---|---|---|
| `invalid_request_body` | 400 | oxunmayan JSON body |
| `invalid_credentials` | 401 | login: istifadəçi və ya parol səhvdir |
| `invalid_token` | 401 | sessiya tokeni tapılmadı, vaxtı bitib və ya ləğv olunub |
| `too_many_attempts` | 429 | login: bu IP-dən 15 dəqiqədə 10 uğursuz cəhd (`Retry-After` başlığı ilə) |
| `invalid_old_password` | 400 | parol dəyişmə, köhnə parol səhvdir (P4a-da 401-dən 400-ə keçdi, B15) |
| `forbidden` | 403 | parol dəyişmə: body-dəki `username` sessiya istifadəçisi deyil |
| `invalid_enrollment_token` | 401 | checkin: enrollment tokeni yanlışdır, işlənib, vaxtı bitib və ya başqa node-undur |
| `cidr_overlap` | 409 | şəbəkə yaratma |
| `admin_network_protected` | 403 | wg0-ın silinməsi |
| `protected_rule` | 403 | Close Port / Delete: qorunan port və ya qayda |
| `invalid_status` | 400 | `PUT /nodes/{id}`: status `pending`, `online`, `offline` və ya `expired` olmalıdır |
| `invalid_expires_at` | 400 | `PUT /nodes/{id}`: RFC 3339 vaxtı olmalıdır (`toISOString()` qəbul olunur) |
| `firewall_disabled` | 409 | engine `nft` rejimində deyil |
| `firewall_not_ready` | 409 | engine hələ başlayır |
| `firewall_change_pending` | 409 | başqa dəyişiklik təsdiq gözləyir |
| `firewall_rollback_armed` | 409 | əvvəlki rollback timer aktivdir |
| `conflict` | 409 | dublikat forward |
| `firewall_rejected` | 400 | lockout qoruması, rezerv port, blokun içində allow |
| `firewall_change_expired` | 410 | dəyişiklik təsdiqsiz geri qaytarılıb və ya id tapılmadı |
| `firewall_engine_enforcing` | 409 | nft rejimində iptables importu |
| `method_not_allowed` | 405 | mövcud `/api` yolu, səhv method (`Allow` başlığı ilə) |

200 cavablarının içindəki `error` sahələri (fail2ban, `/health`, `host_error`, sync `errors`) bu formata aid deyil.

## OpenAPI (P2d-2)
- **`GET /api/v1/openapi.json`** (Bearer tələb edir): bütün REST API-nin OpenAPI 3.0.3 sənədi.
- **Necə qurulur:** sənəd əl ilə yazılmır. `server/internal/controlplane/api/rest/openapi.go`-dakı `docOps` cədvəli və Go tipləri (`models.Network`, `models.Node`, `FirewallStatus`, request tipləri) əsasında reflection ilə qurulur.
- **Golden nüsxə:** `server/internal/controlplane/api/rest/testdata/openapi.json`. `bash server/scripts/update-contracts.sh` ilə yenilənir, hər fərq API dəyişikliyidir.
- **Qoruyan testlər:**
  - `TestEveryRouteIsDocumented`: qeydiyyatdan keçmiş hər route sənəddə olmalıdır, tərsinə də;
  - `TestContract`: hər kontrakt-test cavabı sənədin sxeminə qarşı yoxlanılır (`assertMatchesSpec`). Kontrakt testi olmayan endpoint-ləri yalnız golden diff qoruyur.
- **DTO-lar (P2d-3):** bütün request və response body-ləri adlı Go tipləridir (`dto_requests.go`, `dto_system.go`, `dto_fail2ban.go`, `dto_firewall.go`). Sənəddə ümumi `object` kimi yalnız iki yer qalır: `/api/v1/openapi.json`-un özü və v2 dəyişiklik cavabının `item` sahəsi (yaradılan qeyd, `{"id"}` və ya `{"node_id","egress"}`).
- **Şərti açarlar:** bəzi açarlar yalnız müəyyən halda gəlir (məsələn fail2ban jail sayğacları, `firewall.ready`, v2 state-də `host_error` və ya `ssh_ports`/`egress_interface`). Sxemdə onlar `required` deyil. Mövcud olanda `0`, `false`, `""` və `[]` real dəyərdir.
- **Əlavə status:** `PUT /system/fail2ban/jail/settings` ayarların bir hissəsi tətbiq olunmayanda 206 qaytarır (`status: "partial"`, `errors`). Bu status sənəddə var (`docExtraResponses`).
- **Məhdudiyyət:** request sxemlərində `required` yoxdur: Go hər sahəni isteğe bağlı decode edir, default-ları handler verir. `GET /debug/wireguard/{id}`-in 404-ü də vahid formadadır (`not_found`).
- **İstifadə:** P5 web client tiplərini bu sənəddən `openapi-typescript` ilə yaradacaq.

## `/api` fallback (P2d-2)
- **Naməlum `/api/...` yolu:** 404 `not_found`. Əvvəl bu yol SPA-ya düşürdü.
- **Mövcud yol, səhv method:** 405 `method_not_allowed` və `Allow` başlığı, məsələn `Allow: GET, POST`.
- **Token olmadan:** auth middleware əvvəl cavab verir (401).
- **SPA-nın öz `Invalid path` 400 cavabı** plain text olaraq qalır. `/health` `/api`-dən kənardadır.

## Sessiyalar və login (P4a)
- **`POST /api/v1/auth/login`** (`{username, password}`): yeni sessiya yaradır və `{token, username}` qaytarır. `username` daxil olan istifadəçinin adıdır; əvvəl həmişə env-dəki admin adı qayıdırdı.
- **Token:** 64 simvol hex. `Authorization: Bearer <token>` ilə göndərilir. Sessiya 24 saat yaşayır və istifadə ilə uzanmır. Control-plane restart olanda sessiyalar qalır, çünki DB-də saxlanılır.
- **`POST /api/v1/auth/logout`** → 204: cari sessiyanı ləğv edir.
- **Sessiyanın ləğv olunduğu hallar:**
  - logout;
  - istifadəçinin silinməsi (bütün sessiyaları gedir);
  - parol dəyişməsi (həmin istifadəçinin digər sessiyaları gedir, dəyişikliyi edən sessiya qalır).

  Ləğv olunmuş və ya vaxtı bitmiş token `401 invalid_token` alır.
- **`PUT /api/v1/auth/password`** (`{oldPassword, newPassword}`, `username` isteğe bağlıdır): parol həmişə sessiya istifadəçisinin parolu dəyişir. Body-də başqa `username` göndərilsə, `403 forbidden` qayıdır. Səhv köhnə parol `400 invalid_old_password` qaytarır.
- **Login limiti:** bir IP-dən 15 dəqiqədə 10 uğursuz login olandan sonra `429 too_many_attempts` qayıdır, düzgün parol olsa belə. `Retry-After` neçə saniyə gözləmək lazım olduğunu deyir. Uğurlu login həmin IP-nin sayğacını sıfırlayır. Sayğac yaddaşdadır, restartda sıfırlanır.
- **Açıq (auth tələb etməyən) yollar:** yalnız `/health` və `/api/v1/auth/login`, dəqiq uyğunluqla. Əvvəl `/login` ilə bitən istənilən yol auth-dan keçirdi.

## Node enrollment və same-origin (P4b)
- **`GET /api/v1/nodes/{id}/install.sh`** (panel sessiyası tələb edir): hər çağırış yeni, bir dəfəlik, 15 dəqiqəlik enrollment tokeni yaradır və onu skriptə yazır. Skript bu ardıcıllıqla işləyir:
  1. WireGuard quraşdırılır;
  2. `wg0.conf` quoted heredoc ilə yazılır, icazəsi `600`;
  3. `wg-quick@wg0` qaldırılır;
  4. node VPN üzərindən `http://<hub ünvanı>:8080/api/v1/nodes/{id}/checkin`-ə `X-Enrollment-Token` başlığı ilə checkin edir (2 saniyə ara ilə 30 cəhd).

  Heç bir port internetə açılmır.
- **`POST /api/v1/nodes/{id}/checkin`:**
  - panel sessiyası ilə əvvəlki kimi işləyir;
  - sessiya olmadıqda `X-Enrollment-Token` həmin node-un işlənməmiş və vaxtı bitməmiş tokeni olmalıdır, əks halda `401 invalid_enrollment_token`. Token ilk uğurlu istifadədə işlənmiş sayılır.

  Başlıq yalnız bu yolda və `POST` method-unda işə yarayır, başqa heç bir endpoint-i açmır.
- **Checkin label-ləri:** `wireguard_` ilə başlayan açarlar nəzərə alınmır. Əvvəl checkin `wireguard_private_key`-i əvəz edə bilirdi.
- **Same origin:**
  - panel API-ni öz nginx-i üzərindən `/api/v1` kimi çağırır;
  - control-plane artıq `Access-Control-*` başlıqları göndərmir;
  - `OPTIONS` sorğusu digər səhv method-lar kimi `405` alır.

## Node cavabları (P4c)
- **`labels.wireguard_private_key` artıq qaytarılmır.** Key şifrələnmiş ayrıca sütunda saxlanılır.
- **Yeni sahə `has_config` (bool):** server node-un private key-ini saxlayırsa `true` olur. Belə node üçün `GET /nodes/{id}/config`, `/qrcode` və `/install.sh` işləyir. İmport olunmuş peer-lər üçün `false`-dur.
- **Checkin və server yaratma** `wireguard_*` label-lərini qəbul etmir, ona görə key label vasitəsilə yazıla bilməz. Startup miqrasiyası sütunda artıq olan key-i label ilə əvəz etmir.

## API səthinə sonrakı əlavələr
- **HEAD:** hər GET yolu HEAD-ə də cavab verir: eyni status və başlıqlar, body yoxdur. Yan təsiri olan GET-lər HEAD-də onu etmir (`install.sh` token yaratmır). 405 cavabındakı `Allow` başlığında GET varsa, HEAD də göstərilir.
- **`/api` və sonunda `/` olan `/api/...` yolları:** JSON `404 not_found`.
- **Request log** bütün sorğuları yazır, o cümlədən mux-un 301 yönləndirmələrini.
- **OpenAPI sənədinə əlavələr:**
  - query parametrləri (`lines`, `jail`, `limit`, `chain`, `confirm`);
  - `X-API-Key` (`apiKey`) və checkin üçün `X-Enrollment-Token` security sxemləri;
  - QR üçün `format: binary`;
  - `NodeStatus` enum-u;
  - nullable `$ref`-lər `type: object` ilə;
  - `ssh_ports` və `egress_interface` nullable deyil, sadəcə isteğe bağlıdır.

## `GET /api/v1/nodes/{id}/traffic` (P8, 2026-10-15)
Node-un trafik tarixçəsi, intervallar üzrə baytlar.
- **Query:** `range` = `24h` (default, 5 dəq intervallar, 288 nöqtə), `7d` (1 saat, 168 nöqtə) və ya `30d` (4 saat, 180 nöqtə).
- **Cavab:** `{"node_id","range","bucket_seconds","points":[{"t","rx","tx"}]}`.
  - `t` intervalın başlanğıcıdır.
  - `rx` və `tx` həmin intervalda ötürülən baytlardır, hub-un saydığı kimi.
  - Nümunə olmayan intervallar `0` göstərir.
- **Xətalar:** 400 `invalid_range`, 404 `node not found`.

## Backup-lar — `/api/v1/backups` (P8, 2026-10-15)
Manual backup-lar. Hər backup bir `.tar.gz` faylıdır: `db.sql` (`pg_dump`) və `wireguard/*.conf`. Fayllar serverdə `/var/backups/novusgate/panel`-də saxlanılır (qovluq 0700, fayl 0600).

| Method | Path | Cavab |
|---|---|---|
| GET | `/backups` | `{"backups":[{"name","size","created_at"}]}`, ən yenisi birinci |
| POST | `/backups` | 201 `{"name","size","created_at"}`; 409 `backup_running`; 500 (`pg_dump` xətası control-plane log-undadır) |
| GET | `/backups/{name}` | `application/gzip` yükləmə; 404 |
| DELETE | `/backups/{name}` | 204; 404 |

- Ad yalnız `novusgate-backup-YYYYMMDD-HHMMSS.tar.gz` ola bilər, başqa fayl açılmır.
- Backup servisi qurulmayıbsa 503 `backups_disabled` qaytarılır.

## Telegram bildirişləri — `/api/v1/notifications` (P8, 2026-10-15)
| Method | Path | Cavab |
|---|---|---|
| GET | `/notifications/settings` | `{"enabled","chat_id","token_set","node_offline","node_expired","fail2ban_ban","firewall_change"}`. Bot token heç vaxt qaytarılmır. |
| PUT | `/notifications/settings` | Body eyni sahələrdir, `token_set` əvəzinə isə `bot_token` göndərilir. Boş və ya yoxdursa saxlanılan token qalır. 200 yeni ayarları qaytarır. 400 kodları: `invalid_chat_id`, `invalid_bot_token`, `notifications_incomplete` (chat ID və ya token olmadan aktivləşdirmə). |
| POST | `/notifications/test` | 200 `{"status":"sent"}`. 400 `notifications_incomplete`. 502 `telegram_failed` Telegram-ın izahı ilə qaytarılır (məsələn `chat not found`); token mesaja düşmür. 503 `notifications_disabled`. |

- `chat_id`: rəqəmli chat/qrup ID-si (`-100…`) və ya `@kanal`. `bot_token`: `<bot id>:<sirr>` formatında, BotFather-in verdiyi kimi.
- Hadisələr:
  - `node_offline`: 5 dəqiqə handshake olmayanda göndərilir, node qayıdanda da bildiriş gəlir.
  - `node_expired`: reconciler node-u expired edəndə göndərilir. `WG_RECONCILER=off` olarsa bu hadisə göndərilmir.
  - `fail2ban_ban`: `/var/log/novusgate/fail2ban.log`-da yeni `Ban` sətri görünəndə göndərilir.
  - `firewall_change`: `/api/v1/firewall/*` altında GET olmayan uğurlu (2xx) sorğudan sonra göndərilir.
- Eyni hadisə (eyni node, jail+IP) 30 dəqiqə ərzində bir dəfə göndərilir. Firewall dəyişikliklərinin hər biri ayrıca göndərilir.

## `GET /api/v1/firewall/policy-matrix` (2026-10-15)
Şəbəkə×şəbəkə siyasət matrisi; bütün firewall rejimlərində işləyir.
- **Cavab:**
  - `nft_enforcing`;
  - `networks[]` (`id`, `name`);
  - `cells[from][to]` → `verdict` (`allow` / `deny` / `partial`), `reason`, `rules[]` (qayda adları, sıra ilə).
- Qaydalar firewall-un kompilyasiya etdiyi kimi qiymətləndirilir:
  - aktiv qaydalar `priority`, sonra `created_at` sırası ilə yoxlanır, ilk uyğun gələn qalib gəlir;
  - node `/32` ünvanına, custom isə prefiksə çevrilir.
- Default nəticə (2026-10-19, M1-dən bəri bütün rejimlərdə eyni): eyni şəbəkə daxilində `allow`, şəbəkələr arasında `deny`. Qarşılıqlı (`bidirectional`) qayda hər iki istiqamətdə sayılır.

## Şəbəkə DNS-i və hub (2026-10-20, P3)
- `PUT /networks/{id}/dns` və `POST /networks`: `client_dns`-də hər hansı şəbəkənin hub ünvanı 400 `dns_is_hub` (cihazlar hubu onsuz da DNS kimi işlədir; hub özünə ötürərdi).
- Konfiq `DNS` sətri hubun şəbəkədəki ünvanıdır (dinləyici işləyirsə); serverləri dəyişmək konfiqi dəyişmir.
- Şəbəkə JSON-unda (siyahı, detal, yaratma) `dns_served` (bool: hub bu şəbəkə üçün DNS-ə cavab verir) və `dns_error` (cavab vermirsə səbəb; yalnız operator və admin görür, viewer üçün `""`). Saxlanmır, canlı vəziyyətdir.

## `GET/PUT /api/v1/settings/vpn` (2026-10-19, server tərəfli marşrut P1)
- **GET** (bütün rollar): `{pool, next_cidr}` — konfiqlərin marşrutladığı hovuz və yeni şəbəkənin alacağı /24 (`""`: hovuz doludur).
- **P2:** cavabda həm də `endpoint_host` (`""`: IP) və `endpoint_default` (WG_SERVER_ENDPOINT). PUT `{endpoint_host}` — domen (RFC 1123) və ya IPv4, port və sxemsiz; 400 `invalid_endpoint_host`. PUT-da sahələrdən biri kifayətdir, verilməyən dəyişmir. Konfiqlərdə `Endpoint = <host>:<şəbəkə portu>`.
- Review düzəlişi: server ünvanı (IPv4) hovuzun içində ola bilməz — 400 `endpoint_inside_pool`; endpoint-i hovuzun içində olan şəbəkənin konfiqi hovuzu yox, şəbəkələri adla yazır. iptables rejimində `NOVUSGATE-VPN` sonunda `-i wg+ -d <hovuz> -j DROP`: hub tərəfindəki hovuz ünvanlarına (provayderin özəl şəbəkəsi, Docker) yalnız qayda icazə verəndə çatılır (nft-də onsuz da default drop).
- **PUT** (admin) `{pool}`: özəl IPv4 blok, /8–/16, şəbəkə ünvanı ilə yazılmış (10/8, 172.16/12, 192.168/16, 100.64/10 daxilində); 400 `invalid_pool`. Bütün cihaz konfiqləri köhnəlir.
- **`POST /networks`:** `cidr` boş olsa server hovuzdan növbəti boş /24-ü seçir (10/8-də: 10.10.0.0/24, 10.11.0.0/24, …); hovuz doludursa 409 `pool_full`; hovuzdan kənar CIDR 400 `cidr_outside_pool`.
- Konfiq `AllowedIPs`: hovuz + hovuzdan kənar şəbəkələr + qaydanın digər tərəfinin kənar aralıqları; hovuzun içində yeni şəbəkə konfiqi dəyişmir.

## `GET /api/v1/firewall/access-check` (2026-10-19, VLAN planı M3)
"Kim kimi görür?": iki tərəf (şəbəkə, cihaz və ya qrup) arasında, hər iki istiqamətdə. Bütün rollar oxuya bilər.
- **Sorğu:** `from_type`, `to_type` ∈ `network` / `node` / `group`; `from_id`, `to_id` UUID.
- **Cavab:** `from`, `to` (`type`, `id`, `name`, `addresses[]`); `forward` (from əlaqə başladır) və `reverse` (to başladır) → `verdict` (`allow` / `deny` / `partial`), `reason`, `reason_key` (`rule`, `same_network`, `isolated`, `mixed` — tərəfin cihazları fərqli cavab alır, `empty` — cihazsız qrup), `rule` (həlledici qayda), `rules[]`.
- Qiymətləndirmə matrislə eynidir, cihaz-cihaz: qrup üzvlərinə, cihaz `/32`-yə açılır.
- **Xətalar:** 400 (yanlış tip və ya UUID), 404 (şəbəkə/cihaz/qrup tapılmadı).

## Node qrupları — `/api/v1/groups` (P9a, 2026-10-15)
- `GET /groups` → `{groups: NodeGroup[]}`, ada görə sıralı. `NodeGroup`: `id`, `name`, `description`, `created_at`, `members[]` (`node_id`, `name`, `virtual_ip`, `network_id`).
- `POST /groups` `{name, description}` → 201; ad təkrarlanırsa 409 `group_name_taken`.
- `PUT /groups/{id}` → adı və təsviri dəyişir.
- `DELETE /groups/{id}` → 204; VPN qaydası qrupu istifadə edirsə 409 `group_in_use`.
- `PUT /groups/{id}/members` `{node_ids: []}` → üzvləri tam əvəz edir (transaksiya), sonra VPN qaydaları yenidən tətbiq olunur.
- VPN qaydası: `source_type`/`dest_type` üçün yeni dəyər `group`; sorğuda `source_group_id`/`dest_group_id`, cavabda əlavə olaraq `source_group_name`/`dest_group_name`.
- VPN qaydasında custom `0.0.0.0/0` (hər ünvan) 400 ilə rədd edilir — `any` tipi işlədilir (2026-10-19). Kənar IP aralığı yalnız qaydanın digər tərəfindəki cihazların konfiqinə yazılır.
- VPN qaydası `bidirectional` (bool, default `false`): `true` = qarşılıqlı — hər iki tərəf əlaqə başlada bilər (hub əks istiqamətli qaydanı da yazır); `false` = bir tərəfli — yalnız mənbə başlayır, cavablar həmişə qayıdır.
- nft rejimində qrup `set grp_N { type ipv4_addr; }` kimi kompilyasiya olunur; iptables rejimində hər üzv cütü üçün ayrıca qayda yazılır.

## Panel rolları (P9a, 2026-10-15)
- Rollar: `admin` > `operator` > `viewer`. Yoxlama auth-dan sonra `roleMiddleware`-də aparılır, rədd edilən sorğu 403 `forbidden` alır.
- **viewer:** `viewerReads` siyahısındakı GET-lər (şəbəkələr, node-lar, qruplar, firewall vəziyyəti, fail2ban, audit və s.). Dəyişiklik kimi yalnız öz parolunu dəyişə və logout edə bilər. Heç bir siyahıda olmayan GET admin tələb edir; `TestOperatorRoutesExist` təsnif olunmamış GET-i tutur.
- **operator:** şəbəkələr (yarat/sil, server, sync), node-lar (PUT/PATCH/DELETE), qruplar və VPN qaydaları (CRUD + apply). Node config/QR/install.sh-ı ala bilər.
- **admin:** qalan hər şey: istifadəçilər, host firewall, fail2ban, backup, bildirişlər, sessiyalar, debug.
- Həssas GET-lər: `nodes/{id}/config`, `qrcode`, `install.sh` → operator; `backups/{name}`, `debug/wireguard/{networkId}`, `users`, `auth/sessions`, `firewall/host/export`, `notifications/settings` → admin.
- `GET /auth/me` → `{id, username, role}`. Login cavabında da `role` var.
- `POST /users` `role` qəbul edir (default `admin`). `PUT /users/{id}/role` `{role}` istifadəçini qaytarır.
- Son admini aşağı salmaq və ya silmək 409 `last_admin` verir.
- Siyahı `server/internal/controlplane/api/rest/roles.go` faylındadır; `TestOperatorRoutesExist` siyahıdakı hər route-un mövcud olduğunu yoxlayır.

## Limit profilləri — `/api/v1/limits` (P9b, 2026-10-15)
- `GET /limits` → `{profiles, node_limits, enforcing}`:
  - `profiles[]`: `id`, `name`, `down_kbps`, `up_kbps`, `max_connections` (`null` = limitsiz), `schedule[]` (`days` 0=bazar…6=şənbə, `from`/`to` `HH:MM`, `to` `24:00` ola bilər, `to < from` gecə yarısını keçir), `timezone`, `node_ids`, `group_ids`;
  - `node_limits[]`: hər limitli node üçün qüvvədə olan profil (`node_id`, `virtual_ip`, `profile_id`, qrupdan gəlirsə `group_id`);
  - `enforcing`: yalnız nft mühərriki limitləri tətbiq edir; iptables rejimində `false`.
- `POST /limits` → 201; `PUT /limits/{id}` → 200 (bağlı node-lar dərhal yeni limitləri alır); `DELETE /limits/{id}` → 204.
- `PUT /limits/{id}/bindings` `{node_ids, group_ids}` → bağlamaları tam əvəz edir; başqa profildə olan node/qrup bu profilə keçir.
- Xətalar: 400 (validasiya: ad 1–100, sürət 1–100 000 000 kbit/s, bağlantı 1–1 000 000, ən çox 28 pəncərə, naməlum saat qurşağı, heç bir limit/cədvəl yoxdursa), 409 `limit_name_taken`, 409 `limit_in_use` (bağlı profil silinmir), UUID olmayan id → 404, naməlum node/qrup → 400.
- Rollar: GET hamıya, dəyişikliklər operator və admin.
- `GET /firewall/policy-matrix` xanasında yeni `limited` sahəsi: tərəflərdən birində limitli node var və nft limitləri tətbiq edir. Verdikt dəyişmir.

## Trafik kvotası (P9c, 2026-10-15)
- Limit profilində yeni sahələr: `quota_mb` (aylıq, MB = 10⁶ bayt; `null` = kvota yoxdur), `quota_action` (`block` default, `throttle`), `throttle_kbps` (`throttle` üçün məcburi), `quota_reset_day` (1–28, default 1).
- `GET /limits` cavabında `quota_states[]`: `node_id`, `period_start`, `used_bytes`, `warned_at`, `exceeded_at`.
- `POST /nodes/{id}/quota/reset` → 204 (sayğac sıfırlanır, blok/yavaşlatma dərhal götürülür; sayğacı olmayan node üçün də 204); naməlum node və ya UUID olmayan id → 404. Rol: operator.
- `quota_states[].period_end`: dövrün sonu; panel bitmiş dövrün sayğacını boş göstərir.
- Bildiriş ayarlarında yeni `quota_exceeded` açarı (default `true`): 80% və 100%.

## Server idarəsi — `/api/v1/server/*` (P10a, 2026-10-15)
- Yalnız admin; oxumalar da (`sensitiveReads`). Hər dəyişiklik **step-up** tələb edir: `POST /auth/step-up` `{password}` → 204, sessiya 5 dəqiqəlik yüksəldilir. Yanlış parol → **400** `invalid_password` (401 paneli çıxışa atardı); istifadəçi başına 15 dəqiqədə 5 yanlış cəhddən sonra → 429 `too_many_attempts` + `Retry-After`. Step-up olmadan dəyişiklik → 403 `step_up_required`.
- `GET /server/services` → `{services:[{name,state}]}` (docker, fail2ban, `wg-quick@wgN`); `POST /server/services/{unit}/restart` → 204 (yalnız bu siyahı, başqası 400).
- `GET /server/sysctl` → `{keys,values}`; `PUT /server/sysctl` `{values}` → `{confirm_within}` (90 s): dəyişiklik dərhal qüvvədədir, `POST /server/sysctl/confirm` (204) gəlməsə host köhnə dəyərləri bərpa edir. Təsdiq gözləyən dəyişiklik varkən yeni dəyişiklik → 409 `sysctl_pending`; gözləyən dəyişiklik yoxdursa (artıq geri qaytarılıb) confirm → 409 `sysctl_not_pending`. `GET` cavabında `pending` (hostun timer-i) və `pending_until` (bu proses bilirsə). İcazəli açarlar: `net.ipv4.ip_forward` (0/1), `net.ipv4.conf.all.rp_filter` (0–2), `net.netfilter.nf_conntrack_max` (1024–16777216), `net.ipv4.tcp_congestion_control` (bbr/cubic), `net.core.default_qdisc` (fq, fq_codel, pfifo_fast, cake).
- `GET /server/system` → `{hostname,timezone,ntp,ntp_synchronized,kernel,os}`; `PUT /server/system/hostname` `{hostname}`; `PUT /server/system/timezone` `{timezone,ntp}` (IANA adı).
- `GET /server/packages` → `{packages:[{name,version,from,security}]}`; `GET /server/packages/upgrade` → son yeniləmə `{running,started_at,finished_at,ok,output}`; `POST /server/packages/upgrade` `{confirm:"upgrade"}` → 202 (gedən yeniləmə varsa 409 `upgrade_running`). apt `systemd-run --wait --pipe` ilə ayrıca host unit-ində işləyir (update 30 dəq, upgrade 60 dəq limit): docker restart-ı dpkg-ni kəsmir.
- `POST /server/reboot` `{confirm:"reboot"}` → 202, 2 s sonra; yeniləmə gedirsə 409 `upgrade_running`. Docker restart-ı `--no-block` ilə (bu konteyneri də dayandırır).
- `GET /server/network` → `{addresses,routes,links}`: `ip -j` siyahıları olduğu kimi (obyekt massivləri), yalnız oxunur.
- Host komandası uğursuz olanda 500 mesajı `<nə> failed; see the server log` olur: komanda çıxışı, yollar və alət mesajları yalnız log-a yazılır.

## Şəbəkənin klient DNS-i (P10a, 2026-10-15)
- `PUT /api/v1/networks/{id}/dns` `{client_dns}` → 200 `Network`. Vergüllə ayrılmış ən çox 3 IPv4 (IPv6 rədd edilir: tam tunel yalnız `0.0.0.0/0` yönləndirir); `"a, b"` şəklinə salınır; başqa dəyər → 400 `invalid_dns`; boş = default. Rol: operator. Naməlum və ya UUID olmayan id → 404.
- `POST /networks` da `client_dns` qəbul edir (eyni yoxlama).
- `Network` cavablarında yeni `client_dns` sahəsi.
- Konfiqlər: DNS varsa split və tam tunel konfiqlərinə yazılır; yoxdursa tam tunel `1.1.1.1`, split DNS-siz. Cihazlarda olan konfiqlər yenidən endirilənə qədər dəyişmir.

## Şəbəkənin tunel rejimi (2026-10-16)
- `Network` cavablarında `tunnel_mode` (`split`/`full`), `Node` cavablarında `tunnel_override` (`split`/`full`/`""` = şəbəkəyə uyğun). Yeni sahələrdir; mövcud sahələr dəyişməyib.
- `POST /networks` `tunnel_mode` qəbul edir (boş = `split`; başqa dəyər → 400 `invalid_tunnel_mode`). `full` yalnız admin üçündür (operator → 403 `forbidden`).
- `PUT /networks/{id}/tunnel` `{tunnel_mode}` və `PUT /nodes/{id}/tunnel` `{tunnel_override}` → 200 v2 dəyişiklik cavabı: `item` = `{network_id|node_id, tunnel_mode, tunnel_override, affected_nodes}`, `pending`, `warnings`. `affected_nodes` rejimi split↔full dəyişən cihazların sayıdır: onların konfiqi yenidən endirilməlidir. Rol: admin. Səhv dəyər → 400 `invalid_tunnel_mode`, naməlum id → 404.
- nftables rejimində dəyişiklik firewall-dan keçir (`?confirm=false` də işləyir, default təsdiq gözləyir). iptables rejimində yalnız konfiqlər dəyişir (hər şəbəkənin wg-quick PostUp-ı NAT edir); Admin VPN (`wg0`) üçün `full` → 409 `full_tunnel_needs_nft`.
- Tam tunel şəbəkəsində yaradılan cihaz firewall-un çıxış dəstinə dərhal düşür (yaradılandan sonra reconcile).
- `PUT/DELETE /firewall/v2/egress/{nodeId}` işləməyə davam edir: açıq = `full` override; bağlı = split şəbəkədə override yox, full şəbəkədə `split` override.
- nftables rejimində: təsdiq gözləyən dəyişiklik zamanı istənən reconcile (məsələn tam tunel şəbəkəsində yeni cihaz) təsdiqdən sonra da işləyir. Eyni rejim yenidən göndəriləndə dəyişiklik yaranmır (200, `affected_nodes: 0`). Shadow rejimi iptables kimi davranır.
- DOCKER-USER (yalnız nft rejimində, `CutoverIptables`): wg ↔ Docker körpüləri (`docker0`, `br-+`) arası trafik `RETURN` (Docker özü qərar verir), qalan wg trafiki `ACCEPT`. iptables/shadow rejimində start zamanı bu qaydalar silinir.

## Şəbəkə interfeysinin vəziyyəti (2026-10-17)
- `Network` cavablarında `interface_up` (interfeys hostda var) və `interface_error` (son qaldırma uğursuzluğunun səbəbi; uğurda `""`). Şəbəkə yaradılanda interfeys qalxmasa da 201 qaytarılır, səbəb `interface_error`-dadır.
- `POST /networks/{id}/restart` → 200 `Network` (interfeys hostda `wg-quick@wgN` kimi yenidən başladılır, peer-lər DB-dən qaytarılır); qalxmasa 500 `interface_failed` səbəblə. Rol: operator. Naməlum şəbəkə → 404.

## VLAN tipli icazə, M1 (2026-10-19)
- Cihaz konfiqinin `AllowedIPs`-i qaydalardan asılı deyil: öz şəbəkəsi, bütün digər VPN şəbəkələri, qaydalarda adı çəkilən VPN-dən kənar ünvan aralıqları; tam tuneldə `0.0.0.0/0`. Kimin kimə çatdığını yalnız hub-ın firewall-u həll edir, ona görə qayda dərhal işləyir və cavablar həmişə qayıdır.
- `Node` cavablarında `config_outdated` (bool): cihazdakı konfiq hazırkı marşrutlarla uyğun deyil (yeni şəbəkə, tunel dəyişikliyi, bu versiyadan əvvəlki konfiq).
- iptables rejimində də şəbəkələr default ayrıdır: `NOVUSGATE-VPN` qaydalardan sonra hər şəbəkə üçün `-i wgN -o wgN -j RETURN`, sonda `-i wg+ -o wg+ -j DROP` (`novusgate-vpn-isolation`); start-da da tətbiq olunur. Siyasət matrisi hər iki rejimdə eyni default-u göstərir (`isolated`).
