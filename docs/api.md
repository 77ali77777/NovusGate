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
| PUT / DELETE | `/firewall/v2/egress/{nodeId}` | — | node-un serverdən internetə çıxışını (full tunnel) açır və ya bağlayır |
| POST | `/firewall/v2/confirm/{id}` | — | `{"status":"confirmed"}` |

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

```json
{"status":"healthy","version":"0.1.0","checks":{
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
- **Vaxtı keçmiş node** ən geci 15 saniyəyə `status: "expired"` alır və peer-i silinir, panel açılmasa belə.

## Xəta formatı (P2d-1)
Bütün `/api` xəta cavabları bu formadadır:

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
| `invalid_credentials` | 401 | login, istifadəçi tapılmayanda parol dəyişmə |
| `invalid_old_password` | 401 | parol dəyişmə, köhnə parol səhvdir (status P4-də 400 olacaq, B15) |
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
- **Məhdudiyyət:** request sxemlərində `required` yoxdur: Go hər sahəni isteğe bağlı decode edir, default-ları handler verir. `GET /debug/wireguard/{id}`-in 404 body-si köhnə formadadır (`{"network_id","error"}`), vahid xəta formasında deyil.
- **İstifadə:** P5 web client tiplərini bu sənəddən `openapi-typescript` ilə yaradacaq.

## `/api` fallback (P2d-2)
- **Naməlum `/api/...` yolu:** 404 `not_found`. Əvvəl bu yol SPA-ya düşürdü.
- **Mövcud yol, səhv method:** 405 `method_not_allowed` və `Allow` başlığı, məsələn `Allow: GET, POST`.
- **Token olmadan:** auth middleware əvvəl cavab verir (401).
- **SPA-nın öz `Invalid path` 400 cavabı** plain text olaraq qalır. `/health` `/api`-dən kənardadır.
