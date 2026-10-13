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
