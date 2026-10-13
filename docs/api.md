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
- **400** — yanlış giriş və ya rədd edilmiş dəyişiklik (`firewall change rejected`): lockout cəhdi, rezerv admin portu, WireGuard portu.
- **404** — qeyd tapılmadı.
- **409** — engine `nft` rejimində deyil, başqa bir dəyişiklik təsdiq gözləyir, və ya əvvəlki rollback timer hələ aktivdir.
- **410** — dəyişikliyin müddəti bitib və o geri qaytarılıb.
- **500** — host-da tətbiq xətası.

## Köhnə firewall endpoint-ləri `FIREWALL_ENGINE=nft` rejimində

`/firewall/host/*` və `/system/fail2ban/*permanent*` endpoint-ləri eyni request və cavab formalarını saxlayır, amma engine cədvəllərindən istifadə edir. Fərqlər:
- `GET /firewall/host/rules` INPUT zəncirini sintetik qurur. Struktur qaydalar (SSH, WireGuard, admin portları) `protected: true` olur və `force` ilə də silinmir.
- Rezerv admin portlarını (3007, 5432, 8080, 8443) publik açmaq 400 qaytarır.
- `POST /firewall/host/import` 409 qaytarır. `GET /firewall/host/export` `nft list table inet novusgate` çıxışını verir.
