# Data modeli

Migration-lar `server/internal/controlplane/store/migrations_sql/` qovluğundadır. Ardıcıl tətbiq olunur, tətbiq olunanlar `schema_migrations` cədvəlində qeyd edilir. Rollback faylları `store/migrations_rollback/` qovluğundadır və `psql` ilə əl ilə işə salınır.

## `sessions` (007, P4a)
| Sütun | Tip | Qeyd |
|---|---|---|
| `id` | UUID PK | `gen_random_uuid()` |
| `token_hash` | TEXT UNIQUE NOT NULL | bearer tokenin SHA-256 hex-i; token özü saxlanılmır |
| `user_id` | UUID NOT NULL | `users(id)`, `ON DELETE CASCADE` |
| `created_at` | TIMESTAMPTZ | login vaxtı |
| `expires_at` | TIMESTAMPTZ NOT NULL | `created_at + 24h` |
| `last_used_at` | TIMESTAMPTZ | son istifadə (dəqiqədə ən çox bir yenilənmə) |

- **İndekslər:** `idx_sessions_user (user_id)`, `idx_sessions_expires (expires_at)`.
- **Rollback:** `migrations_rollback/007_sessions.down.sql`. Bütün istifadəçilər logout olur. Köhnə binary bu cədvəli oxumur.

## `enrollment_tokens` (008, P4b)
| Sütun | Tip | Qeyd |
|---|---|---|
| `id` | UUID PK | `gen_random_uuid()` |
| `node_id` | UUID NOT NULL | `nodes(id)`, `ON DELETE CASCADE` |
| `token_hash` | TEXT UNIQUE NOT NULL | install skriptindəki tokenin SHA-256 hex-i |
| `created_at` | TIMESTAMPTZ | skriptin yaradıldığı vaxt |
| `expires_at` | TIMESTAMPTZ NOT NULL | `created_at + 15 dəq` |
| `used_at` | TIMESTAMPTZ NULL | checkin-də doldurulur; doludursa token keçərsizdir |

- **İndeks:** `idx_enrollment_tokens_node (node_id)`.
- **Rollback:** `migrations_rollback/008_enrollment_tokens.down.sql`. İşlənməmiş install skriptləri işləməz olur.

## 009 (P4c): node key-ləri və audit istifadəçisi
- **`nodes.private_key_enc` TEXT NULL:** node-un WireGuard private key-i. Format: `v1:…` (AES-GCM) və ya `plain:…` (master açar yoxdursa). Node JSON-da əvəzinə `has_config` (`private_key_enc IS NOT NULL`) qaytarılır.
- **`firewall_audit_log.user_id` UUID NULL:** `users(id)`, `ON DELETE SET NULL`.
- **Rollback (sıra vacibdir):**
  1. control-plane dayandırılır (`docker compose stop control-plane`), əks halda restart olanda 009 yenidən tətbiq olunur;
  2. yeni image və eyni `MASTER_KEY` ilə key-lər label-ə geri yazılır: `docker compose run --rm control-plane keys-to-labels`;
  3. `migrations_rollback/009_node_keys_and_audit_user.down.sql` psql ilə işə salınır, sonra köhnə image başladılır.

  Down faylı key-lər yalnız sütunda olduqca işləməkdən imtina edir.

## `node_traffic_samples` (010, P8)
Node-ların trafik tarixçəsi. Control-plane hər 5 dəqiqədən bir hər node-un kumulyativ WireGuard sayğaclarını yazır və 30 gündən köhnə nümunələri silir.

| Sütun | Tip | Qeyd |
|---|---|---|
| `node_id` | UUID | `nodes(id)`, `ON DELETE CASCADE` |
| `sampled_at` | TIMESTAMPTZ | nümunə vaxtı |
| `rx_bytes`, `tx_bytes` | BIGINT | hub-un bu peer üçün saydığı kumulyativ baytlar |

- PK `(node_id, sampled_at)`, indeks `sampled_at` (retention üçün).
- Sayğac interfeys yenidən qalxanda sıfırlanır; API azalmanı sıfırdan başlayan say kimi hesablayır.
- Rollback: `migrations_rollback/010_node_traffic_samples.down.sql`.

## `notification_settings` (011, P8)
Telegram bildiriş ayarları. Cədvəldə tək sətir var (`id = 1`, `CHECK`).

| Sütun | Tip | Qeyd |
|---|---|---|
| `enabled` | BOOLEAN | default `false` |
| `chat_id` | TEXT | default `''` |
| `bot_token_enc` | TEXT NULL | `NOVUSGATE_MASTER_KEY` ilə möhürlənir, kontekst `notification_settings.bot_token`. Master açar yoxdursa `plain:` prefiksi ilə saxlanılır. |
| `node_offline`, `node_expired`, `fail2ban_ban`, `firewall_change` | BOOLEAN | default `true` |
| `updated_at` | TIMESTAMPTZ | |

- Sətir yoxdursa API default-ları qaytarır: söndürülüb, bütün hadisələr açıqdır, token yoxdur.
- Rollback: `migrations_rollback/011_notification_settings.down.sql`.

## `fw_history` (012, P3c)
Firewall dəyişiklik tarixçəsi. Hər tətbiq olunmuş dəyişiklikdən sonrakı engine vəziyyəti bir sətirdə saxlanılır.

| Sütun | Tip | Qeyd |
|---|---|---|
| `id` | UUID | PK (tətbiq yaradır) |
| `created_at` | TIMESTAMPTZ | indeks `created_at DESC` |
| `user_id` | UUID NULL | `users(id)`, `ON DELETE SET NULL` |
| `action` | TEXT | `METHOD path`, `baseline` və ya `restore <vaxt>` |
| `state` | JSONB | `{"services","ip_rules","forwards","egress_node_ids"}` |

- Ən yeni 200 sətir saxlanılır, köhnələri insert ilə eyni transaksiyada silinir.
- İlk yazıdan əvvəl `baseline` sətri əlavə olunur: dəyişiklikdən əvvəlki vəziyyət.
- Təsdiq gözləyən dəyişiklik yalnız Confirm-dən sonra yazılır, rollback olunan dəyişiklik heç vaxt yazılmır.
- Rollback: `migrations_rollback/012_fw_history.down.sql`.

## `node_groups`, `node_group_members` (013, P9a)
| Cədvəl | Sütunlar | Qeyd |
|---|---|---|
| `node_groups` | `id` UUID PK, `name` VARCHAR(100) UNIQUE, `description` TEXT, `created_at` TIMESTAMPTZ | |
| `node_group_members` | `group_id` → `node_groups` (CASCADE), `node_id` → `nodes` (CASCADE) | PK `(group_id, node_id)`, indeks `node_id` |

- `firewall_rules.source_group_id` / `dest_group_id` → `node_groups(id)` `ON DELETE RESTRICT`: qayda istifadə etdiyi qrupu silməyə imkan vermir.
- `source_type`/`dest_type` CHECK-ə `group` əlavə olunub.
- Rollback: `migrations_rollback/013_node_groups.down.sql`.

## `users.role` (014, P9a)
- `role` TEXT NOT NULL DEFAULT `'admin'`, CHECK `admin`/`operator`/`viewer`. Mövcud istifadəçilər admin olaraq qalır.
- Son admin qorunur: `SetUserRole` və `DeleteUserKeepingAdmin` admin sətirlərini `FOR UPDATE` ilə kilidləyir.
- Rollback: `migrations_rollback/014_user_roles.down.sql`.

## `limit_profiles` (015, P9b)
| Sütun | Tip | Qeyd |
|---|---|---|
| `id` | UUID | PK |
| `name` | VARCHAR(100) | UNIQUE |
| `down_kbps`, `up_kbps` | INTEGER NULL | kbit/s, `> 0`; NULL = limitsiz |
| `max_connections` | INTEGER NULL | `> 0`; NULL = limitsiz |
| `schedule` | JSONB | `[{"days":[1..5],"from":"08:00","to":"18:00"}]`, boş = həmişə |
| `timezone` | TEXT | IANA adı, default `UTC` |
| `created_at` | TIMESTAMPTZ | |

- `nodes.limit_profile_id`, `node_groups.limit_profile_id` → `limit_profiles(id)` `ON DELETE RESTRICT`.
- Qüvvədə olan profil: node-un öz profili, yoxdursa profili olan ilk qrupun (ad sırası ilə) profili (`store.ListNodeLimits`).
- Rollback: `migrations_rollback/015_limit_profiles.down.sql` (profillər və bağlamalar silinir).

## Trafik kvotası (016, P9c)
- `limit_profiles`: `quota_mb` INTEGER NULL (`> 0`), `quota_action` TEXT (`block`/`throttle`), `throttle_kbps` INTEGER NULL, `quota_reset_day` SMALLINT (1–28).
- `node_quota_state`: `node_id` PK → `nodes` (CASCADE), `period_start`, `used_bytes`, `last_rx`/`last_tx` (son nümunənin WireGuard sayğacları), `warned_at`, `exceeded_at`, `updated_at`.
- Sayğac artımla aparılır: hər 5 dəqiqəlik nümunədə rx+tx fərqi əlavə olunur (sayğac azalanda sıfırdan sayılır). Nümunələrdən cəmlənmir, çünki nümunələr 30 gün saxlanılır, dövr isə 31 gün ola bilər.
- `notification_settings.quota_exceeded` BOOLEAN DEFAULT TRUE.
- Rollback: `migrations_rollback/016_traffic_quota.down.sql`.
- 017: `node_quota_state.period_end` (dövr başlayanda sabitlənir; mövcud sətirlərdə `period_start + 1 ay`), `updated_at` optimistik yazma üçün işlənir. Kvotası olmayan node-un sətri silinir. Rollback: `migrations_rollback/017_quota_period_end.down.sql`.
