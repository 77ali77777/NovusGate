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
