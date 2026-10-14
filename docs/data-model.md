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
