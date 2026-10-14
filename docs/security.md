# Təhlükəsizlik

## Panel auth (P4a)
- **Sessiyalar:** hər login `sessions` cədvəlində bir sətir yaradır. Token (32 təsadüfi bayt, hex) yalnız client-ə qaytarılır. DB-də onun SHA-256 hash-i saxlanılır, ona görə DB oğurlansa belə tokenlər oxunmur.
- **Ömür:** login-dən 24 saat (`sessionTTL`, `server/internal/controlplane/api/rest/auth.go`). `last_used_at` dəqiqədə ən çox bir dəfə yenilənir və yalnız məlumat üçündür.
- **Ləğv:**
  - logout cari sessiyanı silir;
  - istifadəçi silinəndə bütün sessiyaları da silinir (`ON DELETE CASCADE`);
  - parol dəyişəndə həmin istifadəçinin digər sessiyaları silinir.
- **Vaxtı bitmiş sessiyalar** hər uğurlu login-də təmizlənir.
- **Parol dəyişmə** yalnız sessiya istifadəçisinin parolunu dəyişir. Əvvəl body-dəki `username` istənilən hesabı seçə bilirdi.
- **Login limiti:** IP üzrə 15 dəqiqədə 10 uğursuz cəhd, sonra 429. Sayğac yaddaşdadır. Panelin nginx-i arxasında IP `X-Real-IP`-dən götürülür, yalnız loopback-dən gələndə (P4b).
- **Auth-suz yollar:** yalnız `/health` və `/api/v1/auth/login`, dəqiq uyğunluqla.
- **`X-API-Key`:** `novusgate_API_KEY` təyin olunubsa, Bearer-dən əlavə tələb olunur. Panel üçün onu nginx əlavə edir (P4b).

## Məlum açıq məsələlər (P4b/P4c)
- **Node private key-ləri:** P4c-də həll olundu (aşağıya bax).
- **`install.sh` və `checkin`:** P4b-də həll olundu (aşağıya bax).
- **`web/.env`:** P4b-dən sonra build onu oxumur, amma fayl hələ git-dədir (aşağıya bax).

## Node enrollment və proxy (P4b)
- **Enrollment tokeni:** 32 təsadüfi bayt. DB-də (`enrollment_tokens`) yalnız SHA-256-sı saxlanılır. Bir node üçündür, 15 dəqiqə və bir dəfəlik keçərlidir. İşlənməsi bir `UPDATE … WHERE used_at IS NULL` əmri ilə olur, ona görə paralel iki checkin eyni tokeni işlədə bilmir.
- **Public port açılmır:** skript paneldən kopyalanır. Checkin WireGuard qalxandan sonra VPN üzərindən gedir (8080 yalnız `wg+` interfeyslərində açıqdır).
- **Checkin label filtri:** `wireguard_*` açarları node-dan qəbul olunmur.
- **Etibarlı proxy:** `X-Real-IP` yalnız loopback-dən (panelin nginx-i) gələn sorğuda nəzərə alınır. Başqa client bu başlıqla öz IP-sini seçə bilmir. Bu IP-dən istifadə edənlər: login limiti, firewall-un operatoru kilidləməyə qarşı qoruması və firewall audit log-u.
- **API açarı:** `X-API-Key`-i panelin nginx-i env-dən (`NOVUSGATE_API_KEY`) əlavə edir. Açar artıq JS bundle-a düşmür. `web/.dockerignore` `.env` fayllarını image-dən çıxarır.
- **İstifadəçinin qərarı:** `web/.env` hələ git-də izlənir. Əvvəlki bundle-lar açarı daşıyıb, ona görə açarı dəyişmək və faylı git-dən çıxarmaq tövsiyə olunur.

## Node private key-ləri və audit (P4c)
- **Saxlanma:** node-un WireGuard private key-i artıq `labels`-də deyil, `nodes.private_key_enc` sütunundadır.
  - **Format:** `v1:<base64(nonce|ciphertext)>`, AES-256-GCM ilə şifrələnir.
  - **Master açar:** `NOVUSGATE_MASTER_KEY` (64 hex simvol, compose-da `.env`-dəki `MASTER_KEY`-dən).
  - **Açar yoxdursa:** dəyər `plain:` prefiksi ilə saxlanılır və server startup-da xəbərdarlıq verir. Açar sonradan təyin olunsa, növbəti startup bu dəyərləri şifrələyir.
  - **Açar səhvdirsə** (uzunluq və ya hex xətası): server başlamır.
  - **Açar dəyişib və ya silinibsə** (mövcud şifrələnmiş key-ləri aça bilmirsə): server startup-da xəta ilə dayanır.
- **API:**
  - node cavablarında key yoxdur;
  - `has_config` yalnız serverin key-i saxlayıb-saxlamadığını göstərir;
  - key yalnız `config`, `qrcode` və `install.sh` cavablarının içində çıxır (konfiqurasiyanın özüdür).
- **Startup miqrasiyası:** `serve` hər başlayanda köhnə `labels.wireguard_private_key` dəyərlərini sütuna köçürür və label-dən silir, hər node üçün bir SQL əmri ilə. Əməliyyat idempotentdir.
- **Master açarın itməsi:** şifrələnmiş key-lər açılmır. Həmin node-ların config-i yenidən yaradılmalıdır. Açarı `.env` ilə birlikdə yedəkləyin.
- **Audit:** `firewall_audit_log.user_id` dəyişikliyi edən panel istifadəçisidir (`ON DELETE SET NULL`). `user_ip` real client IP-sidir (`clientIP`).
- **Hələ şifrələnmir:** `networks.server_private_key` (spec-də yoxdur; JSON-da gizlidir). Növbəti addım kimi qeyd olunub.
