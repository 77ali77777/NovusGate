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
- **Login limiti:** IP üzrə 15 dəqiqədə 10 uğursuz cəhd, sonra 429. Sayğac yaddaşdadır. Control-plane nginx arxasına keçəndə (P4b) IP `X-Forwarded-For`-dan, yalnız etibarlı proxy-dən götürülməlidir.
- **Auth-suz yollar:** yalnız `/health` və `/api/v1/auth/login`, dəqiq uyğunluqla.
- **`X-API-Key`:** `novusgate_API_KEY` təyin olunubsa, Bearer-dən əlavə tələb olunur. P4b-də yenidən baxılacaq.

## Məlum açıq məsələlər (P4b/P4c)
- **Node private key-ləri** `nodes.labels.wireguard_private_key`-də açıq mətndə saxlanılır və node API cavablarında qaytarılır (P4c).
- **`install.sh` və `checkin`** panel tokeni tələb edir, ona görə yeni node onları çağıra bilmir (P4b, enrollment tokeni).
- **`web/.env`** git-də izlənir və build zamanı bundle-a düşür (`VITE_API_KEY`). P4b `VITE_*` dəyişənlərini aradan qaldırır. Faylın git-dən çıxarılması və açarın dəyişdirilməsi istifadəçinin qərarıdır.
