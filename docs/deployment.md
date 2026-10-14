# Deployment

## Konteynerlər (`server/deployments/docker/docker-compose.yml`)
- **`postgres`:** PostgreSQL 16.
- **`control-plane`:** host şəbəkəsində işləyir, `:8080`-də dinləyir. Firewall bu portu yalnız `wg+` interfeyslərindən buraxır.
- **`web`:** host şəbəkəsində nginx, `:3007`-də HTTPS (self-signed sertifikat image build zamanı yaradılır).

## Panel və API eyni origin-dədir (P4b)
- Panelin nginx-i (`web/nginx/default.conf.template`) `/api/` və `/health` sorğularını `http://127.0.0.1:8080`-ə proxy edir. Brauzer API-ni panelin öz ünvanında (`https://<hub>:3007/api/v1`) çağırır, ona görə mixed content (B23) və CORS yoxdur.
- **`X-API-Key`:** nginx onu `NOVUSGATE_API_KEY` env dəyişənindən əlavə edir. Compose bunu `.env`-dəki `API_KEY`-dən ötürür (`NOVUSGATE_API_KEY: ${API_KEY:-}`). Açar JS bundle-a düşmür.
- **Template:** nginx image-i konteyner başlayanda `/etc/nginx/templates/default.conf.template` faylını env dəyişənləri ilə render edib `conf.d/default.conf`-a yazır. Yalnız mövcud env dəyişənləri əvəz olunur, nginx-in `$host` kimi dəyişənləri toxunulmaz qalır.
- **`X-Real-IP`:** nginx client IP-sini bu başlıqla ötürür. Control-plane onu yalnız loopback-dən gələn sorğuda qəbul edir.
- **`web/.env` artıq istifadə olunmur:**
  - `VITE_API_URL` və `VITE_API_KEY` oxunmur;
  - `web/.dockerignore` `.env` fayllarını build-dən çıxarır;
  - compose faylı artıq onu web konteynerinə mount etmir.

  Center hələ də bu fayla `VITE_*` sətirləri yazır (P7-də təmizlənəcək). Bunun zərəri yoxdur.

## Yeni node-un qoşulması (P4b)
1. Paneldə node-un konfiqurasiya pəncərəsində **Linux → Generate install script** düyməsini basın.
2. Skripti kopyalayın və ya yükləyin, yeni serverdə root kimi işə salın (`bash install-<node>.sh`).
3. Skript 15 dəqiqə və bir dəfə işləyir. Vaxtı keçibsə, yenisini yaradın.

Node checkin-i WireGuard qalxandan sonra VPN üzərindən edir, internetə heç bir port açılmır.

## Master açar (P4c)
- **`.env`-dəki `MASTER_KEY`** (64 hex simvol) compose ilə control-plane-ə `NOVUSGATE_MASTER_KEY` kimi ötürülür və node private key-lərini şifrələyir.
- **Center:**
  - yeni quraşdırmada açarı özü yaradır (`openssl rand -hex 32`, `openssl` yoxdursa `/dev/urandom`);
  - reinstall və update `.env`-də açar yoxdursa və ya boşdursa əlavə edir; mövcud açarı heç vaxt dəyişmir.
- **Əl ilə quraşdırma:** `MASTER_KEY=$(openssl rand -hex 32)` sətrini `server/deployments/docker/.env`-ə əlavə edin.
- **Nümunə fayl:** `server/deployments/docker/.env.example` bütün dəyişənləri, icazə verilən dəyərləri və simvol qaydalarını izah edir: `cp .env.example .env && chmod 600 .env`, sonra hər `CHANGE_ME` dəyərini dəyişin. `DB_*` və `API_KEY` yalnız `A–Z a–z 0–9 . _ ~ -` ola bilər (`DB_PASSWORD` `DATABASE_URL`-in içinə düşür).
- **Açar dəyişdirilməməlidir:** dəyişsə, köhnə key-lər açılmır. Açarı `.env` ilə birlikdə yedəkləyin.
- **Rollback:** `docs/data-model.md`, 009 bölməsi.

## API açarının formatı
`API_KEY` (control-plane-də `novusgate_API_KEY`) yalnız hərf, rəqəm və `. _ ~ -` simvollarından ibarət ola bilər. Səbəb: açar panelin nginx konfiqurasiyasına dırnaq içində yazılır. Başqa simvol olsa, control-plane başlamır. Center açarı hex yaradır.

## Yeniləmə qaydası (buraxılış qeydi)
- **Web və control-plane birlikdə yenilənməlidir:**
  - P2a-dan əvvəlki web köhnə xəta formasını gözləyir və yeni control-plane ilə `[object Object]` göstərə bilər;
  - P4b-dən sonra web API-ni öz nginx-i üzərindən çağırır.

  Ona görə hər ikisini birlikdə build edin (`docker compose up -d --build`). Sonra brauzerdə səhifəni yeniləyin (açıq qalmış köhnə tab köhnə JS-i işlədir).
