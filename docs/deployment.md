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

  Center də artıq bu faylı yazmır.

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

## Mövcud serverlərdə 2026-10-14 dəyişiklikləri
- **Postgres portu:** compose indi `127.0.0.1:5432` publish edir. Konteyner yenidən yaradılmalıdır: Center Update compose faylı dəyişdiyini görüb tam rebuild edir. Əl ilə: `docker compose up -d postgres`.
- **Admin port guard-ı (iptables rejimi):** `setup-firewall.sh` yenidən işə salınmalıdır. Center Update bunu server və ya compose faylları dəyişəndə edir (bu buraxılışda hər ikisi dəyişib). Docker-i qısa müddətə restart edir. Yoxlamaq üçün: `iptables -t mangle -S NOVUSGATE-ADMIN` və `ip6tables -t mangle -S NOVUSGATE-ADMIN`. nft rejimində guard kompilyatordadır, control-plane yenilənəndə tətbiq olunur.
- **`/health`:** monitorinq yalnız `status`-a baxırsa, heç nə dəyişmir. Detallar üçün `X-API-Key` göndərin.

## Yeniləmə qaydası (buraxılış qeydi)
- **Web və control-plane birlikdə yenilənməlidir:**
  - P2a-dan əvvəlki web köhnə xəta formasını gözləyir və yeni control-plane ilə `[object Object]` göstərə bilər;
  - P4b-dən sonra web API-ni öz nginx-i üzərindən çağırır.

  Ona görə hər ikisini birlikdə build edin (`docker compose up -d --build`). Sonra brauzerdə səhifəni yeniləyin (açıq qalmış köhnə tab köhnə JS-i işlədir).

## NovusGate Center əməliyyatları (P7)
- **Update:**
  - Dəyişiklik aşkarlansa, fayllar dəyişməzdən əvvəl backup alınır: `/var/backups/novusgate/update-<vaxt>/`. İçində `code.tar.gz` (`.env` ilə), `wireguard.tar.gz` və `db.sql` var; son 5 backup saxlanılır.
  - Hər hansı addım uğursuz olsa və ya control-plane `/health`-ə bir dəqiqə ərzində cavab verməsə, əvvəlki versiya avtomatik bərpa olunur və update 1 kodu ilə bitir.
  - DB avtomatik geri qaytarılmır, çünki miqrasiyalar yalnız genişləndirir. Lazım olsa `db.sql`-dən əl ilə bərpa edin.
- **Uninstall:**
  - Yalnız NovusGate silinir: onun konteynerləri, volume-ları, qurduğu image-lər, wg interfeysləri, INPUT qaydaları, nft cədvəli, boot unit və fail2ban jail faylı.
  - Docker-in şəbəkə qaydaları və başqa tətbiqlərin image və volume-ları qalır.
- **Join VPN:** paneldə Nodes → Connect → Linux → "Generate install script" düyməsini basın, skripti Center-də Join VPN pəncərəsinə yapışdırın. Skript bir dəfə və 15 dəqiqə ərzində işləyir, serverdə root kimi icra olunur.
- **Non-root SSH istifadəçisi:** Center əmrləri `sudo -n` ilə işlədir, ona görə həmin istifadəçinin parolsuz sudo hüququ olmalıdır.
- **Eyni server üçün iki əməliyyat:** ikincisi 409 alır və birincinin bitməsini gözləməlidir.

## Center iş log-ları (2026-10-15)
Server səhifəsində **Job logs** kartı hər işin tam çıxışını göstərir (👁️ baxmaq, ⬇️ yükləmək). API: `GET /api/servers/:id/jobs`, `GET /api/servers/:id/jobs/:name`. Log-lar `data/jobs`-dadır, avtomatik silinmir; parollar maskalanmır (`docs/security.md`).

## Center ilkin yoxlaması (2026-10-15)
Center-in Install skripti hosta toxunmazdan əvvəl bunları yoxlayır və bütün problemləri birlikdə göstərir:
- Ubuntu 22.04+ və ya Debian 12+ (nft firewall, limitlər və kvota nftables 1.0.2+ tələb edir; 2026-10-15 qərarı: köhnə serverlər istifadə olunmur);
- x86_64 və ya aarch64;
- ən azı 1 GB RAM (2 GB-dan az olanda xəbərdarlıq);
- `/opt`-da 3 GB boş disk;
- TCP 3007/5432/8080/8443 və UDP 51820 boş olmalıdır;
- systemd.

Uyğun gəlməsə exit 5 ilə dayanır və heç nə dəyişmir. Reinstall və Update bu yoxlamanı işlətmir: o hostda NovusGate artıq qurulub.

## Panel backup-ları və restore (P8)
- **Yaratmaq:** Settings → Backups → "Backup now". Fayl `/var/backups/novusgate/panel/` qovluğundadır. Backup private açarları saxlayır; yüklənmiş faylı təhlükəsiz yerdə saxlayın.
- **Restore (əl ilə):**
  1. `tar -xzf novusgate-backup-....tar.gz -C /tmp/ng-restore`
  2. WireGuard: `cp /tmp/ng-restore/wireguard/*.conf /etc/wireguard/ && chmod 600 /etc/wireguard/*.conf`
  3. DB: `docker exec -i novusgate-postgres psql -U <DB_USER> -d <DB_NAME> < /tmp/ng-restore/db.sql`. Bunu boş bazaya edin (təzə install-dan sonra), çünki dump mövcud cədvəllərin üzərinə yazmır.
  4. `docker compose up -d --force-recreate control-plane`
- Restore üçün eyni `MASTER_KEY` lazımdır (`.env`): node açarları onunla şifrələnib. Backup-da `.env` yoxdur.

## VPN qaydaları iptables rejimində (2026-10-15 Update qeydi)
Update-dən sonra paneldə yaradılmış drop/reject VPN qaydaları iptables rejimində ilk dəfə trafiki kəsməyə başlayır: əvvəl wg ACCEPT-lərinin altında qalırdılar. Update-dən əvvəl Firewall → VPN Rules siyahısına və Network policies matrisinə baxın. Ətraflı: `docs/security.md`.

## Telegram bildirişləri (P8)
- Panel → Settings → **Telegram notifications** bölməsində qurulur, env dəyişəni lazım deyil. Control-plane serverdən `https://api.telegram.org`-a çıxış imkanı olmalıdır.
- Miqrasiya `011_notification_settings.sql` yeniləmədə avtomatik tətbiq olunur.
- **Qeyd:** `/etc/fail2ban/fail2ban.local`-da operatorun öz `logtarget`-i varsa (məsələn SYSLOG), NovusGate drop-in-i onu əvəz edir. Uninstall log-u `/var/log/fail2ban.log`-a qaytarır, əvvəlki dəyərə yox.
- **Fail2Ban log-u (2026-10-15):** `setup-firewall.sh` fail2ban-ı `/var/log/novusgate/fail2ban.log`-a yazmağa yönləndirir. Yalnız NovusGate-in öz faylları yazılır:
  - `/etc/fail2ban/fail2ban.d/novusgate.local` (`logtarget`), recidive jail-i üçün isə `jail.d/novusgate.local`-da `logpath`;
  - öz logrotate faylı `/etc/logrotate.d/novusgate-fail2ban` (həftəlik, `fail2ban-client flushlogs`);
  - işləyən fail2ban-a `fail2ban-client set logtarget`.

  Compose bu qovluğu konteynerə mount edir. Qovluq mount edildiyi üçün rotasiyadan sonra yeni fayl görünür. Paketin `/etc/logrotate.d/fail2ban` faylına (dpkg conffile) toxunulmur; əvvəlki versiyanın əlavə etdiyi `copytruncate` oradan silinir. `/var/log/fail2ban.log` artıq yenilənmir. Center uninstall bu faylları silir və log-u köhnə yola qaytarır.

## Limit profilləri və saat qurşağı (P9b)
- Boot unit-də (`novusgate-firewall.service`) `Environment=TZ=UTC` var. Center Update `setup-firewall.sh`-ı yenidən işlədir və unit yenilənir.
- Funksional yoxlama: `bash server/scripts/limits-functional-check.sh` (NET_ADMIN + SYS_ADMIN, `--privileged` yox; netns ilə real trafik: sürət, bağlantı limiti, cədvəl; konteyner Asia/Baku saat qurşağında işləyir).

## Server idarəsi (P10a)
- Panelin "Server" səhifəsi host komandalarını control-plane konteynerindən `nsenter -t 1` ilə icra edir; bu, konteynerin host PID namespace-i ilə işləməsini tələb edir (`docker-compose.yml`-də `pid: host`). İzolə test konteynerində (host PID-siz) host oxumaları 500 verir; bu gözlənilir.
- sysctl idarə faylı: `/etc/sysctl.d/90-novusgate.conf`; geri qaytarma skripti: `/var/lib/novusgate/sysctl-rollback.sh`; timer: `novusgate-sysctl-rollback`.
- Migration 019 control-plane başlayanda avtomatik tətbiq olunur.
- Node installer-i: konfiqdə `DNS =` varsa və `resolvconf` yoxdursa `resolvectl`-ə link yaradır (yoxdursa `openresolv` quraşdırır); wg-quick DNS-i bununla tətbiq edir.

## Center düzəlişləri (audit, 2026-10-15)
- **Join VPN** hub-un özündə (`/opt/NovusGate` olan serverdə) işləmir (exit 3): node skripti `wg0.conf`-u yazır, bu isə hub-da admin VPN-dir.
- **Uninstall** paneldəki Server səhifəsinin izlərini də silir: `novusgate-sysctl-rollback.timer` və `/etc/sysctl.d/90-novusgate.conf`. Bu faylın qoyduğu dəyərlər işləyən kernel-də növbəti reboot-a qədər qalır.
- **Install:**
  - `curl` yoxdursa quraşdırır; get.docker.com faylı endirilə bilmirsə install dayanır;
  - `/var/log/auth.log` yoxdursa (Debian 12) fail2ban `sshd` jail-i journal-dan oxuyur (`backend = systemd`, `python3-systemd`);
  - sonda panel ünvanını `https://…:3007` kimi göstərir;
  - `.env`-ə `VPN_IP` yazır (Credentials görünüşü üçün).
- **Update:**
  - `rsync` yoxdursa quraşdırır; köhnə kopyalama yolu silindi (silinmiş fayllar qalırdı);
  - hub "degraded" qalxırsa və ya `novusgate-web` işləmirsə xəbərdarlıq yazır, update saxlanılır.
- **Docker əməliyyatları:** konteyner adı yoxlanılır (`[A-Za-z0-9][A-Za-z0-9_.-]*`), çünki SSH ilə shell-ə gedir.
