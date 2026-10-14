# P2 — Backend nüvəsi: bölgü və qərarlar

> **Tarix:** 2026-10-13
>
> **Ana spec:** `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md`. Bu sənəd onun §3 (sındırmamaq qaydaları), §4.1 (backend) və §7 (B11, B12, B14, B16, B21, B22) bölmələrinə əsaslanır.
>
> **Mənbə:** iki müstəqil kod xəritəsi (REST kontraktı; WireGuard/expiry/baqlar). Hər iddia `fayl:sətir` ilə yoxlanılıb.

## 1. Niyə bölünür
P2 tək plan kimi çox böyükdür. Onun tərkibi:
- 61 route-un kontrakt testi;
- 167 `errorResponse` çağırışı;
- WireGuard interfeysi;
- reconciler;
- expiry job;
- servis qatı;
- OpenAPI.

Hər alt-plan ayrıca yoxlanılır və tək başına işləyən proqram verir.

| Alt-plan | Məzmun | Davranış dəyişikliyi |
|---|---|---|
| **P2a Kontrakt + baqlar** | Test seam-ləri; mövcud cavab formalarının snapshot testləri; B14, B16, B21, B22; DB parolunun log-a yazılması; frontend-in hər iki xəta formasını oxuması | Yalnız baq düzəlişləri (aşağıda §3) |
| **P2b Müşahidə** | `log/slog` (JSON), işləyən request log-u, panic-recover middleware, `/health` (DB, interfeyslər, reconciler, nft), ikiqat middleware-in aradan qaldırılması | Log formatı; `/health` cavabına sahələr **əlavə olunur** |
| **P2c WireGuard + reconciler + expiry** | `netctl/wg` `Manager` interfeysi (CLI implementasiyası, runner seam-i); reconciler `shadow → enforce` (`WG_RECONCILER`); `wgN.conf` peer-lərlə DB-dən; expiry job (B11); `loadNetworks` importu "adopt" kimi | `shadow`-da yoxdur; `enforce` env ilə |
| **P2d Servis qatı + vahid xəta + OpenAPI** | Handler → service → store; `{"error":{"code","message"}}`; OpenAPI 3 sənədi kontrakt snapshot-larından | Xəta forması: frontend-in hər iki formanı oxuyan versiyası (P2a) deploy olunandan sonra |

## 2. Qərarlar
1. **Snapshot = kontrakt.** P2a mövcud cavabları olduğu kimi dondurur, `null` siyahılar da daxil. Sonrakı hər düzəliş snapshot fərqi kimi görünür və commit-də əsaslandırılır.
2. **`wgctrl` əlavə olunmur** (§5-də "istəyə bağlı" idi). CLI implementasiyası saxlanılır, `nft.Runner` kimi bir runner arxasına keçir. Yeni paket yoxdur.
3. **Vahid xəta forması iki addımla keçir.**
   - P2a frontend-də `data.error?.message ?? data.error` oxuyan helper əlavə edir.
   - P2d backend-i dəyişir.
   - Web və server eyni Update ilə deploy olunur, amma helper köhnə panel keşindən də qoruyur.
4. **Reconciler-in "adopt" qaydası.** Hostda olub DB-də olmayan peer-lər `enforce` rejimində də silinmir, DB-yə idxal olunur (ana spec §3.4). Bu, indiki `loadNetworks` davranışıdır. Silmə yalnız DB-də olan, amma vaxtı keçmiş və ya silinmiş node-lara aiddir.
5. **IP ayırma (B21).** Mövcud nümunə saxlanılır: network, `.1` (hub) və `.2` ötürülür. Əlavə olaraq broadcast ünvanı **heç vaxt** verilmir. Hub ünvanı CIDR-in real prefiksi ilə yazılır (`/24` sabit deyil). Mövcud şəbəkələrin `wgN.conf`-una toxunulmur.

## 3. P2a-da dəyişən davranış (hamısı baq düzəlişidir)
P2a-ya daxil deyil:
- **`install.sh`-da nil network panic-i** (`config_handlers.go:372`). `nodes.network_id` FK `ON DELETE CASCADE` ilə bağlıdır, ona görə bu, yalnız iki sorğu arasındakı yarışda yaranır və test edilə bilmir. P2b-dəki recover middleware onu 500-ə çevirəcək.
- **Panel-in `install.sh` əmrində auth başlığının olmaması.** Bu, B9/B10-dur → P4.

Dəyişənlər:
- **Boş siyahılar** `null` əvəzinə `[]` qaytarılır: nodes, networks, users, fail2ban history, permanent bans (B14; `VPNRuleModal` çöküşü).
- **fail2ban history:**
  - Ban və Unban qeydləri real olaraq qaytarılır;
  - Unban qeydi `unban` kimi işarələnir;
  - jail düzgün çıxarılır (indi PID götürülür);
  - `jail` parametri shell-ə ötürülmür.
- **fail2ban logs:** Unban qeydləri `unban` kimi işarələnir.
- **fail2ban whitelist:** ağac formatlı çıxışdan yalnız ünvanlar qaytarılır (B16).
- **`GetPublicKey`:** açarın sonundakı `=` kəsilmir (B22).
- **iptables qayda siyahısı:**
  - 8–9 sahəli sətir panic etmir;
  - yeni iptables-in "opt" sütunsuz formatı düzgün oxunur (B22).
- **Yeni şəbəkənin hub ünvanı** CIDR prefiksi ilə yazılır. Node-a broadcast ünvanı verilmir (B21).
- **Startup log-unda DB parolu** maskalanır (secret log-a yazılmır).

## 4. P2c qərarları (2026-10-14)
- **`WG_RECONCILER`:** `off` | `shadow` (default) | `enforce`. Səhv dəyər verilsə server başlamır.
- **Expire addımı** shadow və enforce rejimlərində işləyir: vaxtı keçmiş node-ları DB-də `expired` kimi yazır. Bu, mövcud lazy expiry-nin vaxtında işləyən formasıdır.
- **Diff addımı:** vaxtı keçmiş node-ların peer silinməsi hər iki rejimdə tətbiq olunur, DB yenidən oxunur və uğursuz silinmə növbəti tick-də təkrarlanır (final review düzəlişi). Əlavə və yeniləmə shadow-da yalnız log yazır, enforce-da DB yenidən oxunandan sonra tətbiq olunur.
- **Naməlum peer-lər silinmir** ("adopt" qaydası), allowed-ips daraldılmır.
- **`wgN.conf`-a `[Peer]` yazılması P2c-2-yə saxlanılıb.** `wg0.conf` installer-indir, reboot bərpasını isə `restorePeers` edir.

## 5. P2d bölgüsü (2026-10-14)
- **P2d-1 (bağlandı):**
  - vahid xəta body-si `{"error":{"code","message"}}` və sabit kodlar;
  - `PUT /nodes/{id}`-də `status` və `expires_at` validasiyası.
- **P2d-2 (bağlandı):**
  - kontrakt snapshot-larından OpenAPI 3 sənədi;
  - qeydiyyatdan keçmiş hər route-un sənəddə olduğunu yoxlayan test.
- **P2d-3 (bağlandı, 2026-10-14):** bütün request və response body-ləri adlı DTO-lardır, OpenAPI sənədi tiplidir. Wire formatı dəyişməyib, kontrakt snapshot-ları eyni qalıb.
- **Servis qatı (handler → service → store) təxirə salındı.** Səbəblər:
  - P2-nin qəbul meyarlarında yoxdur (snapshot-lar yaşıl, reconciler shadow-da izahsız drift-siz, expiry panel bağlı olanda da işləyir);
  - istifadəçiyə görünən faydası yoxdur, regressiya riski isə realdır.

  Ehtiyac yarananda (P6 və ya ayrıca P2 davamı) ayrıca plan olacaq.
- **P2c-2 ləğv olundu (istifadəçi qərarı, 2026-10-14):** reboot bərpasını `restorePeers` və reconciler edir, host-dakı `wgN.conf` fayllarına peer yazılmır.
- **P2-nin vəziyyəti:** bağlandı.
