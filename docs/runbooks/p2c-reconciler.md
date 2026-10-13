# P2c Staging Runbook — WireGuard reconciler və expiry

**Nə vaxt istifadə olunur:** P2c qəbul testi üçün. Hər addımın əmri və real çıxışı bu faylın sonundakı "Nəticələr" bölməsinə yazılır. Nəticə uydurulmur.

**Hazırlıq:** P1 runbook-dan keçmiş staging VM, ən azı bir test node-u ilə.

**Log formatı:** `docker logs novusgate-control-plane` JSON yazır (`LOG_FORMAT=json`). Oxumaq üçün `.env`-də `LOG_FORMAT=text` yaz.

## 1. Shadow rejimi (default)
1. `.env`-də `WG_RECONCILER` yoxdur və ya `shadow`-dur. `docker compose up -d control-plane` icra et.
2. 30 saniyə gözlə, sonra `docker logs novusgate-control-plane 2>&1 | grep reconciler` icra et.
   - **Gözlənilən:** `WireGuard reconciler: shadow`.
   - `would change peer` sətirləri ya yoxdur, ya da var. Hər belə sətir DB ilə kernel arasında fərq deməkdir. `kind`, `node` və `interface` dəyərlərini qeyd et və səbəbini izah et.
   - `peer not in the database (left alone)` sətri DB-də olmayan peer-i göstərir. Kimin əlavə etdiyini araşdır, reconciler onu silmir.
3. `curl -s http://<vpn-ip>:8080/health | jq .checks.reconciler` → `mode: "shadow"`, `ok: true`, `last_run` doldurulub, `pending` = 2-ci addımdakı fərqlərin sayı.

## 2. Expiry (panel bağlı)
1. Panel-də test node-unun `expires_at` vaxtını 1 dəqiqə sonraya qoy, sonra panel-i bağla.
2. 2 dəqiqə gözlə.
   - `wg show wg0 peers` (və ya node-un interfeysi) → node-un açarı **yoxdur**.
   - `docker logs novusgate-control-plane 2>&1 | grep "node expired"` → node-un adı görünür.
   - `GET /api/v1/networks/{id}/nodes` → node `status: "expired"`.

## 3. Reaktivasiya (B11)
1. Panel-də həmin node-a gələcək bir `expires_at` ver.
2. `wg show wg0 peers` → açar dərhal (bir neçə saniyəyə) geri qayıdır.
3. Node-un client-i yenidən qoşula bilir.

## 4. Enforce rejimi
Yalnız 1-ci addımda bir gün ərzində izahsız fərq yoxdursa keç.
1. `.env`-də `WG_RECONCILER=enforce` yaz, sonra `docker compose up -d control-plane`.
2. Test node-unun peer-ini əl ilə sil: `wg set wg0 peer <açar> remove`. 15 saniyə ərzində `wg show wg0 peers` onu yenidən göstərməlidir. Log-da `reconciler: changed peer` və `kind=add` olmalıdır.
3. Əl ilə yad peer əlavə et: `wg set wg0 peer <yeni açar> allowed-ips 10.99.0.250/32`.
   - Peer qalır, silinmir.
   - Log-da `peer not in the database (left alone)` görünür.
   - Sonra onu özün sil.
4. Site gateway node-u varsa, onun allowed-ips siyahısına əl ilə LAN route əlavə et. Siyahı enforce-dan sonra da həmin route-u saxlamalıdır.

## 5. Geri qayıdış
- `.env`-də `WG_RECONCILER=shadow` (yalnız log) və ya `off` (P2c-dən əvvəlki davranış) yaz, sonra `docker compose up -d control-plane`.
- `off` rejimində expiry yenə yalnız panel açılanda işləyir (köhnə lazy davranış).

## Nəticələr
<!-- Hər addım: tarix · əmr · real çıxış -->
