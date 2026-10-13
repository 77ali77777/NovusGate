# P3b-1 Staging Runbook — nftables firewall engine

Staging: P1 runbook-dan keçmiş Ubuntu 24.04 VM. Hər addımın əmrini və çıxışını bu faylın sonuna yaz. Nəticə uydurulmur.

> ⚠️ **`FIREWALL_ENGINE=nft` P3b-2-yə qədər yalnız staging üçündür.** iptables `INPUT DROP` siyasəti və idxal olunmuş iptables qaydaları kernel-də qalır. Ona görə bu panel əməliyyatları uğurlu cavab qaytarır, amma hostda real effekti yoxdur:
> - Open Port;
> - Allow IP;
> - idxal olunmuş blokun Unblock-u;
> - idxal olunmuş fail2ban permanent ban-ın silinməsi.
>
> Bu əməliyyatlar `nft list table` ilə yoxlanılır, kənardan trafiklə yox.
>
> Engine işə düşəndə nə edir:
> - İdxal iptables-də "əvvəlki ACCEPT sonrakı DROP-u üstələyir" ziddiyyəti tapsa, keçidi rədd edir və heç nə dəyişmir. Log: `import iptables rules: …`. Ziddiyyəti iptables rejimində düzəlt və restart et.
> - Köhnə `novusgate-vpn-*` FORWARD qaydalarını yalnız nftables ilk dəfə uğurla tətbiq olunandan sonra silir. Tətbiq alınmasa, iptables işləməyə davam edir və engine arxa planda təkrar cəhd edir.

1. Hostda `apt-get install -y nftables` icra et. Sonra `nft --version` (1.0.2 və ya daha yeni olmalıdır).
2. `server/deployments/docker/.env`-ə `FIREWALL_ENGINE=shadow` yaz, `docker compose up -d control-plane`.
   - Log: `[Firewall] shadow mode: nftables ruleset compiles and passes nft -c`.
   - `nft list tables` → `novusgate` **olmamalıdır** (shadow heç nə tətbiq etmir).
3. Panel-dən bir port aç (məs. 8444) və bir IP blokla (iptables yolu hələ işləyir).
4. `FIREWALL_ENGINE=nft`, `docker compose up -d control-plane`.
   - Log: `imported N panel rules from iptables` və `nftables engine applied the stored ruleset`.
   - `nft list table inet novusgate`: SSH portları, 8444 və bloklanmış IP orada olmalıdır.
   - `cat /etc/novusgate/firewall.nft` mövcud olmalıdır.
5. Panel → Open Port 8445 → `nft list chain inet novusgate input | grep 8445`.
   - **Qeyd:** iptables `INPUT DROP` siyasəti P3b-2-yə qədər qalır. Ona görə portun kənardan real açılması P3b-2-dən sonra yoxlanılır.
6. Təsdiqli v2 dəyişikliyi:
   ```bash
   curl -X POST https://<panel>/api/v1/firewall/v2/services -d '{"protocol":"tcp","port_from":9443}' …
   ```
   - `systemctl list-timers 'novusgate-fw-rollback*'` → timer görünməlidir.
   - Təsdiq etmə, 75 saniyə gözlə: 9443 yox olmalıdır, `GET /firewall/v2/state`-də `services`-də görünməməlidir.
7. Eyni sorğunu təkrarla, sonra `POST /firewall/v2/confirm/{id}` → 9443 qalmalı, `/etc/novusgate/firewall.nft`-də olmalıdır.
8. Öz IP-ni bloklamağa cəhd et (panel → Block IP) → 400 almalısan.
9. VPN qaydası əlavə et (A → B drop) → `nft list chain inet novusgate vpn_policy` qaydanı göstərməlidir. Əsl trafiklə yoxla.
10. Ziddiyyət yoxlaması:
    - Panel → Block IP `203.0.113.0/24` (v1, `confirm` yoxdur), sonra Allow IP `203.0.113.5` → **400** almalısan. Blok allow-dan əvvəl yoxlanılır, yəni allow heç vaxt işləməzdi.
    - Blok-u sil.
11. Retry yoxlaması: 6-cı addımdakı təsdiqsiz dəyişiklik gözləyərkən VPN qaydası əlavə et.
    - Log-da `reconcile failed (will retry)` görünməlidir.
    - Rollback-dan sonra ən geci 15–30 saniyə ərzində `nft list chain inet novusgate vpn_policy` qaydanı göstərməlidir.
12. `FIREWALL_ENGINE=iptables`-ə qayıt. **Bütün addımlar məcburidir**, yoxsa köhnə davranış qayıtmır:
    1. `.env`-də `FIREWALL_ENGINE=iptables` yaz, sonra `docker compose up -d control-plane`.
    2. `nft delete table inet novusgate`. Cədvəl `policy drop` ilə qalsa, iptables-də açılan portları və Unblock-u bloklayır. Avtomatik silinmə P3b-2-dədir.
    3. `rm -f /etc/novusgate/firewall.nft`.
    4. `curl -X POST https://<panel>/api/v1/firewall/vpn/apply …`. Bu, nft rejimində silinmiş `novusgate-vpn-*` FORWARD qaydalarını iptables-ə qaytarır. iptables rejimində onlar boot-da avtomatik sync olunmur.
    5. Nəzərə al: nft rejimində edilmiş port, blok və allow dəyişiklikləri iptables-ə **geri yazılmır**. Lazım olanları panel-dən yenidən et.
    6. Yoxla: `iptables -S FORWARD | grep novusgate-vpn` və `nft list tables` (`novusgate` olmamalıdır).
