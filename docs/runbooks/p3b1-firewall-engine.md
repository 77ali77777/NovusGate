# P3b-1 Staging Runbook — nftables firewall engine

Staging: P1 runbook-dan keçmiş Ubuntu 24.04 VM. Hər addımın əmrini və çıxışını bu faylın sonuna yaz. Nəticə uydurulmur.

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
10. `FIREWALL_ENGINE=iptables`-ə qayıt, `docker compose up -d control-plane`.
    - Köhnə davranış qayıtmalıdır.
    - `nft delete table inet novusgate` ilə cədvəli əl ilə silmək olar. Avtomatik silinmə P3b-2-dədir.
