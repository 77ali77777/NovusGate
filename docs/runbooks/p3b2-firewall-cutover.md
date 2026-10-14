# P3b-2 Staging Runbook — iptables → nftables keçidi

**Nə vaxt istifadə olunur:** `FIREWALL_ENGINE=nft` rejiminin tam qəbul testi üçün. Bu runbook P3b-1 runbook-unu əvəz edir.

**Necə yazılır:** hər addımın əmri və real çıxışı bu faylın sonundakı "Nəticələr" bölməsinə yazılır. Nəticə uydurulmur. Gözlənilən nəticə alınmasa, işi dayandır və çıxışı olduğu kimi qeyd et.

**Log formatı (P2b):** control-plane log-u JSON-dur (`LOG_FORMAT=json`). `docker logs novusgate-control-plane | grep '<mətn>'` əvvəlki kimi işləyir. Oxumaq asan olsun deyə `.env`-ə `LOG_FORMAT=text` yazmaq olar.

## Hazırlıq
1. **Staging VM:** Ubuntu 24.04, P1 və P3b-1 runbook-larından keçmiş.
2. **SSH iki portda dinləyir:**
   - `/etc/ssh/sshd_config`-ə `Port 22` və `Port 2222` yaz;
   - `systemctl restart ssh`;
   - yoxla: `ss -Htlnp | grep sshd` → 22 və 2222.

## Keçid
3. **Center → Update** (`setup-firewall.sh` işə düşür).
   - **Bilinən sıra problemi:** Update yeni control-plane-i `setup-firewall.sh` boot unit-i quraşdırmazdan əvvəl başlada bilər. Onda control-plane log-unda `host not ready for FIREWALL_ENGINE=nft` görünür və iptables işləməyə davam edir (fail-closed). Bu halda skript bitəndən sonra bir dəfə `docker compose restart control-plane` icra et.

   Sonra yoxla:

   | Əmr | Gözlənilən |
   |---|---|
   | `systemctl is-enabled novusgate-firewall.service` | `enabled` |
   | `nft --version` | `nftables v1.0.9` (≥ 1.0.2) |
   | `systemctl is-enabled nftables` | `disabled` (heç vaxt aktiv edilmir, onun default konfiqi bütün ruleset-i silir) |
   | `cat /etc/fail2ban/jail.d/novusgate.local` | `port = 22,2222` (iptables rejimində `banaction` sətri olmur) |
   | `iptables -S INPUT` | installer baseline-ı, sonda `-P INPUT DROP` |

4. **nft rejimini aç:** `.env`-ə `FIREWALL_ENGINE=nft` yaz və `docker compose up -d control-plane` icra et.

   Log-da (`docker logs novusgate-control-plane`) bu sətirlər görünməlidir:
   - `imported N panel rules from iptables`;
   - `nftables engine applied the stored ruleset`;
   - `iptables INPUT handed over to nftables (N rules removed)`.

   Yoxla:
   - `iptables -S INPUT` → `-P INPUT ACCEPT`; yalnız `-j f2b-*` (və varsa `REJECT` və ya başqa alətlərin zəncirlərinə jump) sətirləri qalır;
   - `iptables -S FORWARD | grep novusgate-vpn` → boş;
   - `cat /etc/novusgate/firewall.nft` → fayl mövcuddur.

5. **Center → Update-i bir daha icra et.** Bu dəfə `setup-firewall.sh` nft rejimini görür. Log: `FIREWALL_ENGINE=nft: the control plane owns INPUT filtering`.
   - **Diqqət:** Center-in Update-i `setup-firewall.sh`-i yalnız `server/` (konkret olaraq `server/deployments/docker`) faylları dəyişəndə işə salır. Update log-unda server dəyişikliyi yoxdursa, skripti əl ilə işə sal: `sudo bash /opt/NovusGate/server/deployments/docker/setup-firewall.sh`.

   Sonra:
   - `jail.d/novusgate.local` faylında `banaction = nftables-multiport` olmalıdır;
   - `iptables -S INPUT` dəyişməməlidir;
   - `docker ps` uptime-ı sıfırlanmamalıdır (Docker restart olunmur).

## Funksionallıq
6. **Port açıb-bağlamaq:**
   - hostda `python3 -m http.server 8444 &`;
   - panel → Open Port 8444;
   - kənardan `nc -zv <server> 8444` → `succeeded`;
   - panel → Close Port 8444 → `nc` timeout və ya refused verməlidir.
7. **Lockout ssenariləri:**

   | Əməliyyat | Gözlənilən |
   |---|---|
   | Panel → Block IP: öz public IP-n | **400** |
   | Panel → Close Port 2222 | **403** (SSH portu qorunur) |
   | Panel → Allow IP `203.0.113.5` (əvvəlcə `203.0.113.0/24` bloklanıbsa) | **400** |
   | v2 dəyişikliyi `confirm` olmadan | 75 saniyədən sonra geri qaytarılır, SSH işləyir |

8. **Port forward-un dublikatı:** eyni `public_port` ilə `POST /firewall/v2/forwards` iki dəfə göndər. İkinci cavab **409** olmalıdır.

## Reboot
9. `reboot`. Server qalxandan sonra:
   - `systemctl status novusgate-firewall.service` → `active (exited)`;
   - `journalctl -b -u novusgate-firewall -u docker --no-pager | head`: novusgate-firewall Docker-dən **əvvəl** başlamalıdır;
   - SSH həm 22, həm də 2222 portunda işləməlidir;
   - VPN üzərindən panel açılmalıdır;
   - 8444 portu reboot-dan əvvəlki vəziyyətində qalmalıdır;
   - `iptables -S INPUT` → hələ də `ACCEPT` (netfilter-persistent təhvildən sonrakı vəziyyəti yükləyib).
   - **fail2ban zəncirləri (iptables rejimində qalan hostlar üçün):** `netfilter-persistent save` fail2ban-ın `f2b-*` zəncirlərini və o anki ban-ları da `rules.v4`-ə yaza bilər (fail2ban versiyasından asılıdır, yoxlanmayıb). Reboot-dan sonra bunları yoxla və nəticəni yaz:
     - `iptables -S | grep f2b`: hər zəncir yalnız bir dəfə görünməlidir;
     - `rules.v4`-dən qalxan ban-lar `fail2ban-client status sshd` siyahısında görünürmü;
     - bantime bitəndə həmin ban-lar silinirmi?

## fail2ban
10. Test IP-dən 2222 portuna 4 dəfə səhv parol gir. Sonra:
    - `fail2ban-client status sshd` IP-ni göstərməlidir;
    - `nft list ruleset | grep -B2 -A6 f2b` IP-ni nftables-də göstərməlidir.

## Məlum məhdudiyyət (M8)
11. İstifadəçinin öz Docker bridge şəbəkələrindəki konteynerlər host xidmətlərinə və VPN peer-lərinə çata bilmir. Səbəb: input siyasəti drop-dur, `wg*`-a forward isə yalnız DNAT ilə keçir.

    Yoxla: `docker run --rm alpine wget -T3 -qO- http://<vpn-ip>:8080/health` → xəta verməlidir. Bu gözlənilən davranışdır.

    Çevrilə bilməyən drop/reject VPN qaydaları (M9) əvvəlki kimi atlanır və log-da xəbərdarlıq kimi görünür.

## Geri qayıdış (iptables)
12. Bu addımları ardıcıllıqla icra et:
    1. `.env`-də `FIREWALL_ENGINE=iptables` yaz, sonra `docker compose up -d control-plane`.
    2. `bash /opt/NovusGate/server/deployments/docker/setup-firewall.sh` icra et. Skript iptables baseline-ını qurur (`INPUT DROP` sonda), yalnız bundan sonra `table inet novusgate`-i silir.
    3. Yoxla:
       - `iptables -S INPUT` → baseline, sonda `-P INPUT DROP`;
       - `nft list tables` → `novusgate` yoxdur;
       - `ls /etc/novusgate/firewall.nft` → fayl yoxdur;
       - `cat /etc/fail2ban/jail.d/novusgate.local` → `banaction` sətri yoxdur.
    4. `curl -X POST https://<panel>/api/v1/firewall/vpn/apply -H "Authorization: Bearer …"` icra et. `novusgate-vpn-*` FORWARD qaydaları geri qayıtmalıdır.
    5. SSH 22 və 2222 portlarında işləməlidir.
    6. Nəzərə al: nft rejimində edilmiş port, blok və allow dəyişiklikləri iptables-ə geri yazılmır. Lazım olanları panel-dən yenidən et.

## Dəstəklənməyən host (istəyə bağlı)
13. Ubuntu 20.04 VM-də `FIREWALL_ENGINE=nft` yaz.
    - Log-da `host not ready for FIREWALL_ENGINE=nft` sətri, `older than 1.0.2` və ya `not on the nf_tables backend` səbəbi ilə görünməlidir.
    - `nft list tables` → `novusgate` olmamalıdır.
    - Panel → Open Port → **409**.
    - iptables əvvəlki kimi işləməyə davam etməlidir.

## Nəticələr
<!-- Hər addım: tarix · əmr · real çıxış -->
