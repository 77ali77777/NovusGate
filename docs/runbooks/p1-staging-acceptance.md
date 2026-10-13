# P1 Staging Acceptance

Staging: təzə Ubuntu 24.04 VM, root SSH. Hər addımın nəticəsini (əmr + çıxış) bu faylın sonuna yaz.

1. Center ilə Install (port 22). Gözlənilən: log `INSTALLATION COMPLETE`, `docker ps` 3 konteyner `Up`.
2. Panel → yeni şəbəkə (wg1) + 2 peer (biri 1 saatlıq). Bir client qoş.
3. `sudo reboot`. Boot-dan sonra:
   - `docker ps` → 3 konteyner `Up` (restart policy)
   - `wg show wg1 peers` → hər iki aktiv peer var
   - client yenidən qoşulur, panel açılır
   - `systemctl is-enabled docker` → `enabled` (restart siyasəti boot zamanı docker servisinin aktiv olmasını tələb edir)
4. Center → Reinstall. Gözlənilən:
   - `ls /opt/NovusGate/server/data/postgres/PG_VERSION` var
   - `ls /opt/NovusGate/admin-vpn.conf` var
   - panelə köhnə admin parolu ilə giriş olur, şəbəkələr və peer-lər yerindədir
5. Center → Install (quraşdırılmış serverdə). Gözlənilən: log `[ERROR] NovusGate is already installed`, Center-də status `installed` qalır.
6. Panel → Open Port tcp 3, sonra Close Port tcp 3. `iptables -S INPUT` → `-i wg0 ... --dport 3007 -j ACCEPT` hələ də var.
7. Ayrıca VM: `/etc/ssh/sshd_config` → `Port 2222`, Center-də port 2222 ilə Install. Gözlənilən: install-dan sonra və reboot-dan sonra `ssh -p 2222` işləyir.
8. Center-də səhv parollu server → Install. Gözlənilən: log `[ERROR] ...`, Center konteyneri işləməyə davam edir (`docker ps` uptime sıfırlanmayıb).
9. Center → Update, sonra Migrate. Gözlənilən: `admin-vpn.conf` yerindədir, Migrate `✅ Database updated!` yazır.
