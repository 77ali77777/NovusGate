# Arxitektura

## Firewall mühərriki (P3a)
- `server/internal/netctl/nft` — NovusGate-in öz nftables cədvəli `table inet novusgate` (IPv4 + IPv6):
  - `Compile` modeli atomik `nft -f` skriptinə çevirir (`table` → `delete table` → yenidən təyin);
  - `Validate` nft sintaksisinə "inject"-in və təhlükəli portların qarşısını alır;
  - `CheckProtection` SSH lockout-a qarşı qoruyur (fail closed);
  - `Executor` nft CLI üzərindən `Check`, `Apply` və `Snapshot` edir;
  - `SafeApplier` snapshot + `systemd-run` host timer + prosesdaxili timer ilə "60 saniyəyə təsdiqlə, yoxsa geri qayıt" mexanizmini qurur.
- `server/internal/controlplane/firewall` — DB-dəki şəbəkələri və VPN qaydalarını mühərrik modelinə çevirir və host faktlarını (`sshd -T`, `ip route get`) aşkarlayır.
- `novusgate-server firewall preview [--check]` — DB-dən ruleset-i göstərir. Hostu **dəyişmir**: `--check` yalnız `nft -c` edir.
- Hazırda heç bir HTTP endpoint və ya startup kodu nft tətbiq etmir. Tətbiq P3b-də `FIREWALL_ENGINE` bayrağı ilə gələcək.
- Semantika: nftables-də `accept` yekun deyil, `drop` yekundur. Siyasət drop ilə tətbiq olunur, Docker-in və fail2ban-ın cədvəllərinə toxunulmur.
- Testlər: `server/scripts/test-in-docker.sh` (`NFT_CHECK=1` ilə kernel yoxlaması).

## Firewall engine inteqrasiyası (P3b-1)
- **`FIREWALL_ENGINE`:**
  - `iptables` — default, köhnə kod yolları dəyişmir;
  - `shadow` — startup-da yalnız `nft -c` icra olunur;
  - `nft` — engine tətbiq edir.
- **`firewall.Engine`:** `Change.Mutate` ilə dəyişikliyi yaddaşda qurur, tətbiq edir. `Change.Commit` ilə yalnız dəyişiklik canlı olandan sonra (dərhal və ya təsdiqdən sonra) DB-yə yazır, ona görə rollback olan dəyişiklik saxlanmır. Bitmə vaxtı olan IP qaydası üçün reconcile planlaşdırılır.
- **DB:** `fw_services`, `fw_ip_rules`, `fw_forwards`, `fw_egress`, `fw_meta` (migration 006). Rollback faylı `store/migrations_rollback/`-dadır və embed olunmur.
- **REST:** `/api/v1/firewall/v2/*` (bax `docs/api.md`). nft rejimində köhnə `/firewall/host/*` endpoint-ləri validasiyadan sonra adapterə keçir (`firewall_v1_nft.go`). Şəbəkə və node dəyişiklikləri reconcile edir.
- **Startup (nft):** iptables-dən bir dəfəlik idxal (`fw_meta.iptables_imported`), köhnə `novusgate-vpn-*` FORWARD qaydalarının silinməsi, reconcile.
- **Boot faylı:** `/etc/novusgate/firewall.nft`. Onu yükləyən unit P3b-2-dədir.
- **DB testləri:** `server/scripts/test-with-postgres.sh` (`TEST_DATABASE_URL`, `-p 1`).
