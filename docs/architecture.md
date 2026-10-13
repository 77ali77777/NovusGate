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
- **Startup (nft):**
  - iptables-dən bir dəfəlik idxal (`fw_meta.iptables_imported`). "Əvvəlki ACCEPT sonrakı DROP-u üstələyir" ziddiyyəti olarsa, idxal rədd edilir;
  - reconcile;
  - köhnə `novusgate-vpn-*` FORWARD qaydaları yalnız ilk uğurlu apply-dan sonra silinir (`Engine.AfterApply`).
- **Retry:** uğursuz reconcile (pending təsdiq, aktiv rollback timer, aşkarlama xətası) `ReconcileOrRetry` ilə arxa planda təkrarlanır. Backoff 15 saniyədən başlayır, 5 dəqiqəyə qədər artır. Expiry, şəbəkə/node/VPN dəyişiklikləri və startup bu yoldan keçir.
- **Qoruma:** hər apply-da sorğu edənin ünvanından əlavə, `wg0` peer-lərinin canlı WireGuard endpoint-ləri də qorunur (`Engine.Protect`).
- **Boot faylı:** `/etc/novusgate/firewall.nft`. Onu `novusgate-firewall.service` yükləyir:
  - unit-i `setup-firewall.sh` qurur;
  - `Before=network-pre.target docker.service`;
  - fayl olmayanda unit heç nə etmir.

### Keçid (P3b-2)
- **Host yoxlaması (`firewall.CheckHost`).** nft rejiminin şərtləri:
  - host nft ≥ 1.0.2;
  - `novusgate-firewall.service` aktivdir (`enabled`);
  - iptables nf_tables backend-dədir.

  Şərt ödənmirsə, startup dayanır, iptables işləməyə davam edir və firewall dəyişiklikləri 409 qaytarır. Ubuntu 20.04 bu şərtlərə görə dəstəklənmir.
- **Hazır olma.** Startup iptables idxalını bitirib `MarkReady` çağırana qədər engine dəyişiklik qəbul etmir (`ErrNotReady`).
- **INPUT-un təhvili (`firewall.CutoverIptables`).** İlk uğurlu apply-dan sonra (`Engine.AfterApply`, prosesin hər başlanğıcında bir dəfə):
  1. iptables INPUT siyasəti `ACCEPT` olur;
  2. INPUT-dakı sadə `ACCEPT`/`DROP` qaydaları öz spec-i ilə silinir (nömrə ilə yox, ona görə fail2ban-ın eyni anda etdiyi dəyişiklik silinəni sürüşdürə bilməz). `REJECT` ban-ları və başqa alətlərin zəncirlərinə jump-lar (fail2ban, CrowdSec) saxlanılır və log-a yazılır;
  3. `netfilter-persistent save` icra olunur.

  Köhnə `novusgate-vpn-*` FORWARD qaydaları da eyni anda silinir.
- **`setup-firewall.sh`:**
  - hər rejimdə `nftables` paketini quraşdırır (`nftables.service` heç vaxt aktiv edilmir), boot unit-i qurur və fail2ban üçün `jail.d/novusgate.local` faylını yazır (bütün SSH portları; nft rejimində `nftables-multiport`);
  - nft rejimində, ruleset faylı mövcuddursa, iptables-ə və Docker-ə toxunmur;
  - iptables rejimində əvvəl baseline-ı qurur, sonra `table inet novusgate` cədvəlini və boot faylını silir. Geri qayıdış budur.
- **M5.** VPN-only istisnalar (API portları, rezerv portlarda servislər) yalnız DB-dəki şəbəkə interfeyslərinə və `wg0`-a aiddir.
- **Versiyalar arası yoxlama.** `server/scripts/nft-versions-check.sh` golden ruleset-ləri və nft 1.0.9 snapshot-unu nft 1.0.2, 1.0.6 və 1.0.9-da `nft -c` ilə yoxlayır.
- **DB testləri:** `server/scripts/test-with-postgres.sh` (`TEST_DATABASE_URL`, `-p 1`).

## Test seam-ləri (P2a)
- **`api/rest`-də dəyişdirilə bilən funksiyalar:**
  - `execHostCommand`, `execCommand`: host və konteyner əmrləri;
  - `generateKeys`: WireGuard açarları;
  - `readFail2BanLog`: `/var/log/fail2ban.log`;
  - `legacySSHPorts`, `adminPeers`, `clearLegacyVPNRules`, `checkFirewallHost`, `cutoverIptables`.

  Testlər bunları stub edir, heç bir test host-a toxunmur.
- **Kontrakt testləri** bax `docs/api.md`. Golden fayllar `.gitattributes` qaydası (`server/**/testdata/** eol=lf`) ilə LF saxlanılır.
- **Yeni şəbəkənin hub ünvanı:** CIDR-in ilk host-u, CIDR-in öz prefiksi ilə (`hubAddress`).
- **`AllocateIP`:** network, `.1` və `.2` ünvanlarını ötürür, broadcast-ı heç vaxt vermir.
- **Startup log-u:** DB URL-dəki parol maskalanır (`maskDatabaseURL`).
