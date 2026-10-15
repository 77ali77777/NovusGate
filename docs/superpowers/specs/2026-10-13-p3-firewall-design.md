# P3 — Firewall (nftables) Dizayn Spesifikasiyası

> **Tarix:** 2026-10-13 · **Status:** təsdiq gözləyir
> **Ana spec:** `docs/superpowers/specs/2026-10-13-novusgate-rebuild-design.md` (§3 sındırmamaq qaydaları, §4.2)
> **Məqsəd:** Linux hostun firewall-unu panel-dən tam və təhlükəsiz idarə etmək. Əhatə dairəsi SSH-dan başlayıb VPN şəbəkələrinə, NAT-a, port forwarding-ə və full tunnel egress-inə qədərdir. Səhv bir qayda heç vaxt serverə girişi bağlamamalıdır.

## 1. İstifadəçi qərarları (2026-10-13)

| Mövzu | Qərar |
|---|---|
| Firewall texnologiyası | nftables (iptables-dən keçid) |
| SSH | **Public qalır**, indiki kimi. Rate-limit və "yalnız VPN/allowlist" istəyə bağlıdır, default olaraq **söndürülüb** |
| Port forwarding | **Lazımdır**: public port → VPN node:port |
| Full tunnel | Firewall hissəsi (egress icazəsi + NAT) **P3-də** hazırlanır; client tərəfi P8-də |
| IPv6 | **IPv4 ilə eyni qaydalar** |

## 2. Yoxlanmış faktlar (2026-10-13, Docker-də icra olundu)

- Həm Ubuntu 24.04 hostu, həm də control-plane image-i (Alpine 3.19) `iptables v1.8.10 (nf_tables)` istifadə edir, yəni backend-lər uyğundur. Ubuntu 20.04 isə legacy backend-dədir, bu P3b-də yoxlanılmalıdır.
- Alpine image-də `nft` yoxdur, `apk add nftables` lazımdır (1.0.9).
- Kompilyatorun yaratdığı ruleset bu versiyalarda `nft -c` yoxlamasından keçir:
  - **nft 1.0.2** (Ubuntu 22.04)
  - **1.0.6** (Debian bookworm)
  - **1.0.9** (Ubuntu 24.04, Alpine 3.19)
- `ct original proto-dst 5432` ifadəsi 1.0.6-da yalnız `meta l4proto tcp` konteksti ilə qəbul olunur.
- Atomik əvəzetmə modeli işləyir: `table inet novusgate` → `delete table inet novusgate` → `table inet novusgate {…}`. Cədvəl yoxdursa da, varsa da eyni nəticə verir. Təkrar tətbiq də işləyir.
- Snapshot geri yüklənir: `nft list table` çıxışı silmə sətrinin arxasınca qoyulur. Bu, timeout-lu ban-lar kimi **dinamik set elementlərini də** geri qaytarır.
- Səhv ruleset `nft -c`-də exit 1 qaytarır və canlı cədvələ toxunulmur.
- `nft -f -` stdin-dən oxuyur.
- **Mühit tələsi:** Windows-dakı WSL docker shim argumentlərdəki `$`-ı (`$?`, `$(…)`) konteynerə çatmamış genişləndirir. Shell məntiqi həmişə skript faylında olmalıdır. Nümunə: `server/scripts/test-in-docker.sh`.

## 3. nftables semantikası (dizaynın təməli)

- `accept` **yekun deyil**: paket eyni hook-dakı digər base chain-lərdən də keçir (Docker-in iptables-nft cədvəlləri, fail2ban-ın öz cədvəli). `drop` isə **yekundur**.
- Nəticədə:
  - Bizim cədvəl qadağaları `drop` ilə tətbiq edir.
  - İcazələrimiz yalnız başqa cədvəllər də icazə verəndə işə yarayır.
  - **P3b keçidi zamanı** iptables INPUT siyasəti ACCEPT-ə çevrilməli və panel-in iptables qaydaları silinməlidir, əks halda iptables-in `INPUT DROP` siyasəti bizim icazələrimizi bloklayar.
- Docker-in FORWARD zəncirləri saxlanılır. wg trafiki üçün minimal iptables ACCEPT (indiki PostUp) qalır, deny isə bizim cədvəldədir.

## 4. Cədvəl quruluşu: `table inet novusgate` (IPv4 + IPv6)

| Element | Məzmun |
|---|---|
| `set ssh_ports` | sshd-dən aşkarlanan portlar (həmişə qorunur) |
| `set wg_ports` (interval) | `51820-51900` + hər şəbəkənin `ListenPort`-u. 51900-dən böyük portlar da açılır (B-baqı) |
| `set blocked_v4/v6` (interval, timeout) | bloklar; müddətli ban-lar `timeout Ns` ilə. Vaxtı keçmiş və geniş prefiksin əhatə etdiyi elementlər atılır |
| `set egress_v4` | full tunnel icazəli node IP-ləri |
| `chain input` (policy **drop**) | lo → bloklar → established → invalid drop → SSH → WireGuard UDP → `wg0`: 3007/5432 → `wg*`: 8080/8443 → servislər (mənbə və interfeys məhdudiyyəti ilə, v4/v6) → ICMP/ICMPv6 → `counter` |
| `chain forward` (policy accept) | bloklar → established → public-dən Docker-ə publish olunmuş 5432 drop → `wg*` → `vpn_policy`. VPN-ə daxil olan trafik yalnız DNAT olunubsa (port forward) keçir, qalanı drop |
| `chain vpn_policy` | VPN qaydaları (sıra ilə; accept/drop/reject) → eyni şəbəkə daxilində trafik accept (indiki davranış) → `egress_v4` → internet accept → `counter drop` |
| `chain prerouting` (nat) | port forward: `iifname <egress> tcp dport P dnat ip to T:Q` |
| `chain postrouting` (nat) | port forward-un cavab yolu: `ip daddr T oifname wgN … ct status dnat masquerade`. Node-un AllowedIPs-i internet client-in IP-sini əhatə etmir, ona görə cavab hub vasitəsilə qayıdır. Bununla yanaşı `egress_v4` → `masquerade` |

**Saxlanılan davranış:**
- SSH 22 həmişə açıqdır.
- Admin portları yalnız VPN-dəndir.
- ICMP açıqdır.
- Eyni şəbəkə daxilindəki peer-lər bir-biri ilə danışa bilir.
- WireGuard aralığı açıqdır.
- Default deny.

**Yeni:**
- IPv6 üçün də eyni qaydalar.
- Port forwarding.
- Egress (full tunnel).
- 51900-dən yuxarı WireGuard portları.
- Docker 5432-nin həqiqətən bağlanması.
- VPN DROP qaydalarının həqiqətən işləməsi (B7).

## 5. Təhlükəsizlik mexanizmləri

1. **Validasiya (`Validate`):**
   - interfeys və ID-lər regex ilə yoxlanılır, ona görə nft sintaksisinə heç nə "inject" olunmur;
   - admin portları public servis kimi açıla bilməz;
   - forward SSH, admin və WireGuard portlarına qoyula bilməz;
   - forward-un hədəfi bir VPN şəbəkəsinin içində olmalıdır;
   - VPN subnet-ləri yalnız IPv4-dür.
2. **SSH qoruması (`CheckProtection`):** aşkarlanan bütün SSH portları ruleset-də olmalıdır. Operatorun hazırkı ünvanı bloklana bilməz. SSH portu aşkarlanmasa, **rədd edilir** (fail closed).
3. **Təhlükəsiz tətbiq (`SafeApplier`):**
   1. `nft -c` ilə yoxlanılır.
   2. Snapshot alınır.
   3. **Host-side timer qurulur:** `systemd-run --on-active=60s nft -f <snapshot>`. Qurulmasa, tətbiq edilmir.
   4. Ruleset tətbiq olunur.
   5. Prosesdaxili timer işə düşür.
   6. `Confirm` hər iki timer-i dayandırır. Təsdiq gəlməsə, snapshot geri yüklənir.
   7. Control plane çöksə belə, host timer bərpanı edir.
4. **Legacy (v1) endpoint-lər** təsdiq UI-ı bilmir. Onlar `confirm=false` ilə dərhal tətbiq olunur, amma validasiya və SSH qoruması **həmişə** işləyir.

## 6. Alt-planlar

| Plan | Məzmun | Davranış dəyişikliyi | Qəbul şərti |
|---|---|---|---|
| **P3a Mühərrik** | `internal/netctl/nft`: model, validasiya, kompilyator, SSH qoruması, aşkarlama, executor, təhlükəsiz tətbiq + systemd timer. `internal/controlplane/firewall`: DB → model. `novusgate-server firewall preview [--check]`. Image-ə `nftables` | **Yoxdur**: heç nə avtomatik tətbiq olunmur | Bütün testlər yaşıl, kernel yoxlaması nft 1.0.2/1.0.6/1.0.9-da keçir; staging-də `preview --check` OK |
| **P3b İnteqrasiya** | Yeni cədvəllər (`fw_services`, `fw_blocked`, `fw_forwards`, `fw_egress`, `fw_settings`, `fw_snapshots`) + rollback; API `/firewall/v2/*` (təsdiq ilə); v1 endpoint-ləri adapter kimi; iptables-dən import (Open Port, Blocked IP); `FIREWALL_ENGINE=iptables\|shadow\|nft` (default `iptables`, sonra `shadow`, sonra `nft`); `novusgate-firewall.service` boot-da Docker-dən əvvəl; `setup-firewall.sh` artıq flush etmir; fail2ban `nftables-multiport` + xüsusi SSH portu; legacy backend aşkarlanması; SSH portlarını Close Port/Delete-dən qorumaq | Bəli, mərhələli və bayraqla idarə olunan | Staging runbook: lockout ssenariləri, Docker konteynerləri işləyir, reboot-dan sonra qaydalar yerindədir, Update panel qaydalarını silmir |
| **P3c UI** | Yeni UI kit üzərində (P5-dən sonra): Overview (SSH qorunur, IPv6, Docker exposure, gözləyən təsdiq), Services, Access Lists, Network Policies (matris), NAT & Forwarding, Fail2Ban, Live (sayğaclar, drop log-u, conntrack), History (diff, rollback), System Rules (yalnız oxumaq üçün) | — | §6 paritet siyahısı + yeni funksiyalar |

**P3c statusu (2026-10-15):** P5/P6 ləğv olunduğu üçün P3c hazırkı dizaynda edildi. Advanced tabında servislər, IP qaydaları, forward-lar, egress və preview var. Live tabında sayğaclar, son 1 saatda drop olunan mənbələr (dinamik nft set) və conntrack var. History tabında diff və təsdiqli restore var. Network Policies matrisi və ayrıca System Rules görünüşü edilmədi; VPN qaydaları köhnə VPN Rules tabında qalır.

## 6a. P3a final review-dan P3b-yə ötürülən tələblər (2026-10-13)
- `CheckProtection` hər tətbiq yolunda (`confirm=false` daxil) çağırılmalıdır. `SafeApplier` xam skript qəbul edir və qorumanı özü yoxlamır (M3).
- `Protection.Addrs`-a sorğunun mənbə ünvanı və operatorun **WireGuard endpoint IP-si** daxil edilməlidir. `CheckProtection`-dan əvvəl ünvanlar `Unmap()` olunmalıdır (M2).
- Reconcile ən yaxın ban bitmə vaxtında yenidən işləməlidir. Kompilyator interval set-də daha geniş, amma tez bitən blokun altındakı daha uzunömürlü daha dar bloku atır (M4). 365 gündən uzun ban-lar da timeout-suz render olunur.
- `SystemdTimer` `NsenterRunner` ilə işlədilməlidir. Host-da `nft` olmalıdır, ona görə installer `apt-get install -y nftables` etməlidir. Olmasa, `Arm` rədd edir (fail closed).
- Admin portlarının istisnası `wg*` prefiksinə görə deyil, `rs.Networks`-dəki interfeyslərə görə olmalıdır (M5).
- Runbook-da qeyd olunmalıdır: istifadəçinin öz Docker bridge konteynerləri host xidmətlərinə və VPN peer-lərinə çata bilməyəcək (M8). Çevrilə bilməyən drop/reject VPN qaydaları atlanır (M9, indiki davranış kimi).
- CI-a kənar ruleset-lər əlavə edilməlidir: boş, yalnız v6 mənbələr, şəbəkəsiz. Versiyalar arası snapshot yoxlaması da daxil (M10).
- **P3b-2-də bağlandı (2026-10-13):**
  - M5 (`331dc34`);
  - M8 runbook qeydi (`docs/runbooks/p3b2-firewall-cutover.md`, addım 11);
  - M10: kənar golden-lar və `scripts/nft-versions-check.sh` (`331dc34`);
  - installer-in `nftables` paketi: `setup-firewall.sh` (`f22aaaa`).

## 6b. P3b-1 final review-un minor-ları, P3b-2-yə ötürülür (2026-10-13)

**Status (P3b-2):**
- **Bağlandı:**
  - 1: 409 (`033d080`);
  - 2: commit `WithoutCancel`, uğursuz commit-dən sonra reconcile, Persist xəbərdarlıq kimi (`2854f01`), servislər bir tranzaksiyada (`033d080`);
  - 3: ən uzun prefiks (`033d080`);
  - 5: WireGuard portları və `/128` (`033d080`);
  - 6: hazır olma şərti (`2854f01`);
  - 7: panel-in delete sorğusu (`033d080`);
  - 4: 2026-10-14, istifadəçi qərarı ilə: allow qaydaları admin və API portlarını açmır (bax `docs/api.md`).
- **Açıq qalır:**
  - 5-in `line_number` sürüşməsi: v1 API-nin nömrəyə əsaslanan məhdudiyyətidir, P3c UI v2 ID-lərindən istifadə edir.
1. **Forward-un dublikatı.** Eyni `(protocol, public_port)` cütü üçün forward kernel-ə tətbiq olunur, sonra Commit `UNIQUE` şərtində uğursuz olur və 500 qaytarır. Bunu Mutate-də 409 ilə əvvəlcədən yoxlamaq lazımdır.
2. **Apply-dan sonrakı xətalar.**
   - Commit request-in `ctx`-i ilə işləyir. Bunun əvəzinə `context.WithoutCancel` istifadə olunmalıdır.
   - Commit xətası olanda best-effort reconcile edilməlidir.
   - Persist xətası 500 yox, xəbərdarlıq olmalıdır.
   - `addServices` tranzaksiyasızdır.
3. **`wireGuardEndpointFor` ilk uyğun peer-i qaytarır.** Ən uzun prefiks uyğunluğu lazımdır, endpoint yolu üçün test də yazılmalıdır.
4. **Whole-address Allow IP public mənbə üçün admin portlarını (3007/5432/8080/8443) açır.** Bu legacy davranışla paritetdir, amma §4 ilə ziddiyyət təşkil edir. Qərar istifadəçinindir.
5. **v1 adapter-lərinin kənar halları.**
   - Sintetik WireGuard sətri həmişə `51820:51900` göstərir.
   - `/128` sonluğu kəsilmir.
   - Expiry və ya SSH aşkarlanması dəyişəndə `line_number` sürüşür.
6. **Startup idxalı ilə v1 handler-ləri arasında pəncərə var.** İdxaldan əvvəl açılan port idxalda dublikat yarada bilər.
7. **Əvvəldən mövcud bug.** Panel `DELETE /firewall/host/rules` çağırır (`web/src/api/client.ts`), backend isə yalnız `POST /firewall/host/rules/delete` qeydiyyatdan keçirir. Nəticədə hər iki rejimdə Delete/Unblock işləmir.

## 7. Açıq risklər

- **Ubuntu 20.04 (iptables legacy):** konteynerdəki iptables-nft ilə hostun legacy qaydaları fərqli backend-lərdə yaşayır. P3b-də aşkarlanmalı və ayrıca xəbərdarlıq göstərilməlidir.
- **`systemd-run`** host-da olmalıdır (Ubuntu standartı). Olmasa, `SafeApplier` tətbiqi rədd edir və heç vaxt qorumasız tətbiq etmir.
- **Eyni şəbəkə daxilində default accept** indiki davranışdır. Onu məhdudlaşdırmaq istəyən istifadəçi VPN DROP qaydası yazır, qaydalar intra-network accept-dən əvvəl yoxlanılır.
