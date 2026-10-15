# P9/P10 — VPN nəzarəti (limitlər, qadağalar) və serverin idarəsi

> **Status:** təklif, istifadəçi təsdiqini gözləyir (2026-10-15).
> **Branch:** `feature/p9-control`, `rebuild/plans`-dan (`b17319e`) ayrılıb.
> **Əsas spec:** `2026-10-13-novusgate-rebuild-design.md`. Sındırmamaq qaydaları (§3) burada da qüvvədədir.

## 1. Məqsəd

İstifadəçinin təsviri: NovusGate üç şeydir.
1. **Tam funksional VPN sistemi.** Bu hissə əsasən hazırdır.
2. **VPN serverinin özünün idarəsi:** daxili şəbəkə ayarlarından firewall ayarlarına qədər hər şey paneldən.
3. **VPN firewall sistemi:** limitlər, qadağalar və s.

Bu spec 2 və 3-də olan boşluqları bağlayır. Kodda yoxlanılıb (2026-10-15):
- sürət limiti, kvota və bağlantı limiti yoxdur;
- server tərəfində yalnız oxumaq var (`/system/info`), həmçinin Fail2Ban, firewall və backup;
- client DNS sabit `1.1.1.1`-dir;
- panel istifadəçilərinin rolu yoxdur.

## 2. Qərarlar

İstifadəçi təklifi "et" ilə qəbul etdi. Aşağıdakılar tövsiyə edilən default-lardır və istənilən vaxt dəyişdirilə bilər.

| Mövzu | Qərar | Alternativ |
|---|---|---|
| Branch | `feature/p9-control`, `rebuild/plans`-dan | — |
| Sürət limiti | nftables `limit rate` (policing) | `tc` HTB shaping. Daha hamardır, daha mürəkkəbdir; lazım olsa sonra |
| Kvota aşanda | **blokla** (node VPN trafikini itirir, handshake qalır); qrup/node üzrə "sürəti endir" seçimi | — |
| DNS filtri | `blocky` (Go, tək binary, konteyner) | AdGuard Home |
| Panel rolları | `admin`, `operator`, `viewer` | — |
| Sıra | P9a → P9b → P9c → P10a → P9d → P10b | P10a-nı önə çəkmək |

## 3. Ortaq prinsiplər

- **Bir mühərrik:** bütün yeni firewall imkanları mövcud nftables mühərrikinə (`netctl/nft` kompilyatoru, `firewall.Engine`) əlavə olunur. Nəticədə:
  - eyni təsdiq/rollback;
  - eyni History;
  - eyni golden və `nft-versions-check.sh` testləri.

  iptables rejimində yeni limitlər **tətbiq olunmur**: panel bunu açıq yazır və nft rejimini tövsiyə edir. Səbəb: iptables yolu yalnız uyğunluq üçün saxlanılır.
- **Hostu dəyişən hər əməliyyat** (P10) eyni təhlükəsiz qəlibdən keçir:
  1. əvvəlki vəziyyət saxlanılır;
  2. dəyişiklik tətbiq olunur;
  3. N saniyə içində təsdiq gəlməsə systemd timer əvvəlki vəziyyəti qaytarır.

  Bu, firewall-un `SafeApplier`-i ilə eyni modeldir.
- **Səlahiyyət:** P10 endpoint-ləri yalnız `admin` üçündür. Parol yenidən istənilir (step-up, 5 dəqiqə etibarlı). Hamısı audit jurnalına düşür.
- **i18n:** bütün yeni UI mətnləri `az`/`en` namespace-lərindədir. `tests/i18n.test.mjs` bunu tələb edir.
- **Tiplər:** backend dəyişəndə `update-contracts.sh` → `npm run gen:api`.

## 4. P9a — Qruplar və rollar (təməl)

### 4.1 Node qrupları
- **DB (miqrasiya 013 + rollback):**
  - `node_groups(id, name UNIQUE, description, created_at)`;
  - `node_group_members(group_id → node_groups ON DELETE CASCADE, node_id → nodes ON DELETE CASCADE, PK(group_id,node_id))`.
- **API:**
  - `GET/POST /api/v1/groups`;
  - `PUT/DELETE /api/v1/groups/{id}`;
  - `PUT /api/v1/groups/{id}/members` (tam siyahı).
- **VPN qaydaları:** `source_type`/`dest_type`-a `group` əlavə olunur (`source_group_id`, `dest_group_id`). Miqrasiyada `firewall_rules`-a nullable sütunlar gəlir.
- **Kompilyator:** hər qrup üçün `set grp_<id> { type ipv4_addr; elements = { üzvlərin virtual IP-ləri } }`, qaydalar `ip saddr @grp_<id>` ilə.
  - Üzv dəyişəndə reconcile olur. Bütün cədvəl yenidən yüklənir; bu, indiki modeldir.
  - **Yoxlanıb:** `nft -c` 1.0.2/1.0.6/1.0.9-da keçdi.
- **Policy matrisi:** qrup qaydaları matrisdə node qaydaları kimi "partial" sayılır (üzvlər hansı şəbəkədədirsə).
- **UI:**
  - Nodes səhifəsində qrup sütunu və filtr;
  - Settings-də və ya ayrıca "Groups" səhifəsində qrupların idarəsi;
  - VPN qayda modalında "Qrup" növü.

### 4.2 Panel rolları
- **DB:** `users.role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','operator','viewer'))`. Mövcud istifadəçilər `admin` olur.
- **Rollar:**
  - `viewer`: yalnız GET;
  - `operator`: node/şəbəkə/qrup/VPN qaydaları/limitlər; firewall host qaydaları, backup, server idarəsi, istifadəçilər və bildiriş ayarları yox;
  - `admin`: hər şey.
- **Tətbiq:** route şablonuna görə cədvəl (`roleRequired[route+method]`) middleware-də yoxlanılır.
  - Default: dəyişdirən sorğu → `admin`.
  - Test hər route-un cədvəldə olduğunu yoxlayır, ona görə yeni route rolsuz qalmır.
- **Sessiya cavabı** `role` qaytarır; UI icazəsiz düymələri gizlədir. Backend yenə də yoxlayır.
- **Ən azı bir admin:** son admini silmək və ya endirmək 409 qaytarır.

**P9a qəbul şərti:**
- qrup qaydası compile və `nft -c` keçir;
- viewer heç bir dəyişiklik edə bilmir (403);
- son admin qorunur.

## 5. P9b — Sürət limiti, bağlantı limiti, vaxt cədvəli

Hamısı "limit profili" kimi node-a və ya qrupa bağlanır. Node-un öz profili qrupunkundan üstündür.

- **DB (014):** `limit_profiles`:
  - `id, name`;
  - `down_kbps, up_kbps` (NULL = limitsiz);
  - `max_connections` (NULL = limitsiz);
  - `schedule JSONB` (həftənin günləri və saat aralıqları);
  - `timezone TEXT`.

  `node_groups.limit_profile_id`, `nodes.limit_profile_id` nullable sahələrdir.
- **Sürət:** forward zəncirində, VPN qaydalarından **əvvəl** (`vpn_policy`-yə jump-dan qabaq):
  - yuxarı: `ip saddr <ip> limit rate over <up> kbytes/second drop`;
  - aşağı: `ip daddr <ip> limit rate over <down> kbytes/second drop`.

  Qrup profili bütün qrupa bir limit vermir, **hər üzvə ayrıca** limit verir: `update @rl_<profil>_up { ip saddr limit rate over … }` dinamik set-i ilə.
  - **Yoxlanıb:** sintaksis `nft -c` ilə 3 versiyada.
  - Full tunnel-dəki internet trafiki də bu limitə düşür.
- **Bağlantı:** yeni bağlantıda `add @ct_<profil> { ip saddr ct count over N } drop` (TCP və UDP). **Yoxlanıb:** sintaksis.
- **Vaxt cədvəli:**
  - cədvəl daxilində heç nə dəyişmir;
  - cədvəldən kənarda node-un forward trafiki drop olur.
  - Kompilyasiya: `ip saddr @… meta day {…} meta hour "HH:MM"-"HH:MM" return`, sonra drop. **Yoxlanıb:** sintaksis 3 versiyada.
  - ⚠️ **Yoxlanmalı:** nft `meta hour`-u yükləmə anında hostun saat qurşağına görə çevirir. DST keçidində qaydalar yenidən yüklənməlidir. Plan: control-plane DST sərhədlərində reconcile planlaşdırır (`scheduleExpiry` qəlibi ilə), test ilə.
- **Matris və Live:**
  - matris limitləri göstərmir, çünki verdikt dəyişmir; xanada "limitli" işarəsi olur;
  - Live sayğacları hər limit qaydası üçün atılan paketləri göstərir (comment `limit:`).
- **UI:**
  - Firewall → "Limits" tabı: profillər, onların node/qruplara bağlanması;
  - node detalında aktiv profil.

**P9b qəbul şərti:**
- golden testlər;
- `nft-versions-check.sh` OK;
- **funksional test** (netns + veth, P3-dəki kimi):
  - sürət limiti `iperf3` ilə ölçülür (±20%);
  - bağlantı limiti N+1-ci bağlantını atır;
  - cədvəldən kənar trafik bloklanır.

## 6. P9c — Trafik kvotası

- **DB (015):**
  - `limit_profiles`-ə `quota_mb_month`, `quota_action ('block'|'throttle')`, `throttle_kbps`, `quota_reset_day (1–28)` əlavə olunur;
  - `node_quota_state(node_id, period_start, used_bytes, exceeded_at)`.
- **Hesablama:** mövcud 5 dəqiqəlik `node_traffic_samples`-dən dövr ərzində rx+tx toplamı (sayğac sıfırlananda delta mövcud traffic kodu kimi hesablanır). Job hər 5 dəqiqədən bir, sampler ilə birlikdə işləyir.
- **Aşanda:**
  - `block` → node-un IP-si `quota_exceeded_v4` set-inə əlavə olunur (forward-da drop);
  - `throttle` → `throttle_kbps` limiti tətbiq olunur;
  - Telegram bildirişi gedir (yeni hadisə növü `quota_exceeded`, ayarlarda açar);
  - %80-də xəbərdarlıq.
- **Sıfırlanma:** dövr başında avtomatik; panel-də "kvotanı indi sıfırla" (admin/operator).
- **UI:** node siyahısında və detalında istifadə zolağı (məs. 32/50 GB).

**P9c qəbul şərti:**
- vaxt və nümunələr fake edilmiş testlər: dövr sərhədi, sayğacın sıfırlanması, %80 və %100, sıfırlanma;
- blok set-i compile olunur.

## 7. P10a — Server idarəsi, aşağı risk

Hamısı `nsenter` ilə hostda işləyir. Mövcud `HostRunner`/`NsenterRunner` qəlibi ilə.

| İmkan | Necə | Rollback |
|---|---|---|
| Servislər (wg-quick@*, docker, fail2ban, control-plane) | `systemctl status/restart` | lazım deyil; restart təsdiq soruşur |
| Client DNS (şəbəkə üzrə) | `networks.client_dns` (016); config, QR və install skripti onu işlədir; full tunnel default-u 1.1.1.1 qalır | DB dəyişikliyidir |
| sysctl | icazəli açarlar: `net.ipv4.ip_forward`, `net.ipv4.conf.all.rp_filter`, `net.netfilter.nf_conntrack_max`, `net.ipv4.tcp_congestion_control` (bbr/cubic), `net.core.default_qdisc`; `/etc/sysctl.d/90-novusgate.conf` + `sysctl -p` | təsdiq/rollback timer |
| Sistem | hostname (`hostnamectl`), saat qurşağı və NTP (`timedatectl`), yenilənəcək paketlər (`apt list --upgradable`) və `apt-get upgrade` (iş kimi, log ilə), reboot | reboot və upgrade iki addımlı təsdiq |
| Şəbəkə görünüşü | `ip -j addr`, `ip -j route`, `ip -j link`: yalnız oxumaq | — |

- **UI:** yeni "Server" səhifəsi (sidebar), tablar: Servislər, Şəbəkə, Kernel, Sistem.

**P10a qəbul şərti:**
- runner fake ilə əmr testləri;
- sysctl icazəli siyahıdan kənar açarı rədd edir;
- rollback timer qurulur;
- rol: yalnız admin.

## 8. P9d — DNS filtri

- **Komponent:** compose-a `blocky` konteyneri. Host şəbəkəsində, yalnız VPN interfeyslərinin ünvanlarında dinləyir.
  - **Yeni image — təsdiq tələb edir:** versiya pin olunur, 2 həftədən köhnə buraxılış.
- **Yönləndirmə:** nft-də `iifname "wg*" udp/tcp dport 53 dnat to <hub IP>:53`; `tcp dport 853` (DoT) drop. Ona görə client DNS-i dəyişsə də filtr işləyir.
- **Konfiqurasiya:** panel blok siyahılarını (URL-lər), xüsusi qadağan/icazəli domenləri və qrup üzrə siyasəti saxlayır, `blocky` config-i yaradır və reload edir.
- **Statistika:** `blocky` API-dən bloklanan sorğuların sayı Live-da göstərilir.
- **Məlum məhdudiyyət:** DoH (443 üzərindən DNS) bloklanmır. Yalnız məlum DoH endpoint-ləri IP siyahısı ilə bağlana bilər. Sənəddə açıq yazılır.

**P9d qəbul şərti:**
- funksional test: konteynerdə qadağan domen `NXDOMAIN`, icazəli domen cavab verir;
- DNAT qaydası golden-də.

## 9. P10b — Route-lar və SSH (yüksək risk, ən sonda)

- **Statik route-lar:**
  - DB `static_routes`;
  - `novusgate-routes.service` (oneshot) `ip route replace …` edir;
  - netplan/ifupdown fayllarına toxunulmur;
  - dəyişiklik təsdiq/rollback ilə;
  - default route dəyişdirilmir (rədd edilir).
- **SSH:**
  - port və `PasswordAuthentication`;
  - `/etc/ssh/sshd_config.d/90-novusgate.conf` yazılır, `sshd -t` yoxlayır;
  - firewall yeni portu **əvvəl** açır (protected SSH ports);
  - `systemctl reload ssh`;
  - 120 s içində təsdiq gəlməsə köhnə config bərpa olunur.

  Parol ilə girişi bağlamaq yalnız serverdə ən azı bir `authorized_keys` açarı varsa icazəlidir.

**P10b qəbul şərti:**
- staging runbook: port dəyişikliyi + təsdiqsiz geri qayıtma real VM-də;
- `sshd -t` uğursuz olarsa heç nə dəyişmir.

## 10. Testlər və yoxlama

- **Go:** hər mərhələ üçün unit + DB testləri (`test-with-postgres.sh`); kompilyator golden-ləri; `NFT_CHECK=1`; `nft-versions-check.sh`.
- **Funksional şəbəkə testləri:** netns + veth konteynerində (iptables VPN zənciri testindəki kimi), CI-da opsional.
- **Web:** `npm test` (i18n, OpenAPI drift daxil), `tsc`, `vite build`.
- **Hər mərhələnin sonunda müstəqil review** (opus). Tapıntılar düzəldilir.

## 11. Risklər

| Risk | Azaltma |
|---|---|
| Limit qaydaları köhnə kernel-də yüklənmir | `nft -c` yalnız WSL kernel-də yoxlanıb; Ubuntu 20.04 (5.4) VM-də yoxlanacaq. Uğursuz olarsa həmin imkan host yoxlamasında söndürülür və panel bunu yazır |
| Vaxt cədvəli və DST | DST sərhədlərində reconcile; testlə |
| Policing TCP-də sürəti "dişli" edir | Sənəddə yazılır; ehtiyac olarsa `tc` (ayrıca qərar) |
| Server idarəsi girişi itirir | Hər yazma əməliyyatı təsdiq/rollback timer ilə; SSH və route ən sonda, staging runbook ilə |
| DNS filtri DoH ilə keçilir | Sənəddə məhdudiyyət; məlum DoH IP-lərinin bloklanması seçimi |
| Rol cədvəlində unudulmuş route | Bütün route-ları cədvəllə müqayisə edən test |

## 12. Təsdiq gözləyən

1. Bu spec (bütövlükdə və ya dəyişikliklərlə).
2. **P9d** — `blocky` image-i (yeni komponent).
3. **P10b** — staging VM-də sınaq (istifadəçi edir).
