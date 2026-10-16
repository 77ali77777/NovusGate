# Panel UX overhaul, network tunnel mode, engine switch — plan

**Mənbə:** istifadəçi tələbi 2026-10-16 ("hər bölmə peşəkar sistemlərdəki kimi, başa düşülən olsun"; "şəbəkə yaradanda split / tam tunel seçilsin, cihazlar ona uyğun olsun"; "nftables paneldən açılsın"; "siyasət cədvəli anlaşılsın").
**Sübut bazası:** izolə test stack-ində real məlumatla 28 ekran görüntüsü (scratchpad `ux/`), kod oxunuşu (aşağıda fayl:sətir).
**Qayda:** hər tapşırıq üçün əvvəl test (RED), sonra kod (GREEN); hər mərhələdən sonra fullweb/Go/Center testləri, izolə brauzer yoxlaması (ekran görüntüsü), müstəqil review, commit. Yeni hər sahə "?" kömək mətni ilə (az + en).

---

## Mərhələ 1 — risksiz UI düzəlişləri (API və DB dəyişmir)

### 1.1 Layout xətaları
| # | Problem (sübut) | Həll | Qəbul meyarı |
|---|---|---|---|
| B1 | Telefonda menyu bağlanıbsa, kompüterdə məzmun yan menyunun altına düşür: `Layout.tsx:212` `lg:ml-64` yalnız `sidebarOpen` olanda; menyu isə `lg:translate-x-0` ilə həmişə görünür | `lg:ml-64` həmişə; `sidebarOpen` yalnız mobil üçün | 1440px-də `sidebarOpen=false` ilə də başlıq tam görünür (ekran görüntüsü) |
| B2 | Telefonda menyu hər açılışda ekranı örtür (vəziyyət yadda saxlanılır) | Mobil menyu vəziyyəti yadda saxlanmır, defolt bağlı; keçiddən sonra bağlanır | 390px-də səhifə açılanda menyu bağlı |
| C8 | Yuxarı panel: boş boz dairə + "Developer rejimi" | İstifadəçi menyusu: ad, rol, "Parolu dəyiş", "Çıxış"; bağlantı nişanı (VPN / dev) kiçik qalır | Panel boş element göstərmir |

### 1.2 Terminologiya və adlar
| # | Problem | Həll |
|---|---|---|
| C1 | "Node-lar", "Peer yarat", "Peer-lər", "3 peer-dən" — eyni şeyə üç ad | Hər yerdə **Cihaz** (en: Device); i18n açarları dəyişmir, mətnlər dəyişir |
| C9 | "Admin Management Network" az interfeysdə ingiliscə; "0 node" (admin cihazı node deyil) | wg0 şəbəkəsi göstərişdə **"Admin VPN"** + izah "Sizin idarə cihazınız buradan qoşulur; panel yalnız bu şəbəkədən açılır" (DB adı dəyişmir) |
| C10 | Parametrlər: "Admin istifadəçilər" (siyahıda operator və izləyici də var) | **İstifadəçilər** |

### 1.3 Cihazlar
| # | Problem | Həll |
|---|---|---|
| B6 | Cədvəl enə sığmır: "Redaktə" sütunu kəsilir, adlar bölünür | Boş/az istifadə olunan sütunlar (Açıq IP, Etiketlər) cihaz detalına; sətir sonunda "…" menyusu (Konfiq, QR, Redaktə, Sil) |
| C2 | Yaradarkən hansı şəbəkəyə düşdüyü görünmür (yan menyudakı seçicidən gizli) | Formada **Şəbəkə** seçimi (defolt: cari); API eynidir (`POST /networks/{id}/servers`) |
| C3 | Detalda konfiq/QR/skript yoxdur; "Redaktə → Deaktiv → Yadda saxla…" hack izahı | Detalda **Konfiq yüklə / QR / Linux skripti** və **"Bağlantını bərpa et"** (mövcud `POST /networks/{id}/sync`) |

### 1.4 Firewall quruluşu
| # | Problem | Həll |
|---|---|---|
| B3 | 10 tab; 1440px-də "Tarixçə", "Sistem qaydaları" ekrandan kənarda | Tablar 5 qrupa: **Xülasə · Server qorunması** (portlar, IP blok/icazə, host qaydaları) · **Şəbəkələr arası** (matris + VPN qaydaları) · **Limitlər** · **Təkmil** (servislər, port yönləndirmə, canlı, tarixçə, sistem qaydaları; nft tələb edir, kilid nişanı) |
| C5 | Hər tabda eyni 3 düymə; icmalda INPUT/FORWARD/OUTPUT ACCEPT jarqonu | Düymələr yalnız "Server qorunması"-nda; icmal sadə dildə: "Server: N port açıq, N IP bloklu; Şəbəkələr arası: …" |
| C6 | "Qaydaları tətbiq et" — qaydalar onsuz da yadda saxlananda tətbiq olunur (`firewall_handlers.go:1078,1158,1199`) | Düymə "**Hamısını yenidən tətbiq et**" adı + "?" izahı ("qaydalar serverdə əl ilə dəyişdirilibsə") |
| C11 | Limitlər xəbərdarlığı "(FIREWALL_ENGINE=nft)" deyir | `EngineOff` ilə eyni izah (+ Mərhələ 3-də açar) |

### 1.5 Siyasət cədvəli (A3) və şəbəkə səhifəsi
- Başlıq "**Haradan ↓ / Haraya →**", hər xanada qısa səbəb (`matrixReason`: qayda adı / eyni şəbəkə / ayrıdır / iptables defolt), altda açıqlama (İcazə · Qadağa · Qismən) və "Qadağanı açmaq üçün xanaya klikləyin".
- Hover `title` yerinə görünən mətn (telefonda da işləyir).
- C12: şəbəkə səhifəsində "ona/ondan" → "**Bu şəbəkədən → X**" / "**X → bu şəbəkəyə**".
- **Qəbul:** ekran görüntüsündə səbəb mətni hər xanada görünür; test: `matrixReason` bütün açarlar üçün.

### 1.6 Digər
| # | Problem | Həll |
|---|---|---|
| B4 | Topologiya açılanda xəritə sığdırılmır, şəbəkələr kəsilir | İlk açılışda `fitView`; saxlanılmış yer yoxdursa avtomatik düzülüş |
| B5 | Server səhifəsi xətada uzun "Yüklənir…" (təkrar sorğular) | Server sorğularında `retry` qaydası (`retryFirewallV2` kimi); aydın xəta mesajı |
| C7 | Audit jurnalı xam HTTP: `POST /networks/{networkId}/servers`, `201` | İnsan dilində: "admin «Ofis» şəbəkəsində cihaz yaratdı" (route → cümlə xəritəsi, ID → ad), nəticə "Uğurlu / Rədd edildi / Xəta", filtr (istifadəçi, əməliyyat növü, tarix). Server dəyişmir |

**Mərhələ 1 testləri:** hər pure helper üçün unit test (audit cümləsi, matris səbəbi, layout qərarı); fullweb (tsc, testlər, biome, vite), helpScan/i18nScan 0; izolə Playwright ilə 28 səhifənin yenidən ekran görüntüsü və əvvəl/sonra müqayisəsi; müstəqil review.

---

## Mərhələ 2 — şəbəkə tunel növü (A1) və rejim zolağı (C4)

**DB (migration 020 + rollback):** `networks.tunnel_mode TEXT NOT NULL DEFAULT 'split' CHECK (tunnel_mode IN ('split','full'))`; `nodes.tunnel_override TEXT NULL CHECK (… IN ('split','full'))` (NULL = şəbəkəyə uyğun). Mövcud `egress` (tam tunel) dəyərləri override `full` kimi köçürülür.

**API:** `POST /networks` `tunnel_mode`; `PUT /networks/{id}/tunnel` (operator); node create/update `tunnel` (`network` | `split` | `full`). OpenAPI + kontrakt goldens; web tipləri yenidən yaradılır.

**Davranış:** cihazın effektiv rejimi = override və ya şəbəkənin rejimi. `tunnelRouting` (`config_handlers.go:25`) bunu oxuyur: tam → `AllowedIPs = 0.0.0.0/0` + DNS. nftables rejimində hub NAT-ı mövcud egress set-i ilə (effektiv tam cihazlar). iptables rejimində hub-da NAT onsuz da var (`wireguard/config_generator.go:40` PostUp `MASQUERADE`) — **açıq qərar, aşağıya bax**.

**UI:**
- Şəbəkə yarat: "**Şəbəkə növü**" — iki kart: "VPN (yalnız VPN şəbəkələri)" / "Tam tunel (bütün internet serverdən)", hər biri qısa izahla və "?".
- Şəbəkə kartı və detalı: növ nişanı; detalda dəyişmək (xəbərdarlıq: "cihazlarda konfiqi yenidən yükləyin").
- Cihaz yarat/redaktə: "Tunel: Şəbəkəyə uyğun (VPN) / Split / Tam"; cədvəldə nişan.
- **C4 rejim zolağı** (Firewall → Şəbəkələr arası və şəbəkə detalı): "Hazırkı rejim **iptables**: şəbəkələr arasında hər şey açıqdır, qaydalar yalnız bloklayır" və ya "**nftables**: şəbəkələr bir-birindən ayrıdır, yalnız qayda icazə verir".

**Testlər:** store (migration, override), REST (create/update/tunnel, kontrakt), `tunnelRouting` (split/full/override/DNS), web helper (effektiv rejim), upgrade testi (köhnə egress → override). Real cihazla internetə çıxış — staging.

---

## Mərhələ 3 — nftables mühərrikini paneldən açmaq (A2)

**Yer:** Server səhifəsi → "Firewall mühərriki" kartı (yalnız admin, step-up), həmçinin `EngineOff` panelindən keçid.

**Axın:**
1. **Ön yoxlama** (dəyişiklik yoxdur): hostun nft versiyası ≥ 1.0.2, nf_tables backend, `setup-firewall.sh` mövcuddur; SSH portları aşkarlanır və göstərilir. Uyğun deyilsə açar səbəbi ilə bağlı.
2. **Keçid** (hostda, `nsenter` + `systemd-run`): `.env`-də `FIREWALL_ENGINE=nft` (əvvəlki fayl saxlanılır) → `setup-firewall.sh` → control-plane yenidən başladılır (`docker restart`, ayrıca host unit-də).
3. **Təsdiq gözləmə:** 120 s ərzində panel yenidən qoşulub "**Saxla**" basılmasa, host timer-i əvvəlki `.env`-i qaytarır, `setup-firewall.sh`-i işlədir və control-plane-i yenidən başladır (sysctl dəyişikliyindəki modelin eynisi).
4. Geri keçid (nft → iptables) eyni yolla.

**Risk:** serverə giriş itə bilər. Avtomatik geri qayıtma, SSH portlarının əvvəlcədən göstərilməsi və runbook (`docs/runbooks/p3b2-firewall-cutover.md`) bunun üçündür. **Real serverdə istifadəçi ilə birlikdə test olmadan "hazırdır" deyilmir.**

**Testlər:** hostadmin (`.env` yazılması, rollback skripti `sh -n`, timer), REST (step-up, 409 gözləyən dəyişiklik, ön yoxlama rədd), UI (geri sayım, səhifə yenidən yüklənəndə vəziyyət serverdən).

---

## Mərhələ 4 — Center düzəlişləri

| # | Problem (kod) | Həll |
|---|---|---|
| U1 | Yalnız fayl **silinən** buraxılış görünmür: `update.sh` `diff -rq … \| grep -v "Only in $INSTALL_DIR"` serverdə qalan köhnə faylları dəyişiklik saymır → "up to date" deyib dayanır | Silinmiş fayllar da dəyişiklik sayılır (`rsync --dry-run --delete` ilə siyahı) |
| U2 | Update log-u nəyin dəyişdiyini göstərmir | "Dəyişən fayllar: N (server), M (web)" + ilk 10 fayl adı |
| U3 | Center-in əsas səhifəsi serverdəki versiyanı göstərmir | Server kartında "Serverdəki versiya: <commit / tarix>" və "Kompüterinizdəki: …"; fərq varsa "Yenilik var" nişanı (install/update zamanı `/opt/NovusGate/VERSION` yazılır) |

---

## Açıq qərar (istifadəçidən)
**Tam tunel iptables rejimində də işləsinmi?**
- **Bəli (tövsiyə):** iptables-də hub NAT-ı artıq var; cihaz konfiqi `0.0.0.0/0` olur. Şəbəkə növü dərhal işləyir, Mərhələ 3-ü gözləmir. Staging-də real cihazla yoxlanmalıdır.
- **Xeyr:** tam tunel yalnız nftables-də; iptables-də seçim kilidli, Mərhələ 3-dən sonra açılır.

## Sıra və təxmini həcm
1. Mərhələ 1 — ən böyük, risksiz (web).
2. Mərhələ 2 — DB + API + web.
3. Mərhələ 4 — Center (kiçik).
4. Mərhələ 3 — ən riskli; sonda, real serverdə birgə test.
