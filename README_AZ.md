# NovusGate

[![GitHub stars](https://img.shields.io/github/stars/Ali7Zeynalli/NovusGate?style=social)](https://github.com/Ali7Zeynalli/NovusGate/stargazers)
[![Lisenziya](https://img.shields.io/badge/Lisenziya-Apache_2.0-blue.svg)](LICENSE)
[![WireGuard](https://img.shields.io/badge/Protocol-WireGuard-88171A.svg)](https://www.wireguard.com/)
[![VPN Type](https://img.shields.io/badge/VPN%20Tipi-Uzaqdan%20Giri%C5%9F-blue.svg)](#-vpn-tipi)

🚀 **Öz şəxsi VPN şəbəkənizi qurun — SaaS asılılığı və ya ağrılı konfiqurasiyalar olmadan.**

**NovusGate** — **WireGuard®** protokolu üzərində qurulmuş, müasir, tamamilə özünüzün idarə etdiyi (self-hosted) **VPN idarəetmə panelidir**.
Tək bir veb paneldən idarə olunan **Hub-and-Spoke (Mərkəz və Budaq) arxitekturası** ilə serverləri, bulud instansiyalarını və şəxsi cihazları təhlükəsiz şəkildə birləşdirir.

İstər istehsalat (production) infrastrukturunu idarə edin, istərsə də sadəcə şəxsi şəbəkənizə tam sahib olmaq istəyin — **NovusGate sizə aydınlıq, təhlükəsizlik və nəzarət verir**.

![NovusGate Dashboard](web/public/novusgate_banner.png)

> 🇺🇸 **English:** [README.md](./README.md)

---

## ⚠️ Vacib: NovusGate Nədir (və Nə Deyil)

**NovusGate "IP-ni gizlət" və ya "geo-məhdudiyyətləri keç" tipli kommersiya VPN xidməti DEYİL.**

Bu, aşağıdakılar üçün **şəxsi şəbəkə infrastruktur alətidir**:
- ✅ Serverlər arası təhlükəsiz əlaqə
- ✅ Daxili xidmətlərə uzaqdan giriş
- ✅ Paylanmış infrastrukturu birləşdirmək
- ✅ Etibarlı şəxsi şəbəkələr qurmaq

**Trafik yönləndirməsi:**
- **Defolt — Split Tunnel:** yalnız VPN şəbəkələrinə (məs. `10.x.x.x`) gedən trafik tuneldən keçir; adi internet trafikiniz birbaşa öz provayderinizdən gedir.
- **İstəyə görə — Full Tunnel:** istədiyiniz node üçün paneldə tam tuneli açsanız, onun bütün internet trafiki sizin serveriniz üzərindən çıxır (DNS də tuneldən keçir).

---

## 🎯 NovusGate Hansı Problemi Həll Edir?

**Ssenari:** Bir yerdə serveriniz var (cloud, ev, ofis), amma:
- ❌ Ona qoşulmaq üçün statik IP-niz yoxdur
- ❌ Serverin portlarını birbaşa internetə açmaq istəmirsiniz
- ❌ NAT/Firewall birbaşa əlaqəni mümkünsüz edir

**NovusGate ilə həll:**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Sizin Server  │     │  NovusGate Hub  │     │ Sizin Kompüter  │
│ (Statik IP yox) │     │   (Cloud VPS)   │     │   (Ev/Ofis)     │
│                 │     │                 │     │                 │
│   10.10.10.3    │────▶│   10.10.10.1    │◀────│   10.10.10.4    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                     ▲                     │
         └──────── Hər ikisi Hub-a qoşulur ─────────┘
```

Hər iki cihaz NovusGate-ə qoşulduqdan sonra:
- ✅ Onlar bir-birini **eyni lokal şəbəkədə** kimi görür
- ✅ Serveriniz `10.10.10.3` olur — həmişə əlçatan
- ✅ Kompüteriniz `10.10.10.4` olur — SSH, RDP və ya istənilən xidmətə qoşula bilər
- ✅ Port yönləndirmə və statik IP lazım deyil
- ✅ NAT və firewall arxasında da işləyir

(Hub şəbəkənin ilk ünvanını götürür, ikinci ünvan ehtiyatda saxlanılır; cihazlar üçüncüdən başlayır.)

**Real nümunə:**
```bash
# Kompüterinizdən (10.10.10.4) serverə qoşulun:
ssh user@10.10.10.3

# Serverdə işləyən veb xidmətə daxil olun:
curl http://10.10.10.3:8080
```

---

## ✨ Niyə NovusGate?

Bu gün mövcud olan şəxsi şəbəkə həllərinin çoxu ya:
- ❌ "Qara qutu" kimi işləyən SaaS həlləridir
- ❌ Böyük miqyasda idarə etmək çətindir
- ❌ Kiçik komandalar üçün həddən artıq mürəkkəbdir
- ❌ Ya da öz serverində qurmaq (self-host) çox ağrılıdır

**NovusGate fərqli olmaq üçün yaradılıb:** rahatlıqdan öncə sahiblik, mürəkkəblikdən öncə sadəlik, mücərrədlikdən öncə şəffaflıq.

Onu siz işlədirsiniz. Siz idarə edirsiniz. Sizin şəbəkəniz — sizin qaydalarınız.

---

## 🚀 Əsas Xüsusiyyətlər

**Şəbəkə və cihazlar**
- **Çoxlu şəbəkə** — hər birinin öz WireGuard interfeysi (wg0, wg1…), subnet-i və UDP portu var.
- **Cihaz (node) idarəsi** — mobil üçün QR kod, desktop üçün `.conf`, Linux üçün bir sətirlik quraşdırma skripti (birdəfəlik, 15 dəqiqəlik token ilə). Giriş müddəti (expiry) qoyula bilər.
- **Full tunnel** — seçilmiş node-un bütün internet trafiki hub üzərindən.
- **Şəbəkə üzrə klient DNS** — cihaz konfiqlərinə yazılan DNS serverləri.
- **Topologiya xəritəsi**, şəbəkə detalları və hər node üçün **trafik tarixçəsi**.

**Firewall və nəzarət**
- **VPN qaydaları** — şəbəkələr, node-lar, qruplar və IP-lər arasında icazə/blok, protokol və port ilə, prioritet sırası ilə; **şəbəkə siyasətləri matrisi** kimin kimə çata bildiyini göstərir.
- **Node qrupları** — qaydaları və limitləri bir neçə node-a birlikdə tətbiq etmək üçün.
- **Host firewall** — port açmaq, IP bloklamaq/icazə vermək; idarə portları (3007, 5432, 8080, 8443) həmişə yalnız VPN-dən əlçatandır.
- **nftables mühərriki** (istəyə görə, aşağıya baxın) — Advanced tab (servislər, IP qaydaları, port yönləndirmə), dəyişikliklərin 60 saniyəlik təsdiqi ilə avtomatik geri qaytarma, **Live** (sayğaclar, conntrack) və **History** (dəyişiklik tarixçəsi, bərpa).
- **Limit profilləri** (nftables mühərriki ilə) — sürət limiti, eyni anda bağlantı limiti, vaxt cədvəli və **aylıq trafik kvotası** (blok və ya yavaşlatma, 80%/100% bildirişi).
- **Fail2Ban** — SSH qoruması, jail ayarları, ağ siyahı, əl ilə və daimi ban, ban tarixçəsi, loglar.

**İdarə və təhlükəsizlik**
- **Rollar** — Admin, Operator, İzləyici (viewer); hər rol yalnız icazəli işləri görür.
- **Sessiyalar** — giriş 24 saat keçərlidir; aktiv sessiyalara baxmaq və bitirmək olar; səhv parol cəhdləri məhdudlaşdırılır.
- **Audit jurnalı** — API ilə edilən dəyişikliklər və giriş cəhdləri.
- **Server səhifəsi** (yalnız admin, parol yenidən soruşulur) — servislər (docker, fail2ban, WireGuard), host şəbəkəsi, kernel parametrləri (90 saniyə ərzində saxlanmasa geri qayıdır), host adı, saat qurşağı/NTP, paket yeniləmələri və reboot.
- **Ehtiyat nüsxələr** (backup) və **Telegram bildirişləri**.
- **Panel iki dildə** (Azərbaycan / English) və **hər sahənin yanında "?"** — sahənin nə olduğunu, kimə lazım olduğunu və dəyişdirəndə nə olacağını izah edir.

**NovusGate Center**
- SSH ilə serverə **quraşdırma, yeniləmə** (ehtiyat nüsxə + xətada avtomatik geri qaytarma), reinstall, uninstall, **Join VPN** (başqa serveri node kimi qoşmaq), veb terminal, server monitorinqi və iş logları.

---

## 📡 VPN Tipi

**NovusGate client əsaslı uzaqdan giriş VPN-dir (Remote Access VPN).**

| VPN Tipi | NovusGate? | Təsvir |
|----------|------------|--------|
| ☁️ Cloud VPN | ⚠️ | AWS/Azure VPN Gateway kimi idarə olunan xidmət deyil; istənilən cloud və ya yerli serverdə qurulur |
| 🔐 IPsec VPN | ❌ | IPsec əvəzinə WireGuard işlədir |
| 🌐 SSL VPN | ❌ | Brauzer əsaslı deyil, WireGuard client lazımdır |
| 💻 **Client əsaslı VPN** | ✅ | WireGuard client proqramı ilə |
| 🏢 Site-to-Site VPN | ⚠️ | Linux serveri node kimi qoşmaqla mümkündür |
| 📡 **Uzaqdan Giriş VPN** | ✅ | Əsas istifadə halı |

- **Protokol:** WireGuard · **Arxitektura:** Hub-and-Spoke · **Tunel:** defolt split, istəyə görə full
- **Client-lər:** mobil (QR), desktop (.conf), Linux (skript)

---

## 👥 NovusGate Kimlər Üçündür?

- **Sistem adminləri** — serverlər və məlumat mərkəzləri arasında təhlükəsiz giriş üçün
- **DevOps mühəndisləri** — infrastrukturu müxtəlif mühitlər arasında birləşdirmək üçün
- **Proqramçılar** — daxili və ya self-hosted platformalar üçün
- **Məxfiliyə önəm verənlər** — öz VPN quruluşuna tam nəzarət üçün

---

## 🧠 Necə İşləyir? (Qısa)

1. **Mərkəzi server (hub)** idarəetmə rolunu oynayır (control plane + panel + PostgreSQL, Docker-də).
2. Öz subnet-i (məs. `10.20.0.0/24`) olan **ayrı şəbəkələr** yaradırsınız.
3. Cihazlar üçün konfiq yaradılır (QR, `.conf` və ya Linux skripti).
4. WireGuard tunelləri qurulur; trafik hub üzərindən, firewall qaydalarına görə yönləndirilir.

---

## 📂 Sistem Memarlığı

```
+-------------------------------------------------------------+
|                     NovusGate Server (hub)                  |
|  +-------------+  +-------------+  +-------------+          |
|  |  Şəbəkə 1   |  |  Şəbəkə 2   |  |  Şəbəkə N   |          |
|  |  wg0:51820  |  |  wg1:51821  |  |  wgN:518XX  |          |
|  | 10.99.0.0/24|  | 10.20.0.0/24|  | 10.XX.0.0/24|          |
|  +------+------+  +------+------+  +------+------+          |
|         |                |                |                 |
|  +------+----------------+----------------+------+          |
|  |  Control plane (Go, REST API) · PostgreSQL    |          |
|  |  Panel (React, nginx, HTTPS :3007)            |          |
|  +-----------------------------------------------+          |
+-------------------------------------------------------------+
                            |
              +-------------+-------------+
              |             |             |
         +----+----+   +----+----+   +----+----+
         | Telefon |   |Noutbuk  |   | Server  |
         +---------+   +---------+   +---------+
```

| Hissə | Qovluq | Təlimatlar |
|-------|--------|-----------|
| **Server (backend)** — Go; WireGuard, firewall, PostgreSQL, REST API | `./server` | [Developer](./server/DEVELOPER_GUIDE_AZ.md) · [User](./server/USER_GUIDE_AZ.md) |
| **Veb panel (frontend)** — React, TypeScript, Tailwind | `./web` | [Developer](./web/DEVELOPER_GUIDE_AZ.md) |
| **NovusGate Center** — SSH ilə quraşdırma və idarə, Node.js | `./NovusGate Center` | [Developer](./NovusGate%20Center/DEVELOPER_GUIDE_AZ.md) · [User](./NovusGate%20Center/USER_GUIDE_AZ.md) |

Texniki sənədlər: [`docs/`](./docs) (API, data modeli, təhlükəsizlik, deployment, runbook-lar).

---

## ⚡ Tez Başlanğıc

### Tələblər

**Öz kompüterinizdə (Center üçün):**
- Docker və Docker Compose

**Server (hub):**
- **Ubuntu 22.04 və ya daha yeni** (24.04, 26.04 yoxlanılıb) və ya **Debian 12 və ya daha yeni** (13 yoxlanılıb)
- x86_64 və ya aarch64; ən azı 1 GB RAM (2 GB tövsiyə olunur), 3 GB boş disk
- Root və ya parolsuz `sudo` ilə SSH girişi
- İnternetdən açıq olmalı portlar: **22/tcp** (SSH) və **51820/udp** (hər yeni şəbəkə üçün növbəti port: 51821, 51822…)
- 3007 (panel), 5432 (DB), 8080 (API), 8443 portlarını internetə **açmayın** — NovusGate onları özü yalnız VPN-ə açır.

Center quraşdırmadan əvvəl serveri yoxlayır (OS versiyası, CPU, RAM, disk, portlar) və uyğun deyilsə dayanır.

---

### Quraşdırma (addım-addım)

#### 1. Repozitoriyanı klonlayın
```bash
git clone https://github.com/Ali7Zeynalli/NovusGate.git
cd NovusGate
```

#### 2. NovusGate Center-i başladın
```bash
cd "NovusGate Center"
docker compose up -d --build
```

#### 3. Center-i açın
Brauzerdə: `http://localhost:3017`

#### 4. Serveri əlavə edin
| Sahə | Təsvir |
|------|--------|
| **Server Name** | İstədiyiniz ad |
| **Host** | Serverin IP ünvanı (məs. `203.0.113.50`) |
| **SSH Port** | Defolt `22` |
| **Username** | `root` və ya parolsuz `sudo`-su olan istifadəçi |
| **Password / Private Key** | SSH parolu və ya PEM açarı (passphrase ilə də olar) |

#### 5. Quraşdırma parametrləri
| Parametr | Təsvir |
|----------|--------|
| **Admin Username** | Panelin ilk admin istifadəçisi (defolt `admin`) |
| **Admin Password** | Boş buraxsanız təsadüfi parol yaradılır |
| **Admin VPN Gateway IP** | Hub-ın admin VPN-dəki ünvanı (defolt `10.99.0.1`, şəbəkə `10.99.0.0/24`) |
| **Database Name / User / Password** | PostgreSQL üçün; parol boşdursa təsadüfi yaradılır |

Hər sahənin yanındakı **"?"** onun nə etdiyini izah edir.

#### 6. Install
Center: sistemi yeniləyir, Docker, WireGuard və Fail2Ban quraşdırır, NovusGate fayllarını `/opt/NovusGate`-ə yükləyir, gizli açarları (DB parolu, API key, master key) yaradır, konteynerləri qurub başladır və **admin VPN**-i (`wg0`) yaradır.

#### 7. Admin VPN konfiqini götürün
Install bitəndə Center **admin VPN konfiqurasiyasını** göstərir: **📥 Download admin-vpn.conf**. Konfiq serverdə də saxlanılır: `/opt/NovusGate/admin-vpn.conf`.

#### 8. VPN-ə qoşulun
1. WireGuard client-i quraşdırın (Windows, macOS, Linux, Android, iOS).
2. `admin-vpn.conf`-u import edin və aktivləşdirin.
3. Sizin VPN ünvanınız `10.99.0.2` olacaq; `ping 10.99.0.1` cavab verməlidir.

#### 9. Panelə daxil olun
```
https://10.99.0.1:3007
```
(Gateway IP-ni dəyişmisinizsə, o IP-ni yazın.)

- **`https://`** yazın — `http://` işləmir.
- Brauzer sertifikat xəbərdarlığı göstərəcək (panel öz imzalı sertifikat işlədir): **Advanced → Proceed / Davam et**.
- **İstifadəçi adı və parol:** Center-də serveri seçin → **Server Credentials** (istənilən vaxt yenidən baxmaq olar), və ya install log-unun sonunda `ADMIN USER` / `ADMIN PASS`.

🎉 Hazırdır.

#### Panel açılmırsa
| Əlamət | Nə etməli |
|--------|-----------|
| Səhifə açılmır | WireGuard-da "Latest handshake" yoxlayın; `ping 10.99.0.1` |
| Server public IP-si ilə açırsınız | İşləməz: panel yalnız VPN-dən açılır |
| Parol qəbul olunmur | 15 dəqiqədə 10 səhv cəhddən sonra müvəqqəti blok; gözləyin və parolu Center → Server Credentials-dən götürün |

Serverdə yoxlama:
```bash
docker ps --format '{{.Names}} {{.Status}}'
sudo wg show wg0 | head -12
curl -sk -o /dev/null -w '%{http_code}\n' https://10.99.0.1:3007
```

---

### Quraşdırmadan sonra
- Yeni VPN şəbəkələri yaradın, cihaz əlavə edin (QR, `.conf`, Linux skripti).
- **Parametrlər → İstifadəçilər**: hər kəsə lazım olan rolu verin (Admin / Operator / İzləyici).
- Telegram bildirişlərini və ehtiyat nüsxələri qurun.
- Başqa Linux serveri node kimi qoşmaq üçün: panel → Nodes → Connect → Linux → install script; sonra Center → **Join VPN** (hub-ın özündə işləmir — orada hub-ın `wg0`-ını əvəz edərdi).

### nftables firewall mühərriki (limitlər, kvota, Advanced tab üçün)
Quraşdırma defolt olaraq **iptables** rejimində işləyir. **Limit profilləri, trafik kvotası, Advanced tab (port yönləndirmə və s.), Live və History** üçün nftables mühərrikini açmaq lazımdır. Addımlar, yoxlamalar və geri qayıdış: [`docs/runbooks/p3b2-firewall-cutover.md`](./docs/runbooks/p3b2-firewall-cutover.md). Qısaca: Center → Update → `server/deployments/docker/.env`-ə `FIREWALL_ENGINE=nft` → `docker compose up -d control-plane` → Center → Update bir daha.

### Yeniləmə
Center → **Update**: kodu yeniləyir, `.env`, verilənlər bazası və VPN konfiqləri saxlanılır, əvvəlcə ehtiyat nüsxə alınır (`/var/backups/novusgate/`), uğursuz olsa əvvəlki versiya avtomatik bərpa olunur. Verilənlər bazası miqrasiyaları control plane başlayanda öz-özünə tətbiq olunur.

**Köhnə versiyadan yeniləyənlər üçün:** rollar əvvəl yox idi, ona görə mövcud istifadəçilərin hamısı **Admin** olur — yeniləmədən sonra Parametrlər → İstifadəçilər-də rolları yoxlayın.

---

### NovusGate Center arxada nə edir?
1. **Yoxlama (preflight):** OS, CPU, RAM, disk, portlar.
2. **Paketlər:** `apt-get update`, Docker (get.docker.com), WireGuard, Fail2Ban.
3. **Fayllar:** `/opt/NovusGate`; admin VPN konfiqi `/opt/NovusGate/admin-vpn.conf`.
4. **Təhlükəsizlik:** DB parolu, API key, master key (node açarlarını şifrələyir) yaradılır və `server/deployments/docker/.env`-də yalnız root üçün saxlanılır; SSH üçün Fail2Ban jail-i (3 səhv cəhd = 1 saat ban); `wg0` admin VPN.
5. **Xidmətlər:** `docker compose up -d` — PostgreSQL, control plane, panel.

---

### Lokal inkişaf / manual işə salma
```bash
cd server/deployments/docker
cp .env.example .env     # ən azı ADMIN_PASSWORD, API_KEY və MASTER_KEY (openssl rand -hex 32) təyin edin
docker compose up -d --build
```
Bu PostgreSQL-i, control plane-i (API, port 8080) və paneli (port 3007) başladır. Panel: `https://localhost:3007`.

> **Qeyd:** tam VPN funksionallığı üçün WireGuard dəstəkli Linux lazımdır. Windows/macOS-da UI və API işləyir, VPN funksiyaları məhdud ola bilər.

Manual production quraşdırması: 👉 **[Server İstifadəçi Təlimatı](./server/USER_GUIDE_AZ.md)**

---

## 🌐 Şəbəkə İdarəsi

| Xüsusiyyət | Təsvir |
|------------|--------|
| **Ayrı subnet-lər** | Hər şəbəkənin öz CIDR-i var (məs. 10.10.0.0/24, 10.20.0.0/24); üst-üstə düşə bilməz |
| **Öz interfeysi** | Avtomatik təyin olunur: wg0, wg1, wg2… |
| **Öz portu** | Hər şəbəkə növbəti boş UDP portunda dinləyir (51820, 51821…) |
| **Klient DNS** | Şəbəkənin cihazlarının işlədəcəyi DNS serverləri (ən çox 3 IPv4) |

**Şəbəkə yaratmaq:** Panel → **Şəbəkələr** → yeni şəbəkə → ad və CIDR (məs. `10.50.0.0/24`). İnterfeys və port avtomatik təyin olunur; o portu (UDP) internetə açın.

---

## 🛡️ Təhlükəsizlik

* Panel, API və DB **yalnız VPN-dən** əlçatandır (3007, 5432, 8080, 8443 internetə bağlıdır).
* API açarı brauzerə heç vaxt düşmür: panelin nginx-i onu sorğuya özü əlavə edir.
* Giriş sessiyası 24 saat keçərlidir; səhv parol cəhdləri məhdudlaşdırılır; rollar hər sorğuda yoxlanılır.
* Server səhifəsindəki dəyişikliklər üçün parol **yenidən** soruşulur (5 dəqiqəlik).
* Node private açarları verilənlər bazasında master key ilə şifrələnmiş saxlanılır.
* Hər API dəyişikliyi audit jurnalına yazılır.
* **Fail2Ban** SSH-ı qoruyur (3 səhv cəhd = 1 saat ban).
* Quraşdırmanın sonunda göstərilən giriş məlumatlarını təhlükəsiz yerdə saxlayın.

---

## 📊 Server Monitorinqi

Əsas paneldə real vaxtda: **CPU**, **RAM**, **disk** istifadəsi və **uptime**; şəbəkə və node statistikaları, node-ların onlayn/oflayn vəziyyəti.

---

## 🔒 Fail2Ban

| Xüsusiyyət | Təsvir |
|------------|--------|
| **Jail statusu və ayarları** | bantime, findtime, maxretry |
| **Ban edilmiş IP-lər** | Hər jail üzrə; bir kliklə ban-dan çıxarma |
| **Əl ilə və daimi ban** | IP-ni əl ilə ban etmək; daimi ban firewall-da saxlanılır |
| **Ağ siyahı** | Heç vaxt ban edilməyəcək IP/CIDR-lər |
| **Tarixçə və loglar** | Ban tarixçəsi, filtr ilə loglar |

Paneldə **Fail2Ban** səhifəsi.

---

## 🔥 Firewall

### Host firewall
| Xüsusiyyət | Təsvir |
|------------|--------|
| **Açıq portlar** | Serverin portlarını açmaq və bağlamaq |
| **IP blok / icazə** | IP və ya CIDR; idarə portları heç vaxt internetə açılmır |
| **Qorunan portlar** | SSH, WireGuard və idarə portları təsadüfi bağlanmadan qorunur |
| **Export / Reset** | Qaydaları yükləmək, defolta qaytarmaq |
| **Advanced, Live, History** | nftables mühərriki ilə (yuxarıya baxın): servislər, IP qaydaları, port yönləndirmə, 60 saniyəlik təsdiq, canlı sayğaclar, dəyişiklik tarixçəsi və bərpa |

### VPN firewall (şəbəkələr arası qaydalar)
| Xüsusiyyət | Təsvir |
|------------|--------|
| **Mənbə / hədəf** | Şəbəkə, node, qrup və ya xüsusi IP |
| **Protokol və port** | TCP, UDP, ICMP və ya hamısı; port, siyahı və ya aralıq |
| **Prioritet** | Kiçik rəqəm əvvəl; ilk uyğun gələn qayda qərar verir |
| **Siyasət matrisi** | Hansı şəbəkənin hansına çata bildiyini və səbəbini göstərir |
| **Avtomatik AllowedIPs** | Cihaz konfiqləri icazə verilmiş şəbəkələri özü əhatə edir |

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│ Mənbə Node  │ ──► │   VPN Server    │ ──► │ Hədəf Node  │
│ (10.10.0.3) │     │  VPN qaydaları  │     │ (10.20.0.5) │
└─────────────┘     └─────────────────┘     └─────────────┘
```

Bütün VPN trafiki hub üzərindən keçir; VPN qaydaları hansı trafikin şəbəkələr arasında keçə biləcəyini müəyyən edir.

**Nümunələr:** ofis şəbəkəsinə admin şəbəkəsinə giriş vermək, development-in production-a girişini bağlamaq, yalnız HTTP/HTTPS-ə icazə vermək, qonaq şəbəkəsini izolyasiya etmək.

---

## 📸 Ekran Görüntüləri

### Veb Panel
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <img src="web/public/photo/web/0.png" alt="Web 0" width="45%">
  <img src="web/public/photo/web/1.png" alt="Web 1" width="45%">
  <img src="web/public/photo/web/2.png" alt="Web 2" width="45%">
  <img src="web/public/photo/web/3.png" alt="Web 3" width="45%">
  <img src="web/public/photo/web/4.png" alt="Web 4" width="45%">
  <img src="web/public/photo/web/5.png" alt="Web 5" width="45%">
  <img src="web/public/photo/web/6.png" alt="Web 6" width="45%">
  <img src="web/public/photo/web/7.png" alt="Web 7" width="45%">
  <img src="web/public/photo/web/8.png" alt="Web 8" width="45%">
  <img src="web/public/photo/web/9.png" alt="Web 9" width="45%">
  <img src="web/public/photo/web/10.png" alt="Web 10" width="45%">
  <img src="web/public/photo/web/11.png" alt="Web 11" width="45%">
  <img src="web/public/photo/web/12.png" alt="Web 12" width="45%">
</div>

### NovusGate Center
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <img src="web/public/photo/installer/0.png" alt="Center 0" width="45%">
  <img src="web/public/photo/installer/1.png" alt="Center 1" width="45%">
  <img src="web/public/photo/installer/2.png" alt="Center 2" width="45%">
  <img src="web/public/photo/installer/3.png" alt="Center 3" width="45%">
  <img src="web/public/photo/installer/4.png" alt="Center 4" width="45%">
</div>

> Qeyd: ekran görüntüləri əvvəlki versiyadandır; yeni səhifələr (Qruplar, Limitlər, Server, Audit və s.) onlarda yoxdur.

---

## 🤝 Töhfə Vermək

Töhfələrinizi gözləyirik ❤️ Xəta hesabatları, yeni funksiya təklifləri və Pull Request-lər yüksək qiymətləndirilir. Töhfə verməzdən əvvəl **Developer təlimatlarını** oxuyun.

---

## ⭐ Layihəyə Dəstək

* ⭐ Repozitoriyaya ulduz verin
* 🐛 Xətalar barədə məlumat verin (Issues)
* 💡 Yeni ideyalar təklif edin
* 📣 Başqaları ilə paylaşın

---

## 🤝 Professional Dəstək / Enterprise Support

> **Quraşdırma çətin gəlir?** Biz kömək edə bilərik!

### Ödənişli xidmətlər
| Xidmət | Təsvir |
|--------|--------|
| 🛠️ **Tam quraşdırma** | NovusGate-in sizin infrastrukturda tam quraşdırılması |
| 🔧 **Server konfiqurasiyası** | Linux, Docker, firewall və təhlükəsizlik |
| 📞 **Texniki dəstək** | Problem həlli və davamlı dəstək |
| 📚 **Təlim** | Komandanız üçün NovusGate təlimi |

> 💰 **Qiymət** işin həcminə və mürəkkəbliyinə görə fərdi hesablanır. Pulsuz konsultasiya üçün əlaqə saxlayın.

### Əlaqə
📧 **Email**: Ali.Z.Zeynalli@gmail.com  
💼 **LinkedIn**: [linkedin.com/in/ali7zeynalli](https://linkedin.com/in/ali7zeynalli)  
📱 **Telefon**: +49 152 2209 4631 (whatsapp)

> 💼 Enterprise müştərilər üçün SLA ilə dəstək mövcuddur.

### 🌍 Dəstək dilləri
| Dil | Language |
|-----|----------|
| 🇦🇿 Azərbaycan | Azerbaijani |
| 🇬🇧 İngilis | English |
| 🇩🇪 Alman | German |
| 🇷🇺 Rus | Russian |
| 🇹🇷 Türk | Turkish |

---

## 📄 Lisenziya

Bu layihə **Apache License 2.0** altında lisenziyalanıb — ətraflı: [LICENSE](LICENSE).

**© 2025 Əli Zeynallı**

Apache 2.0 sizə imkan verir:
- ✅ Proqramı istənilən məqsəd üçün istifadə etmək (kommersiya daxil)
- ✅ Proqramı dəyişdirmək və paylamaq
- ✅ Töhfə edənlərin patent hüquqlarından istifadə etmək

Sizdən tələb olunur:
- 📋 Orijinal müəllif hüququ qeydini saxlamaq
- 📋 LICENSE və NOTICE fayllarını daxil etmək
- 📋 Edilən əhəmiyyətli dəyişiklikləri qeyd etmək
- 📋 Orijinal müəllifə istinad etmək

> 📜 Attribution tələbləri üçün [NOTICE](NOTICE) faylına baxın.

---

**[Ali Zeynalli](https://github.com/Ali7Zeynalli) tərəfindən hazırlanıb**  
*Project NovusGate*
