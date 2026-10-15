# NovusGate Center - İstifadəçi Təlimatı

## Giriş

NovusGate Center, NovusGate VPN serverlərinin yerləşdirilməsi və idarə edilməsi üçün veb əsaslı idarəetmə panelidir. Sadə bir paneldən VPN infrastrukturunuzu quraşdıra, yeniləyə və izləyə bilərsiniz.

## Sürətli Başlanğıc

### Tələblər

- **Hədəf Server:** Ubuntu 22.04 LTS və ya daha yeni (və ya Debian 12+)
- **Giriş:** Root SSH girişi (IP, istifadəçi adı, parol)
- **Resurslar:** Minimum 1GB RAM, 10GB disk sahəsi
- **Portlar:** 22 (SSH), 51820 (WireGuard), 8080 (API), 3007 (Dashboard)

### NovusGate Center-i Başlatmaq

**Variant 1: Docker (Tövsiyə olunur)**
```bash
cd "NovusGate Center"
docker-compose up -d
```

**Variant 2: Node.js**
```bash
cd "NovusGate Center"
npm install
node server.js
```

Panelə giriş: `http://localhost:3017`

## Panel İcmalı

```
┌─────────────────────────────────────────────────────────────┐
│  NovusGate                                                  │
├─────────────┬───────────────────────────────────────────────┤
│             │                                               │
│  SERVERLƏR  │   Server Paneli                               │
│             │                                               │
│  ● Prod     │   ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  ○ Dev      │   │ Status  │ │ Disk    │ │ Yaddaş  │        │
│             │   │   ✓     │ │ 45GB    │ │ 2.1GB   │        │
│             │   └─────────┘ └─────────┘ └─────────┘        │
│             │                                               │
│  + Yeni     │   [Quraşdır] [Yenilə] [Yenidən] [Sil]        │
│             │                                               │
│             │   Docker Konteynerləri                        │
│             │   ┌─────────────────────────────────────┐    │
│             │   │ NovusGate-control-plane  İşləyir    │    │
│             │   │ NovusGate-web            İşləyir    │    │
│             │   │ NovusGate-postgres       İşləyir    │    │
│             │   └─────────────────────────────────────┘    │
└─────────────┴───────────────────────────────────────────────┘
```

## Server Əlavə Etmək

1. Sol menyuda **+ Yeni Server** düyməsinə klikləyin
2. Məlumatları doldurun:
   - **Ad:** Dost ad (məsələn, "Production VPN")
   - **Host:** Server IP ünvanı
   - **Port:** SSH portu (default: 22)
   - **İstifadəçi adı:** Adətən `root`
   - **Parol:** Root parolu
3. **Əlavə et** düyməsinə klikləyin

## Quraşdırma

### Təmiz Quraşdırma

1. Sol menyudan serverinizi seçin
2. **📦 NovusGate Server Quraşdır** düyməsinə klikləyin
3. Quraşdırma seçimlərini konfiqurasiya edin:

| Seçim | Default | Təsvir |
|-------|---------|--------|
| Admin İstifadəçi Adı | `admin` | Panel giriş istifadəçi adı |
| Admin Parolu | avtomatik | Boş buraxsanız avtomatik yaradılır |
| Admin Şəbəkə IP | `10.99.0.1` | Admin girişi üçün VPN gateway IP |
| Verilənlər Bazası Adı | `NovusGate` | PostgreSQL verilənlər bazası |
| Verilənlər Bazası İstifadəçisi | `NovusGate` | PostgreSQL istifadəçi adı |
| Verilənlər Bazası Parolu | avtomatik | Boş buraxsanız avtomatik yaradılır |

4. **Quraşdırmanı Başlat 🚀** düyməsinə klikləyin
5. Canlı quraşdırma logunu izləyin
6. **VACİB:** Sonda göstərilən məlumatları yadda saxlayın!

### Quraşdırmadan Sonra

Quraşdırma tamamlandıqda görəcəksiniz:

```
==========================================
  QURAŞDIRMA TAMAMLANDI!
==========================================
Server IP: 64.225.108.60

------------------------------------------
  🔒 ADMİN VPN KONFİQURASİYASI (MÜTLƏQDİR)
------------------------------------------
Admin Paneli indi bu VPN arxasında GİZLƏDİLİB.
Panelə daxil olmaq üçün bu VPN-ə QOŞULMALISINIZ.

[Interface]
PrivateKey = ...
Address = 10.99.0.2/32
...

------------------------------------------
  TƏHLÜKƏSİZLİK AÇARLARI (BUNLARI SAXLAYIN!)
------------------------------------------
ADMIN USER:  admin
ADMIN PASS:  a1b2c3d4e5f6...
API_KEY:     f6e5d4c3b2a1...
------------------------------------------
```

**Qoşulmaq üçün addımlar:**
1. VPN konfiqurasiya faylını yükləyin (**📥 admin-vpn.conf Yüklə** düyməsinə klikləyin)
2. WireGuard tətbiqinə import edin
3. VPN-ə qoşulun
4. Panelə daxil olun: `https://10.99.0.1:3007`

## Əməliyyatlar

### 🚀 Yeniləmə (Ağıllı)

Serverinizi ən son versiyaya yeniləyir, bunları qoruyur:
- ✅ Verilənlər bazası və bütün məlumatlar
- ✅ İstifadəçi hesabları
- ✅ Konfiqurasiya faylları (.env)
- ✅ WireGuard açarları və peer-lər

**Ağıllı Aşkarlama:**
- Yalnız dəyişən konteynerləri yenidən qurur
- Dəyişməyən komponentləri atlayır (daha sürətli yeniləmə)
- Verilənlər bazası miqrasiyalarını avtomatik icra edir

### 🔄 Yenidən Quraşdırma

Server xarab olduqda, amma məlumatları saxlamaq istədikdə istifadə edin:
- Bütün konteynerləri dayandırır
- Sistem fayllarını silir (data/ qoruyur)
- Sıfırdan yenidən yerləşdirir
- Konfiqurasiyanı bərpa edir

**⚠️ Xəbərdarlıq:** Bu pozucu əməliyyatdır - yenidən quraşdırma zamanı xidmətlər oflayn olacaq.

### 🗄️ Yalnız Verilənlər Bazası Miqrasiyası

Fayllara və ya konteynerlərə toxunmadan verilənlər bazası miqrasiyalarını icra edir:
- Sxem yeniləmələri üçün təhlükəsiz
- Dayanma müddəti yoxdur
- Bütün məlumatları qoruyur

### 🗑️ Silmək

**⚠️ TƏHLÜKƏ: Bu hər şeyi həmişəlik silir!**
- Bütün konteynerləri dayandırır və silir
- Bütün məlumatları və konfiqurasiyanı silir
- WireGuard interfeyslərini silir
- Firewall qaydalarını sıfırlayır

## Docker İdarəetməsi

### Konteyner İdarəsi

| Düymə | Əməliyyat |
|-------|-----------|
| ▶ | Konteyneri başlat |
| ⏹ | Konteyneri dayandır |
| 🔄 | Konteyneri yenidən başlat |
| 📋 | Canlı logları gör |
| 🗑️ | Konteyneri sil |

### Resurs Təmizliyi

- **Şəkilləri Təmizlə:** İstifadə olunmayan Docker şəkillərini sil
- **Volume-ları Təmizlə:** İstifadə olunmayan volume-ları sil
- **Hamısını Təmizlə:** Tam təmizlik (şəkillər, konteynerlər, volume-lar)

## Problemlərin Həlli

### Bağlantı Problemləri

| Xəta | Həll |
|------|------|
| "Server tapılmadı" | IP ünvanını və şəbəkə bağlantısını yoxlayın |
| "Autentifikasiya uğursuz" | Parolu yoxlayın; sshd_config-də `PermitRootLogin yes` olduğundan əmin olun |
| "Bağlantı vaxtı bitdi" | Firewall-u yoxlayın; port 22-nin açıq olduğundan əmin olun |

### Quraşdırma Problemləri

| Xəta | Həll |
|------|------|
| "İcra edilə bilmir: tələb olunan fayl tapılmadı" | Windows sətir sonu problemi - avtomatik düzəldilir |
| "ADMIN_PASSWORD tələb olunur" | Konfiqurasiya xətası - .env faylını yoxlayın |
| "Cihazda yer qalmayıb" | Disk sahəsini boşaldın; Docker prune işlədin |
| "Port artıq istifadə olunur" | Ziddiyyətli xidmətləri dayandırın və ya portları dəyişin |

### VPN Problemləri

| Xəta | Həll |
|------|------|
| VPN-ə qoşula bilmirəm | WireGuard konfiqurasiyasını yoxlayın; server IP-ni təsdiqləyin |
| Panel yüklənmir | VPN-in qoşulu olduğundan əmin olun; https://10.99.0.1:3007 yoxlayın |
| "Əl sıxma vaxtı bitdi" | Firewall UDP 51820 portunu bloklayır; iptables yoxlayın |

### Logları Görmək

1. Konteynerə klikləyin
2. 📋 (loglar düyməsi) klikləyin
3. Real vaxtda axan logları izləyin
4. Xəta mesajlarını yoxlayın

### Manual SSH Girişi

Əgər NovusGate Center qoşula bilmirsə, manual SSH ilə daxil olun:
```bash
ssh root@server-ip-unvani
cd /opt/NovusGate
docker-compose -f server/deployments/docker/docker-compose.yml logs -f
```

## Təhlükəsizlik Tövsiyələri

1. **Default parolları dəyişin** - Quraşdırmadan sonra admin parolunu dəyişin
2. **VPN konfiqurasiyasını təhlükəsiz saxlayın** - Bu fayl admin girişi verir
3. **Müntəzəm yeniləmələr** - Ağıllı Yeniləməni tez-tez istifadə edin
4. **Məlumatları yedəkləyin** - Böyük əməliyyatlardan əvvəl backup alın
5. **Logları izləyin** - Şübhəli fəaliyyət üçün müntəzəm yoxlayın

## Dəstək

- **Developer:** [Ali Zeynalli](https://github.com/Ali7Zeynalli)
- **Problemlər:** GitHub repozitoriyası
- **Sənədləşdirmə:** Texniki detallar üçün DEVELOPER_GUIDE_AZ.md-ə baxın
