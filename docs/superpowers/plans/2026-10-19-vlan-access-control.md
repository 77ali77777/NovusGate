# VLAN tipli icazə sistemi — plan (2026-10-19)

## Məqsəd (istifadəçinin sözləri ilə)
Hər şəbəkə ayrı "VLAN"-dır və default olaraq digərlərini görmür. İcazə üç səviyyədə verilir: şəbəkə ↔ şəbəkə, tək cihaz, qrup (müxtəlif şəbəkələrdən seçilmiş cihazlar). Hər icazənin istiqaməti var:
- **bir tərəfli** — A B-ni görür (A əlaqə başladır, cavablar qayıdır), B A-ya əlaqə başlada bilmir;
- **qarşılıqlı** — ikisi də bir-birinə əlaqə başladır.

## İndiki vəziyyət (kod)
| Var | Çatışmır |
|---|---|
| Qayda qaynağı/hədəfi: `network`, `node`, `group`, `custom`, `any` (`models.go:121-134`, `firewall_handlers.go:921`) | İstiqamət seçimi yoxdur — qarşılıqlı üçün iki qayda lazımdır |
| nftables rejimində şəbəkələr default ayrıdır, `ct established` cavabları buraxır | iptables rejimində şəbəkələr default **açıqdır** |
| Matris şəbəkə səviyyəsində kimin kimi gördüyünü göstərir | Cihaz/qrup səviyyəsində "kim kimi görür" yoxlayıcısı yoxdur |
| — | Cihaz konfiqi (`AllowedIPs`) qaydalardan asılıdır (`config_handlers.go:47-139`): qayda dəyişəndə konfiq yenidən yüklənməlidir; hədəf tərəfə qaynaq CIDR yazılmır → **cavab qayıtmır** |
| — | Admin VPN konfiqi Center-dən sabitdir (`install.sh:204`, `AllowedIPs = 10.99.0.0/24`) |

## Mərhələlər

### M1 — Marşrut qaydadan asılı olmasın, izolyasiya hər rejimdə (əsas)
- Cihaz konfiqi: `AllowedIPs` = **bütün VPN şəbəkələrinin CIDR-ləri** + qaydalardakı `custom` hədəflər; tam tuneldə `0.0.0.0/0`. İcazəni yalnız server verir.
- `nodes.config_routes` (migration 021 + rollback): cihaza verilən konfiqin marşrut izi. Hazırkı ilə fərqlidirsə panel cihazda "Konfiq köhnədir — yenidən yükləyin" göstərir (yeni şəbəkə yaradılanda və s.).
- iptables rejimində `NOVUSGATE-VPN` sonuna "fərqli wg interfeysləri arası DROP" (nftables-dəki `vpn default drop` ekvivalenti); eyni şəbəkə daxili trafik açıq qalır.
- **Davranış dəyişikliyi:** iptables rejimində qaydası olmayan şəbəkələr arası trafik kəsilir; mövcud cihazlar bir dəfə yeni konfiq yükləyir.
- Testlər: konfiq generatoru (split/tam, custom hədəf), iz müqayisəsi, iptables zənciri (fake runner), nft kompilyasiya dəyişmir; real serverdə iki şəbəkə + iki cihazla sınaq.

### M2 — İstiqamət və aydın qayda forması
- `vpn_firewall_rules.bidirectional BOOLEAN DEFAULT false` (migration 022 + rollback): qarşılıqlı qayda nft/iptables-də iki istiqamətə kompilyasiya olunur; matris və audit bunu göstərir.
- Forma: **Kim** (şəbəkə / cihaz / qrup / IP) → **Kimə** (şəbəkə / cihaz / qrup / IP / hamısı) → **Nə** (hər şey / protokol+port) → **İstiqamət** (bir tərəfli / qarşılıqlı) → **Qərar** (icazə / qadağa).
- Formanın altında adi dildə xülasə, məs.: *"Ofis-1-dəki Mühasibat qrupu Serverlər şəbəkəsindəki db-01-ə 5432/TCP ilə qoşula bilər; db-01 Mühasibata əlaqə başlada bilməz; cavablar avtomatik qayıdır."*
- Hər sahəyə "?" (az+en).

### M3 — "Kim kimi görür?" yoxlayıcısı
- API: iki tərəf (cihaz / şəbəkə / qrup) → nəticə (icazə / qismən / qadağa), həlledici qayda, istiqamət. Matrisin cihaz səviyyəsinə endirilmiş forması (eyni qiymətləndirmə kodu: `firewall/matrix.go`).
- Panel: Firewall → Şəbəkələr arası tabında iki seçici + nəticə kartı; matris xanasından açılır.

### M4 — Admin VPN eyni qaydada
- Center `install.sh` admin konfiqini M1 prinsipi ilə yazır.
- Panel: admin cihazı üçün "konfiqi yenidən yarat" (açarı serverdə olmayan köhnə admin konfiqi üçün yeni açar; köhnə konfiq işləməz olur — dialoq bunu deyir).
- Panelə giriş (3007) ayrıca qalır: yalnız Admin VPN-dən (dəyişmir).

## Sıra və qərarlar
- Sıra: M1 → M2 → M3 → M4. Hər mərhələ ayrıca commit, testlər əvvəl RED, real serverdə yoxlama.
- **Açıq qərar (istifadəçi):** iptables rejimi — M1-dəki default izolyasiya ilə saxlanılsın (tövsiyə), yoxsa nftables yeganə mühərrik olsun.
