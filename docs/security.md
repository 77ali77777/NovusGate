# Təhlükəsizlik

## Panel auth (P4a)
- **Sessiyalar:** hər login `sessions` cədvəlində bir sətir yaradır. Token (32 təsadüfi bayt, hex) yalnız client-ə qaytarılır. DB-də onun SHA-256 hash-i saxlanılır, ona görə DB oğurlansa belə tokenlər oxunmur.
- **Ömür:** login-dən 24 saat (`sessionTTL`, `server/internal/controlplane/api/rest/auth.go`). `last_used_at` dəqiqədə ən çox bir dəfə yenilənir və yalnız məlumat üçündür.
- **Ləğv:**
  - logout cari sessiyanı silir;
  - istifadəçi silinəndə bütün sessiyaları da silinir (`ON DELETE CASCADE`);
  - parol dəyişəndə həmin istifadəçinin digər sessiyaları silinir.
- **Vaxtı bitmiş sessiyalar** hər uğurlu login-də təmizlənir.
- **Parol dəyişmə** yalnız sessiya istifadəçisinin parolunu dəyişir. Əvvəl body-dəki `username` istənilən hesabı seçə bilirdi.
- **Login limiti:** IP üzrə 15 dəqiqədə 10 uğursuz cəhd, sonra 429. Sayğac yaddaşdadır. Panelin nginx-i arxasında IP `X-Real-IP`-dən götürülür, yalnız loopback-dən gələndə (P4b).
- **Auth-suz yollar:** yalnız `/health` və `/api/v1/auth/login`, dəqiq uyğunluqla.
- **`X-API-Key`:** `novusgate_API_KEY` təyin olunubsa, Bearer-dən əlavə tələb olunur. Panel üçün onu nginx əlavə edir (P4b).

## Məlum açıq məsələlər (P4b/P4c)
- **Node private key-ləri:** P4c-də həll olundu (aşağıya bax).
- **`install.sh` və `checkin`:** P4b-də həll olundu (aşağıya bax).
- **`web/.env`:** P4b-dən sonra build onu oxumur, amma fayl hələ git-dədir (aşağıya bax).

## Node enrollment və proxy (P4b)
- **Enrollment tokeni:** 32 təsadüfi bayt. DB-də (`enrollment_tokens`) yalnız SHA-256-sı saxlanılır. Bir node üçündür, 15 dəqiqə və bir dəfəlik keçərlidir. İşlənməsi bir `UPDATE … WHERE used_at IS NULL` əmri ilə olur, ona görə paralel iki checkin eyni tokeni işlədə bilmir.
- **Public port açılmır:** skript paneldən kopyalanır. Checkin WireGuard qalxandan sonra VPN üzərindən gedir (8080 yalnız `wg+` interfeyslərində açıqdır).
- **Checkin label filtri:** `wireguard_*` açarları node-dan qəbul olunmur.
- **Etibarlı proxy:** `X-Real-IP` yalnız loopback-dən (panelin nginx-i) gələn sorğuda nəzərə alınır. Başqa client bu başlıqla öz IP-sini seçə bilmir. Bu IP-dən istifadə edənlər: login limiti, firewall-un operatoru kilidləməyə qarşı qoruması və firewall audit log-u.
- **API açarı:** `X-API-Key`-i panelin nginx-i env-dən (`NOVUSGATE_API_KEY`) əlavə edir. Açar yalnız `[A-Za-z0-9._~-]` simvollarından ibarət olmalıdır, əks halda control-plane başlamır (nginx konfiqurasiyası sınmasın). Açar artıq JS bundle-a düşmür. `web/.dockerignore` `.env` fayllarını image-dən çıxarır.
- **İstifadəçinin qərarı:** `web/.env` hələ git-də izlənir. Əvvəlki bundle-lar açarı daşıyıb, ona görə açarı dəyişmək və faylı git-dən çıxarmaq tövsiyə olunur.

## Node private key-ləri və audit (P4c)
- **Saxlanma:** node-un WireGuard private key-i artıq `labels`-də deyil, `nodes.private_key_enc` sütunundadır.
  - **Format:** `v2:<base64(nonce|ciphertext)>`, AES-256-GCM ilə şifrələnir. Node-un ID-si AES-GCM-ə əlavə (autentifikasiya olunan) data kimi verilir, ona görə dəyər başqa node-un sətrinə köçürülsə açılmır.
  - **Köhnə format:** ilk P4c build-in yazdığı `v1:` dəyərləri (node-a bağlanmamış) hələ də açılır və növbəti startup-da `v2:` kimi yenidən şifrələnir.
  - **Master açar:** `NOVUSGATE_MASTER_KEY` (64 hex simvol, compose-da `.env`-dəki `MASTER_KEY`-dən).
  - **Açar yoxdursa:** dəyər `plain:` prefiksi ilə saxlanılır və server startup-da xəbərdarlıq verir. Açar sonradan təyin olunsa, növbəti startup bu dəyərləri şifrələyir.
  - **Açar səhvdirsə** (uzunluq və ya hex xətası): server başlamır.
  - **Açar dəyişib və ya silinibsə** (mövcud şifrələnmiş key-ləri aça bilmirsə): server startup-da xəta ilə dayanır.
- **API:**
  - node cavablarında key yoxdur;
  - `has_config` yalnız serverin key-i saxlayıb-saxlamadığını göstərir;
  - key yalnız `config`, `qrcode` və `install.sh` cavablarının içində çıxır (konfiqurasiyanın özüdür).
- **Startup miqrasiyası:** `serve` hər başlayanda köhnə `labels.wireguard_private_key` dəyərlərini sütuna köçürür və label-dən silir, hər node üçün bir SQL əmri ilə. Əməliyyat idempotentdir.
- **Master açarın itməsi:** şifrələnmiş key-lər açılmır. Həmin node-ların config-i yenidən yaradılmalıdır. Açarı `.env` ilə birlikdə yedəkləyin.
- **Audit:** `firewall_audit_log.user_id` dəyişikliyi edən panel istifadəçisidir (`ON DELETE SET NULL`). `user_ip` real client IP-sidir (`clientIP`).
- **Hələ şifrələnmir:** `networks.server_private_key` (spec-də yoxdur; JSON-da gizlidir). Növbəti addım kimi qeyd olunub.

## Sonrakı sərtləşdirmələr (təxirə salınmış məsələlərin bağlanması)
- **Login:**
  - parol dəyişməsi ilə digər sessiyaların ləğvi bir tranzaksiyada gedir;
  - mövcud olmayan istifadəçi adı da bcrypt-dən keçir, ona görə cavab vaxtı adın olub-olmadığını göstərmir;
  - limiter IPv6-nı `/64` üzrə sayır, ən çox 10000 açar saxlayır;
  - uğurlu login yalnız öz cəhdini silir, əvvəlki uğursuz cəhdlər sayılmağa davam edir.
- **Enrollment:**
  - token yalnız checkin qəbul ediləndən sonra işlənir, ona görə pis body tokeni yandırmır;
  - skript tokeni `ps`-də görünməyən 0600 icazəli faylla ötürür;
  - JSON-a yalnız təhlükəsiz simvollar düşür;
  - 401 alanda skript dərhal dayanır;
  - köhnə tokenlər yeni token yaradılanda təmizlənir.

## Final review düzəlişləri (2026-10-14)
- **Checkin:**
  - body autentifikasiyadan əvvəl 64 KiB ilə məhdudlaşdırılır;
  - token əvvəlcə yalnız yoxlanır və node yadda saxlanandan sonra işlənir, ona görə uğursuz yeniləmə tokeni yandırmır;
  - token yoxlaması mövcud olmayan node üçün də DB-də aparılır, ona görə cavab vaxtı node ID-lərini göstərmir.
- **Peer bərpası:** başqa peer yalnız node-un tam eyni `/32`-sini saxlayırsa, node əlavə olunmur. Exit gateway-in `0.0.0.0/0`-u və ya sayt subnet-i bunu bloklamır: WireGuard daha dəqiq prefiksi seçir.
- **Login limiti:** ən çox 10000 açar saxlanılır, doluda ən köhnəsi atılır. Çoxlu IPv6 `/64` idarə edən hücumçu (məsələn bütöv `/48`) öz sayğaclarını bu yolla sıfırlaya bilər. Bu, yaddaşı məhdudlaşdırmağın qəbul olunmuş qiymətidir.
- **HEAD `install.sh`:** enrollment tokeni yaratmır.

## Port və gizli faylların sərtləşdirilməsi (2026-10-14)
- **PostgreSQL yalnız loopback-dədir:** compose portu `127.0.0.1:5432:5432` kimi publish edir. Docker-in publish etdiyi port iptables `INPUT` qaydalarından keçmir (DNAT `FORWARD`-a gedir). Ona görə əvvəlki `5432:5432` iptables rejimində bazanı internetə açırdı.
  - Control-plane host şəbəkəsindədir və `localhost:5432` ilə qoşulur, onun üçün heç nə dəyişmir.
  - Admin VPN (wg0) üzərindən birbaşa DB-yə qoşulma artıq mümkün deyil. Lazım olsa SSH tuneli istifadə edin: `ssh -L 5432:127.0.0.1:5432 <server>`.
  - Qüvvəyə minməsi üçün: `docker compose up -d postgres`.
- **`.env` faylları git-də deyil:** `web/.env` və `NovusGate Center/.env` indeksdən çıxarıldı, `.gitignore`-lar `.env`-i (server: `deployments/docker/.env`) ignore edir. `web/.env` git tarixçəsində qalır, ona görə `API_KEY` dəyişdirilməlidir.

## Telegram bildirişləri (P8, 2026-10-15)
- Bot token DB-də node private key-ləri kimi `NOVUSGATE_MASTER_KEY` ilə möhürlənir. Möhürün konteksti ayrıdır, ona görə node açarı bu sütuna köçürülsə açılmır.
- Token API cavablarında, log-da və xəta mesajlarında görünmür. Telegram xətasında yalnız Telegram-ın `description` mətni qalır, URL (tokenlə birlikdə) atılır.
- Endpoint-lər panel sessiyası və ya API açarı tələb edir.
- Control-plane `api.telegram.org`-a çıxış edir (HTTPS). Mesajlarda node adları, şəbəkə adları və ban olunan IP-lər var; bunlar Telegram serverlərindən keçir.

## VPN qaydaları iptables rejimində (2026-10-15)
- **Əvvəl:** VPN qaydaları `iptables -A FORWARD` ilə əlavə olunurdu, yəni WireGuard `PostUp`-un `-A FORWARD -i wgX -j ACCEPT` sətirlərindən sonraya düşürdü. Ona görə drop və reject qaydaları **heç vaxt işləmirdi**.
- **İndi:**
  - qaydalar `NOVUSGATE-VPN` zəncirindədir və FORWARD-ın başından `-i wg+ -j NOVUSGATE-VPN` ilə çağırılır;
  - zəncirin ilk sətri `ESTABLISHED,RELATED -j RETURN`-dür, ona görə icazə verilmiş bağlantıların cavabları bloklanmır;
  - qaydalar priority sırası ilə yazılır.
- Paket testi ilə yoxlanıb (iki network namespace): köhnə üsulla drop qaydası keçirdi, yeni zəncirdə bloklayır.
- **Diqqət:** Update-dən sonra paneldə yaradılmış drop/reject VPN qaydaları ilk dəfə trafiki kəsməyə başlayır.
- Yeni qayda yaradılanda (əvvəl yalnız update və delete edirdi) bütün qaydalar yenidən sinxronlaşdırılır. Bu nft rejimində yeni qaydanın dərhal tətbiq olunmamasını da düzəldir.

## Center iş log-ları (2026-10-15)
- Hər uzun işin tam çıxışı `NovusGate Center/data/jobs/<server>/<vaxt>-<iş>.log`-da saxlanılır: install, update, reinstall, migrate, join-vpn, uninstall, prune.
- **İstifadəçi qərarı ilə çıxış maskalanmır və silinmir.** Install-ın çap etdiyi `ADMIN PASS`, `API_KEY` və `DB_PASSWORD` log-da açıq qalır.
- Qovluqlar 0700, fayllar 0600 icazə ilə yaradılır. `data/` git-ə düşmür (`.gitignore`) və install arxivinə daxil edilmir. Center konteynerində `./data` volume-dadır.
- `servers.json` kimi, bu qovluq da Center-in olduğu maşında sirr saxlayır.

## Panel rolları (P9a, 2026-10-15)
- Hər sessiya sorğusu `roleMiddleware`-dən keçir. Siyahıda olmayan dəyişiklik və ya GET avtomatik olaraq admin tələb edir (default-deny).
- Yalnız API açarı ilə giriş yoxdur: sessiya həmişə tələb olunur.
- Private key verən endpoint-lər (`config`, `qrcode`) və enrollment token yaradan `install.sh` viewer-ə bağlıdır. Backup yükləmə, debug, istifadəçilər və sessiyalar yalnız admin üçündür.
- Son admin rolunu itirə və ya silinə bilməz. Paralel sorğularda bu, sətir kilidi ilə qorunur.
- Son admin yoxlaması ID-ni UUID kimi normallaşdırır: böyük hərfli və ya `{...}` formalı ID ilə yeganə admini aşağı salmaq/silmək mümkün deyil (review düzəlişi).
- UI rola görə düymələri gizlədir və ya deaktiv edir (Settings, Nodes, Networks, Groups, VPN qaydaları, host firewall, Advanced, History, Fail2Ban), amma qərarı yalnız backend verir.

## Limit profilləri (P9b, 2026-10-15)
- Limitlər nft `forward` zəncirində `ct state established`-dən əvvəldədir: mövcud bağlantılara da tətbiq olunur. Hər tətbiq cədvəli əvəz edir və sayğac set-lərini boşaldır; bağlantı sayı hər paketdə götürülür, ona görə açıq bağlantılar növbəti paketləri ilə yenidən sayılır (real trafiklə yoxlanılıb). Sürət sayğacları isə tətbiqdən sonra dolu bucket ilə başlayır.
- Sürət policing ilə məhdudlaşdırılır (`limit rate over … burst max(rate/4, 64 KiB)`). Ölçülüb: 8 Mbit/s limit → 7.88, 4 Mbit/s → 3.90 (iperf3, ilk 2 s atılmaqla). TCP üçün policing shaping qədər hamar deyil.
- Vaxt cədvəli UTC-yə çevrilir. nft `meta hour`-u prosesin saat qurşağı ilə çevirir (ölçülüb), ona görə control-plane-in işlətdiyi hər nft, rollback timer-i (`systemd-run --setenv=TZ=UTC`) və boot unit-i (`Environment=TZ=UTC`) UTC ilə işləyir. Yay/qış vaxtı keçidində ruleset avtomatik yenidən qurulur.
- iptables rejimində limitlər **tətbiq olunmur**; panel bunu açıq yazır.

## Trafik kvotası (P9c, 2026-10-15)
- Kvotanı aşan node `block` rejimində `quota_v4` set-inə düşür: forward-da VPN trafiki hər iki istiqamətdə atılır, handshake (input) qalır. `throttle` rejimində node profilin "<id>:quota" surətinə keçir (`throttle_kbps`, digər limitlər saxlanılır).
- Blok istifadənin **cari** kvota ilə müqayisəsindən asılıdır: kvota artırılanda blok dərhal götürülür, azaldılanda qoyulur.
- Dövrün sonu (`period_end`) dövr başlayanda sabitlənir; sıfırlama günü və ya saat qurşağı dövr ortasında dəyişsə, yeni dəyər növbəti dövrdən tətbiq olunur. Dövr bitəndə engine o anda yenidən yüklənir (blok götürülür); tracker sayğacı ən gec 5 dəqiqə sonra sıfırlayır, nümunə gəlməsə və ya sampler xəta versə belə.
- Tracker yalnız oxuduğu sətir dəyişməyibsə yazır, ona görə paneldən edilən paralel "sıfırla" itmir.
- Məlum məhdudiyyətlər: control-plane dövr sərhədində işləməyibsə, son nümunədən sonrakı trafik yeni dövrə yazılır; WireGuard sayğacı sıfırlanıb əvvəlki dəyəri keçibsə, fərq az sayıla bilər (trafik tarixçəsindəki ilə eyni qayda).
- iptables rejimində kvota tətbiq olunmur (limitlər kimi).

## Audit jurnalı və Center log-ları (2026-10-15, review düzəlişləri)
- Rate limit-ə düşən login (429) audit-ə yazılmır: parol yoxlanmadan cavab verilir, yazılsaydı hər kəs cədvəli pulsuz böyüdə bilərdi. Audit yazıları 180 gün saxlanılır (6 saatdan bir təmizlənir).
- Center iş log-ları server silinəndə silinir (parolları ola bilər); silinmiş serverin log-u 404 verir. Log yazılmasa (disk dolu) iş davam edir.
- Məlum, dəyişməyən: Center auth-suz lokal alətdir (açıq CORS); log-larda parollar maskalanmır (istifadəçi qərarı).
