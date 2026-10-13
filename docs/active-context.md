# Active Context

## Son Sessiya
- **Tarix:** 2026-10-13
- **Tapşırıq:** P1 Stabilizasiya (`docs/superpowers/plans/2026-10-13-p1-stabilization.md`)
- **Nəticə:** Task 1–10 commit-lənib (`cde27c5^..70216b9`, 13 commit: `cde27c5` `3fbfd54` `abdb7b5` `1bb5700` `1bbc4c2` `63cf05f` `2ddf730` `f7efd76` `7e1abd1` `b58853c` `dc582ea` `8e9a449` `70216b9`). Step 1 avtomatik testlər (Docker, `MSYS_NO_PATHCONV=1`):
  - Go — `docker run … golang:1.23 go test ./...` → `ok  github.com/novusgate/novusgate/internal/controlplane/api/rest 0.019s`; digər paketlər `[no test files]`; exit 0.
  - Center — `docker run … node:20-bookworm sh -c 'node --test test/*.test.js'` → `# tests 19` · `# pass 19` · `# fail 0`; exit 0.
  - Shell — `docker run … ubuntu:24.04 bash tests/setup-firewall_test.sh` → `OK`; exit 0.
  - Staging qəbulu icra olunmadı, səbəb: staging VM yoxdur — runbook istifadəçi tərəfindən icra olunmalıdır.
- **Davam:** P2 Backend nüvəsi planı yazılmalıdır (növbəti addım). İstifadəçinin tərəfində qalanlar:
  1. `.github/workflows/ci.yml` yaradılmalıdır — `.github` altına yazma icazə ayarlarına görə rədd edildi; YAML P1 planında Task 1 Step 5-dədir.
  2. `setup-firewall.sh` faylının LF ilə yenidən checkout-u rədd edildi — Task 5 (`63cf05f`) faylı artıq LF ilə yazdığı üçün məsələ bağlıdır.
  3. `docs/runbooks/p1-staging-acceptance.md` staging VM-də (təzə Ubuntu 24.04, root SSH) icra olunmalıdır; hər addımın əmr və çıxışı həmin faylın sonuna yazılmalıdır.

### Eyni sessiyanın davamı (2026-10-13): P3 firewall
- **Tapşırıq:** Linux firewall-unu (SSH-dan şəbəkəyə qədər) tam idarə etmək üçün analiz, dizayn və plan.
- **İstifadəçi qərarları:**
  - SSH public qalır;
  - port forwarding lazımdır;
  - full tunnel-in firewall hissəsi P3-də hazırlanır;
  - IPv6 IPv4 ilə eyni qaydaları alır.
- **Nəticə:** `docs/superpowers/specs/2026-10-13-p3-firewall-design.md` və `docs/superpowers/plans/2026-10-13-p3a-firewall-engine.md` commit-ləndi (`709d1a6`). Repo-da kod dəyişməyib. P3a kodu scratchpad-da prototip kimi yoxlanılıb:
  - `go vet`, `go build ./...` və testlər (`ok …/netctl/nft`, `…/controlplane/firewall`, `…/api/rest`) keçir;
  - yaradılan qaydalar nftables 1.0.2, 1.0.6 və 1.0.9-da `nft -c`-dən keçir;
  - kernel-də apply, snapshot və restore işləyir.
- **Aşkarlanan:** WSL docker shim-i argumentlərdəki `$`-ı genişləndirir, ona görə konteyner daxilində `$?` etibarsızdır. Test məntiqi `server/scripts/test-in-docker.sh` faylında olmalıdır.
- **Davam:** P3a planını icra etmək (icra üsulu istifadəçinin seçimidir), sonra P3b. PR üçün push-u istifadəçi edir.

## Son Dəyişikliklər
| Tarix | Dəyişiklik | Fayllar | Səbəb |
|---|---|---|---|
| 2026-10-13 | Close Port dəqiq uyğunluq | firewall_handlers.go, firewall_portmatch_test.go | A6 lockout · `abdb7b5` |
| 2026-10-13 | Startup-da peer bərpası, sync expired-i qaytarmır | peer_restore.go, handlers.go | A3, B11 · `1bb5700` |
| 2026-10-13 | Konteyner restart siyasəti | docker-compose.yml | A3 · `1bbc4c2` |
| 2026-10-13 | SSH port aşkarlanması, DROP sonda | setup-firewall.sh | A5 · `63cf05f` + `2ddf730` |
| 2026-10-13 | Center skriptləri moduldan çıxarıldı | lib/scripts.js, server.js | test oluna bilmə · `f7efd76` |
| 2026-10-13 | Reinstall DB/admin-vpn.conf saxlayır | lib/scripts.js | A1 · `7e1abd1` |
| 2026-10-13 | Install guard | lib/scripts.js, server.js | A2 · `b58853c` |
| 2026-10-13 | SSE xətası crash etmir | lib/sse.js, server.js | A4 · `dc582ea` + `8e9a449` |
| 2026-10-13 | Binary/konteyner adı, admin-vpn.conf | lib/scripts.js, server.js, index.html | B17–B19 · `70216b9` |
| 2026-10-13 | Shell skriptləri LF, Center test skripti | .gitattributes, package.json | LF üçün · `cde27c5` + `3fbfd54` |
| 2026-10-13 | Arxivdə lokal `server/data` göndərilmir | server.js, test/archive.test.js | final review: dev DB prod DB-ni əzə bilərdi · `d0e50d0` |
| 2026-10-13 | DB var, `.env` yoxdursa reinstall dayanır (exit 4) | lib/scripts.js, test/reinstall-db-guard.test.js | final review: yeni secret DB-ni kilidləyərdi · `e43fa22` |
| 2026-10-13 | Runbook: Update yolu və DB guard yoxlaması | docs/runbooks/p1-staging-acceptance.md | final review · `322ad1d` |
| 2026-10-13 | P3 firewall spec + P3a mühərrik planı | docs/superpowers/specs/2026-10-13-p3-firewall-design.md, docs/superpowers/plans/2026-10-13-p3a-firewall-engine.md | firewall-u tam idarə etmək · `709d1a6` |

**Final review sonrası testlər:** Center `# tests 24 · # pass 24 · # fail 0` (fix dalğasının implementer-i icra edib); Go və shell dəyişməyib (final reviewer təkrar icra etdi: yaşıl).

**P3/P7 planlarına ötürülənlər:** panel-dən xüsusi SSH portu bağlana bilər (`protectedPorts` yalnız 22) → P3; `unhandledRejection` handler-i gələcək asılmaları gizlədə bilər, reinstall catch-də SSH bağlantısı sızır → P7.
