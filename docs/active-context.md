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
