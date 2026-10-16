---
name: scripted-edit-pitfalls
description: "node -e string.replace corrupts files when the replacement has $ (e.g. regex `...$`); precedence bug once duplicated a file 50x"
metadata:
  node_type: memory
  type: feedback
  originSessionId: 43f59deb-fd0c-48be-9442-95a0aa4fec7c
  modified: 2026-10-16T14:32:53.395Z
---

Two file corruptions on 2026-10-15 came from ad-hoc node edit scripts, not from the tools:
1. `s.replace(a, b)` where `b` contained `` $` `` / `$'` / `$&` (a Go regex ending in `$` followed by a backtick) — JS treats those as substitution patterns and spliced the file prefix into validate.go.
2. `indexOf(x) + '</'+TAG+'>'.length` — string concatenation, slice(NaN) duplicated Fail2Ban.tsx ~50 times.

3. (2026-10-16) `perl -0pi -e 's|...\|\|...|X|'` — with `|` as delimiter, `\|\|` became an empty alternation, so the pattern matched at offset 0 and X was prepended to the file (Go: "expected 'package'"). Caught by `go vet`, fixed by removing the prefix.

**Why:** restoring needed the user (git checkout is denied, overwrites get blocked by auto mode).
**How to apply:** never use a regex metacharacter (`|`, `#` with /x) as the s/// delimiter when the pattern contains it; prefer the Edit tool for any multi-site code edit and check `git diff` right after; for edits containing `$` use the Edit tool, or `s.split(a).join(b)` / a replacer function `() => b`; parenthesize length arithmetic; dry-run scripted multi-site edits on a scratch copy and check line counts before touching the repo file. Related: [[wsl-docker-shim-dollar-expansion]].
