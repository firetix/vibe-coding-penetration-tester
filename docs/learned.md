# Learned

## Learned Entries

### avoid-socket-setdefaulttimeout-in-concurrent-dns-91e3f7b9
- summary: Avoid socket.setdefaulttimeout in concurrent DNS enumeration; use dnspython resolver timeout/lifetime per-call instead.
- confidence: 0.60
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Avoid socket.setdefaulttimeout in concurrent DNS enumeration; use dnspython resolver timeout/lifetime per-call instead."

### fix-scope-bugs-by-defining-shared-lists-like-csr-df9d2590
- summary: Fix scope bugs by defining shared lists like csrf_indicators outside narrow branches and avoid bare except (use except Exception).
- confidence: 0.60
- domain: preference
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Fix scope bugs by defining shared lists like csrf_indicators outside narrow branches and avoid bare except (use except Exception)."

### use-dynamic-cli-provider-options-so-gemini-is-on-f28893c3
- summary: Use dynamic CLI provider options so Gemini is only offered when google.generativeai is installed; otherwise hide it to keep fresh installs working.
- confidence: 0.60
- domain: preference
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "Use dynamic CLI provider options so Gemini is only offered when google.generativeai is installed; otherwise hide it to keep fresh installs working."

### when-deploying-on-vercel-keep-requirements-txt-l-eceb070b
- summary: When deploying on Vercel, keep requirements.txt lean to avoid the 250MB unzipped serverless function limit; split heavyweight deps or make them optional.
- confidence: 0.60
- domain: preference
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "When deploying on Vercel, keep requirements.txt lean to avoid the 250MB unzipped serverless function limit; split heavyweight deps or make them optional."

### when-deploying-on-vercel-pin-python-via-python-v-2f9d33d7
- summary: When deploying on Vercel, pin Python via .python-version or pyproject.toml if you need a specific version instead of the default.
- confidence: 0.50
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "When deploying on Vercel, pin Python via .python-version or pyproject.toml if you need a specific version instead of the default."

### when-ruff-is-not-on-path-prefer-running-formatti-854edc16
- summary: When ruff is not on PATH, prefer running formatting/lint via `python -m ruff`.
- confidence: 0.60
- domain: environment
- first_seen: 2026-02-13
- last_seen: 2026-02-13
- evidence: "When ruff is not on PATH, prefer running formatting/lint via `python -m ruff`."

## Needs Review
