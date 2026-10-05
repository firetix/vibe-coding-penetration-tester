# Static product page

Open `index.html` directly in a browser.
The page has no build step, external assets, forms, analytics, or network requests.
Its outbound documentation links target the public repository after this change merges.

The evidence panel replays actual local runs against synthetic fixtures.
It does not run a scan in the browser.
Refresh the embedded evidence from the repository root:

```sh
uv run python scripts/refresh_landing_demo.py
```

The page is ready for static hosting. No hosting deployment is implied by this file.
