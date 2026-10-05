"""Record local evidence for the static product page."""

import argparse
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser(description="Embed verified Supabase reports in the product page.")
parser.add_argument("--supabase-report", required=True, type=Path)
args = parser.parse_args()
source = json.loads(args.supabase_report.read_text())
reports = {
    "vulnerable": source["permissive-policy"],
    "fixed": source["fixed-again"],
    "expired": source["invalid-session"],
}
if tuple(report["status"] for report in reports.values()) != ("fail", "pass", "error"):
    raise RuntimeError("Expected verified leaking, fixed, and invalid-session results.")
page = Path(__file__).resolve().parents[1] / "site" / "index.html"
content = page.read_text()
pattern = r'(<script id="demo-data" type="application/json">).*?(</script>)'
updated, count = re.subn(
    pattern,
    lambda match: match[1] + json.dumps(reports).replace("<", r"\u003c") + match[2],
    content,
    flags=re.DOTALL,
)
if count != 1:
    raise RuntimeError("Expected exactly one embedded evidence record.")
page.write_text(updated)
print("Embedded leaking, fixed, and invalid-session Supabase runs in site/index.html.")
