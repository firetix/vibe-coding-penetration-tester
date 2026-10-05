"""Record local evidence for the static product page."""

import json
import re
from pathlib import Path

from vibe_pentest.contract import Contract
from vibe_pentest.demo import demo, fixture, template
from vibe_pentest.runner import run

reports = demo()
with fixture("fixed") as origin:
    reports["expired"] = run(
        Contract.parse(template(origin)),
        {"VPT_ALICE_TOKEN": "demo-alice", "VPT_BOB_TOKEN": "expired-demo-bob"},
    )
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
print("Recorded broken, fixed, and expired-token runs in site/index.html.")
