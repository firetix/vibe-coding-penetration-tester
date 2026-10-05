"""Run both versions of the documented FastAPI recipe."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from vibe_pentest.demo import template

APP = Path(__file__).with_name("app.py")


def verify():
    for vulnerable, expected in [(True, 1), (False, 0)]:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        args = [sys.executable, str(APP), "--port", str(port)]
        if vulnerable:
            args.append("--vulnerable")
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("The FastAPI fixture exited during startup.")
                try:
                    urllib.request.urlopen(origin + "/openapi.json", timeout=0.2).close()
                    break
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.05)
            else:
                raise RuntimeError("The FastAPI fixture did not become ready.")
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "contract.json"
                config.write_text(json.dumps(template(origin)))
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "vibe_pentest",
                        "check",
                        str(config),
                        "--allow-origin",
                        origin,
                        "--format",
                        "json",
                    ],
                    env={
                        **os.environ,
                        "VPT_ALICE_TOKEN": "demo-alice",
                        "VPT_BOB_TOKEN": "demo-bob",
                    },
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if result.returncode != expected:
                    raise RuntimeError("The FastAPI fixture returned an unexpected check result.")
                report = json.loads(result.stdout)
                print(f"FastAPI {'broken' if vulnerable else 'fixed'}: {report['status']}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    verify()
