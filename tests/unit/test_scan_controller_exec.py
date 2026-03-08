import os
import sys


def test_scan_controller_uses_sys_executable_for_main_subprocess(monkeypatch, tmp_path):
    from utils.report_manager import ReportManager
    from utils.scan_controller import ScanController
    from utils.session_manager import SessionManager

    report_root = tmp_path / "reports"
    report_manager = ReportManager(str(report_root))
    session_manager = SessionManager(session_file=str(tmp_path / "sessions.json"))
    controller = ScanController(session_manager, report_manager)

    report_dir = report_manager.create_report_directory("https://example.com")

    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return object()

    monkeypatch.setattr(
        __import__("subprocess"),
        "Popen",
        fake_popen,
    )
    monkeypatch.setattr(controller, "_monitor_process", lambda *_args, **_kwargs: None)

    controller._execute_scan(
        url="https://example.com",
        config={},
        report_dir=report_dir,
        progress_callback=lambda *_args, **_kwargs: None,
    )

    assert captured["cmd"][0] == sys.executable
    assert captured["cmd"][1:] == [
        "main.py",
        "--url",
        "https://example.com",
        "--output",
        os.path.join(str(report_root), report_dir),
    ]

