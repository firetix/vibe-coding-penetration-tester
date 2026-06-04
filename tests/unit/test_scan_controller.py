import logging
import sys

from utils.scan_controller import ScanController
from utils.session_manager import SessionManager


class _ReportManagerStub:
    def __init__(self, upload_folder):
        self.upload_folder = str(upload_folder)


def test_execute_scan_uses_current_python_executable(monkeypatch, tmp_path):
    session_manager = SessionManager(session_file=str(tmp_path / "sessions.json"))
    controller = ScanController(session_manager, _ReportManagerStub(tmp_path))
    captured = {}

    class FakeStdout:
        def readline(self):
            return ""

    class FakeProcess:
        stdout = FakeStdout()

        def communicate(self):
            return "", ""

        def wait(self):
            return 0

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeProcess()

    monkeypatch.setattr("utils.scan_controller.subprocess.Popen", fake_popen)

    controller._execute_scan(
        "http://127.0.0.1:3000",
        {},
        "scan-report",
        lambda *args, **kwargs: None,
    )

    assert captured["cmd"][:2] == [sys.executable, "main.py"]


def test_finalize_scan_without_report_marks_scan_error(tmp_path):
    session_manager = SessionManager(session_file=str(tmp_path / "sessions.json"))
    controller = ScanController(session_manager, _ReportManagerStub(tmp_path))
    session_id = session_manager.create_session()
    scan_id = session_manager.start_scan(session_id, "http://127.0.0.1:3000", {})

    controller._finalize_scan(session_id, scan_id, "missing-report")

    completed = session_manager.get_completed_scans(session_id)
    assert completed[0]["id"] == scan_id
    assert completed[0]["status"] == "error"
    assert (
        completed[0]["current_task"]
        == "Scanner finished but did not generate report.json."
    )


def test_monitor_process_logs_successful_stderr_as_warning(caplog, tmp_path):
    session_manager = SessionManager(session_file=str(tmp_path / "sessions.json"))
    controller = ScanController(session_manager, _ReportManagerStub(tmp_path))

    class FakeStdout:
        def readline(self):
            return ""

    class FakeProcess:
        stdout = FakeStdout()

        def communicate(self):
            return "", "dependency warning"

        def wait(self):
            return 0

    with caplog.at_level(logging.WARNING, logger="web_ui"):
        controller._monitor_process(FakeProcess(), lambda *args, **kwargs: None)

    assert "Scanner stderr contained warnings: dependency warning" in caplog.text
    assert "Scanner process exited with code" not in caplog.text
