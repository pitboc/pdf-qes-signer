# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests für pdf_signer.updater – Download/Install-Flow.

Ebene 1 (Unit): Netzwerk und subprocess werden gemockt.
Ebene 2 (Integration): echter Download, pip --dry-run (kein echtes Install).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _fake_asset_response(tag: str = "v0.3.1",
                         whl_name: str = "pdf_qes_signer-0.3.1-py3-none-any.whl"):
    """Gibt ein simuliertes API-Response-Dict zurück."""
    return {
        "tag_name": tag,
        "html_url": f"https://codeberg.org/pitbo/pdf-qes-signer/releases/tag/{tag}",
        "assets": [
            {
                "name": whl_name,
                "browser_download_url":
                    f"https://codeberg.org/pitbo/pdf-qes-signer/releases/download/"
                    f"{tag}/{whl_name}",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Einzel-Funktionen
# ---------------------------------------------------------------------------

class TestDetectInstallMethod:
    def test_pip_default(self, monkeypatch):
        """Standard-Python-Executable → pip."""
        from pdf_signer.updater import _detect_install_method
        # sys.executable zeigt nicht auf pipx-Home
        monkeypatch.setenv("PIPX_HOME", "/nonexistent/pipx")
        assert _detect_install_method() == "pip"

    def test_pipx_detected(self, monkeypatch, tmp_path):
        """Wenn sys.executable unter PIPX_HOME liegt → pipx."""
        from pdf_signer import updater
        fake_pipx = tmp_path / "pipx"
        fake_exe  = fake_pipx / "venvs" / "pdf-qes-signer" / "bin" / "python"
        fake_exe.parent.mkdir(parents=True)
        fake_exe.touch()

        monkeypatch.setenv("PIPX_HOME", str(fake_pipx))
        monkeypatch.setattr(updater.sys, "executable", str(fake_exe))
        assert updater._detect_install_method() == "pipx"


class TestGetLatestReleaseAsset:
    def test_returns_whl_url(self, monkeypatch):
        import json
        from pdf_signer.updater import get_latest_release_asset
        import urllib.request

        resp_data = _fake_asset_response()

        class FakeResp:
            def read(self):
                return json.dumps(resp_data).encode()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        result = get_latest_release_asset()
        assert result is not None
        tag, url = result
        assert tag == "v0.3.1"
        assert url.endswith(".whl")

    def test_no_whl_asset_returns_none(self, monkeypatch):
        import json
        from pdf_signer.updater import get_latest_release_asset
        import urllib.request

        resp_data = {"tag_name": "v0.3.1", "html_url": "...", "assets": [
            {"name": "source.tar.gz", "browser_download_url": "..."}
        ]}

        class FakeResp:
            def read(self): return json.dumps(resp_data).encode()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        assert get_latest_release_asset() is None

    def test_network_error_returns_none(self, monkeypatch):
        import urllib.request
        from pdf_signer.updater import get_latest_release_asset
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **kw: (_ for _ in ()).throw(OSError("net")))
        assert get_latest_release_asset() is None


class TestDownloadFile:
    def test_download_writes_content(self, tmp_path, monkeypatch):
        from pdf_signer.updater import download_file
        import urllib.request

        content = b"fake wheel content " * 100

        class FakeResp:
            headers = {"Content-Length": str(len(content))}
            _pos = 0
            def read(self, n):
                chunk = content[self._pos:self._pos + n]
                self._pos += n
                return chunk
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        dest = tmp_path / "test.whl"
        progress_calls = []
        download_file("https://fake/test.whl", dest,
                      lambda d, t: progress_calls.append((d, t)))
        assert dest.read_bytes() == content
        assert len(progress_calls) > 0
        # Letzter Aufruf: alles heruntergeladen
        assert progress_calls[-1][0] == len(content)

    def test_abort_raises(self, tmp_path, monkeypatch):
        from pdf_signer.updater import download_file
        import urllib.request

        class FakeResp:
            headers = {"Content-Length": "1000"}
            def read(self, n): return b"x" * n
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        dest = tmp_path / "test.whl"

        call_count = [0]
        def _abort_cb(done, total):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise InterruptedError("Abgebrochen")

        with pytest.raises(InterruptedError):
            download_file("https://fake/test.whl", dest, _abort_cb)


class TestInstallWheel:
    def test_pip_success(self, tmp_path, monkeypatch):
        from pdf_signer import updater
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pip")

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stderr = ""
        monkeypatch.setattr(updater.subprocess, "run", lambda *a, **kw: fake_result)

        ok, err = updater.install_wheel(tmp_path / "pkg.whl")
        assert ok is True
        assert err == ""

    def test_pip_failure_returns_error(self, tmp_path, monkeypatch):
        from pdf_signer import updater
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pip")

        fake_result = MagicMock()
        fake_result.returncode = 1
        fake_result.stderr = "ERROR: some pip error"
        fake_result.stdout = ""
        monkeypatch.setattr(updater.subprocess, "run", lambda *a, **kw: fake_result)

        ok, err = updater.install_wheel(tmp_path / "pkg.whl")
        assert ok is False
        assert "pip error" in err

    def test_pip_dry_run_appends_flag(self, tmp_path, monkeypatch):
        from pdf_signer import updater
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pip")

        captured_cmd = []
        fake_result = MagicMock()
        fake_result.returncode = 0
        def fake_run(cmd, **kw):
            captured_cmd.extend(cmd)
            return fake_result
        monkeypatch.setattr(updater.subprocess, "run", fake_run)

        updater.install_wheel(tmp_path / "pkg.whl", dry_run=True)
        assert "--dry-run" in captured_cmd

    def test_pipx_not_found(self, tmp_path, monkeypatch):
        from pdf_signer import updater
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pipx")
        monkeypatch.setattr(updater.subprocess, "run",
                            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("pipx")))
        ok, err = updater.install_wheel(tmp_path / "pkg.whl")
        assert ok is False
        assert "pipx" in err.lower()


class TestFallbackCommand:
    def test_pip_fallback(self, tmp_path, monkeypatch):
        from pdf_signer import updater
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pip")
        cmd = updater.fallback_command(tmp_path / "pkg.whl")
        assert "pip" in cmd
        assert "pkg.whl" in cmd

    def test_pipx_fallback(self, tmp_path, monkeypatch):
        from pdf_signer import updater
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pipx")
        cmd = updater.fallback_command(tmp_path / "pkg.whl")
        assert "pipx" in cmd


# ---------------------------------------------------------------------------
# UpdateInstallWorker (Unit – alles gemockt)
# ---------------------------------------------------------------------------

class TestUpdateInstallWorker:
    """QThread-Tests ohne GUI; nutzen .run() direkt (kein QApplication nötig)."""

    def test_success_flow(self, tmp_path, monkeypatch):
        from pdf_signer import updater

        monkeypatch.setattr(updater, "download_file",
                            lambda url, dest, cb, **kw: dest.write_bytes(b"fake"))
        monkeypatch.setattr(updater, "install_wheel", lambda p, **kw: (True, ""))

        worker = updater.UpdateInstallWorker("v0.3.1", "https://fake/pkg.whl")
        statuses, results = [], []
        worker.status.connect(statuses.append)
        worker.finished.connect(lambda ok, e: results.append((ok, e)))
        worker.run()   # direkt (kein Thread)

        assert statuses == ["downloading", "installing"]
        assert results == [(True, "")]

    def test_download_error(self, tmp_path, monkeypatch):
        from pdf_signer import updater

        def _fail_download(url, dest, cb, **kw):
            raise OSError("Connection refused")
        monkeypatch.setattr(updater, "download_file", _fail_download)

        worker = updater.UpdateInstallWorker("v0.3.1", "https://fake/pkg.whl")
        results = []
        worker.finished.connect(lambda ok, e: results.append((ok, e)))
        worker.run()

        assert results[0][0] is False
        assert "Connection refused" in results[0][1]

    def test_install_failure_includes_fallback(self, tmp_path, monkeypatch):
        from pdf_signer import updater

        monkeypatch.setattr(updater, "download_file",
                            lambda url, dest, cb, **kw: dest.write_bytes(b"fake"))
        monkeypatch.setattr(updater, "install_wheel",
                            lambda p, **kw: (False, "pip: error"))
        monkeypatch.setattr(updater, "_detect_install_method", lambda: "pip")

        worker = updater.UpdateInstallWorker("v0.3.1", "https://fake/pkg.whl")
        results = []
        worker.finished.connect(lambda ok, e: results.append((ok, e)))
        worker.run()

        assert results[0][0] is False
        # Fehlermeldung + Fallback-Befehl im Text
        assert "pip: error" in results[0][1]
        assert "pip" in results[0][1]

    def test_abort_mid_download(self, monkeypatch):
        from pdf_signer import updater

        worker = updater.UpdateInstallWorker("v0.3.1", "https://fake/pkg.whl")

        def _download_with_abort(url, dest, cb, **kw):
            dest.write_bytes(b"partial")
            cb(100, 1000)   # erstes Chunk
            worker.abort()  # Abbruch setzen
            cb(200, 1000)   # zweites Chunk → löst InterruptedError aus

        monkeypatch.setattr(updater, "download_file", _download_with_abort)

        results = []
        worker.finished.connect(lambda ok, e: results.append((ok, e)))
        worker.run()

        assert results[0] == (False, "aborted")

    def test_dry_run_not_called_install(self, monkeypatch):
        from pdf_signer import updater

        install_calls = []
        monkeypatch.setattr(updater, "download_file",
                            lambda url, dest, cb, **kw: dest.write_bytes(b"fake"))
        monkeypatch.setattr(updater, "install_wheel",
                            lambda p, **kw: install_calls.append(kw) or (True, ""))

        worker = updater.UpdateInstallWorker("v0.3.1", "https://fake/pkg.whl",
                                             dry_run=True)
        worker.run()
        assert install_calls[0].get("dry_run") is True


# ---------------------------------------------------------------------------
# Ebene 2: echter Download + pip --dry-run (Integrations-Test)
# Wird übersprungen wenn kein Netzwerk oder kein Asset auf Codeberg vorhanden.
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_real_download_dry_run_install():
    """Echter Download der neuesten .whl von Codeberg, dann pip --dry-run."""
    from pdf_signer.updater import (get_latest_release_asset, download_file,
                                     install_wheel)
    import tempfile

    result = get_latest_release_asset(timeout=15)
    if result is None:
        pytest.skip("Kein Asset auf Codeberg gefunden oder kein Netzwerk")

    tag, url = result
    assert url.endswith(".whl"), f"Unerwartete Asset-URL: {url}"

    with tempfile.TemporaryDirectory(prefix="pdf-signer-test-") as tmp:
        dest = Path(tmp) / url.rsplit("/", 1)[-1]
        progress_log = []
        download_file(url, dest, lambda d, t: progress_log.append((d, t)),
                      timeout=60)

        assert dest.exists()
        assert dest.stat().st_size > 10_000, "Wheel zu klein – verdächtig"
        assert len(progress_log) > 0

        # pip --dry-run: prüft Abhängigkeiten, installiert nichts
        ok, err = install_wheel(dest, dry_run=True)
        assert ok, f"pip --dry-run fehlgeschlagen: {err}"
