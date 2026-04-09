# SPDX-License-Identifier: GPL-3.0-or-later
"""Update-Prüfung und automatische Installation gegen die Codeberg-Release-API.

Fragt die neueste veröffentlichte Release-Version von
``codeberg.org/pitbo/pdf-qes-signer`` ab und vergleicht sie mit der
aktuell installierten Version.  Die Prüfung läuft in einem
``QThread``, damit die UI nicht blockiert.

## Versionsvergleich

Es wird ``packaging.version.Version`` (PEP 440) verwendet, damit
``0.3.1 > 0.3.1.dev0`` korrekt erkannt wird.  Ist ``packaging`` nicht
verfügbar, fällt der Code auf einen einfachen String-Vergleich zurück –
das reicht für ``X.Y.Z``-Tags ohne Pre-Release-Suffix.

## API-Endpunkt

``GET https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases/latest``

Liefert JSON mit ``tag_name``, ``html_url`` und ``assets[]``.
Kein Authentifizierungstoken nötig – öffentliches Repository.

## Installations-Erkennung

``_detect_install_method()`` prüft ob ``sys.executable`` unter dem
pipx-Home-Verzeichnis liegt.  Ist das der Fall, wird
``pipx install --force <wheel>`` verwendet; sonst
``sys.executable -m pip install --upgrade <wheel>``.

## Neustart

- **Linux:** ``os.execv()`` ersetzt den laufenden Prozess in-place.
- **Windows:** ``subprocess.Popen`` + ``sys.exit(0)`` (neues Fenster,
  altes beendet sich).
"""

from __future__ import annotations

import logging
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

_log = logging.getLogger(__name__)

_RELEASES_BASE = "https://codeberg.org/api/v1/repos/pitbo/pdf-qes-signer/releases"
RELEASES_URL   = _RELEASES_BASE + "/latest"   # stable: non-pre-release only
RELEASES_PAGE  = "https://codeberg.org/pitbo/pdf-qes-signer/releases"


def _parse_version(tag: str):
    """Version-String parsen; gibt ein vergleichbares Objekt zurück."""
    v = tag.lstrip("v")
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        # Einfacher Fallback: Tupel aus Integer-Teilen
        try:
            return tuple(int(x) for x in v.split(".") if x.isdigit())
        except Exception:
            return (0,)


def _fetch_release(channel: str, timeout: int) -> Optional[dict]:
    """Neuestes Release-Objekt von der Codeberg-API laden.

    Für ``"stable"`` wird ``/releases/latest`` verwendet (liefert nur
    nicht-Pre-Releases).  Für ``"develop"`` werden die letzten fünf Releases
    abgerufen und das neueste (Pre-Release oder nicht) zurückgegeben.

    Returns:
        Release-Dict oder ``None`` bei Fehler.
    """
    import json
    import urllib.request

    if channel == "develop":
        url = _RELEASES_BASE + "?limit=5"
    else:
        url = RELEASES_URL  # /releases/latest

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "pdf-qes-signer-updater"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        _log.debug("Release-Abruf fehlgeschlagen: %s", exc)
        return None

    # /releases/latest → einzelnes Dict; /releases?limit=N → Liste
    if isinstance(data, list):
        return data[0] if data else None
    return data


def check_for_update(current_version: str,
                     channel: str = "stable",
                     timeout: int = 8) -> Optional[tuple[str, str]]:
    """Neueste Release-Version von Codeberg abrufen.

    Args:
        current_version: Aktuell installierte Version (z. B. ``"0.3.2"``).
        channel:         ``"stable"`` oder ``"develop"``.

    Returns:
        ``(latest_tag, release_url)`` wenn eine neuere Version verfügbar ist,
        ``None`` wenn aktuell oder bei Fehlern.
    """
    data = _fetch_release(channel, timeout)
    if data is None:
        return None

    tag = data.get("tag_name", "").strip()
    url = data.get("html_url", RELEASES_PAGE).strip()
    if not tag:
        return None

    try:
        if _parse_version(tag) > _parse_version(current_version):
            return tag, url
    except Exception as exc:
        _log.debug("Versionsvergleich fehlgeschlagen: %s", exc)

    return None


def get_latest_release_asset(channel: str = "stable",
                              timeout: int = 8) -> Optional[tuple[str, str]]:
    """Neuestes ``.whl``-Asset von der Codeberg-API abrufen.

    Args:
        channel: ``"stable"`` oder ``"develop"``.

    Returns:
        ``(tag, whl_url)`` oder ``None`` bei Fehler / kein Asset vorhanden.
    """
    data = _fetch_release(channel, timeout)
    if data is None:
        return None

    tag = data.get("tag_name", "").strip()
    if not tag:
        return None
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if name.endswith(".whl"):
            return tag, asset.get("browser_download_url", "")
    return None


def _detect_install_method() -> str:
    """Erkennt die Installationsumgebung der laufenden App.

    Returns:
        ``"pip"``     – pip in einem venv (unterstützt)
        ``"pipx"``    – pipx-verwaltetes venv (unterstützt)
        ``"conda"``   – Conda/Mamba-Umgebung (nicht unterstützt)
        ``"system"``  – System-Python ohne venv (nicht unterstützt)
        ``"unknown"`` – sonstige Umgebung
    """
    exe = Path(sys.executable).resolve()

    # pipx: sys.executable liegt unter PIPX_HOME
    pipx_home = Path(
        os.environ.get("PIPX_HOME", Path.home() / ".local" / "pipx")
    ).resolve()
    try:
        exe.relative_to(pipx_home)
        return "pipx"
    except ValueError:
        pass

    # conda/mamba: CONDA_PREFIX gesetzt oder "conda"/"miniforge"/"miniconda"
    # im Pfad des Executables
    exe_str = str(exe).lower()
    if (os.environ.get("CONDA_PREFIX")
            or any(k in exe_str for k in ("conda", "mamba", "miniforge", "miniconda"))):
        return "conda"

    # pip in venv: sys.prefix != sys.base_prefix
    if sys.prefix != sys.base_prefix:
        return "pip"

    # System-Python (kein venv aktiv)
    return "system"


def download_file(
    url: str,
    dest: Path,
    progress_cb,          # Callable[[int, int], None] – (downloaded, total)
    timeout: int = 120,
) -> None:
    """URL nach *dest* herunterladen; ruft *progress_cb(downloaded, total)* auf.

    *total* ist 0 wenn der Server keine Content-Length sendet.
    Wirft ``Exception`` bei Netzwerk- oder Schreibfehlern.
    """
    import urllib.request

    req = urllib.request.Request(
        url, headers={"User-Agent": "pdf-qes-signer-updater"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 65536
        with open(dest, "wb") as f:
            while True:
                block = resp.read(chunk_size)
                if not block:
                    break
                f.write(block)
                downloaded += len(block)
                progress_cb(downloaded, total)


def install_wheel(wheel_path: Path, dry_run: bool = False) -> tuple[bool, str]:
    """Wheel via pip oder pipx installieren.

    Unterstützte Umgebungen: ``"pip"`` (venv) und ``"pipx"``.
    Bei ``"conda"`` oder ``"system"`` wird ein erklärender Fehler zurückgegeben.

    Args:
        wheel_path: Pfad zur heruntergeladenen ``.whl``-Datei.
        dry_run:    Wenn ``True`` wird ``--dry-run`` übergeben (kein echtes Install).
                    Hinweis: pipx unterstützt kein ``--dry-run``; bei pipx+dry_run
                    wird nur geprüft ob pipx erreichbar ist.

    Returns:
        ``(True, "")`` bei Erfolg; ``(False, error_msg)`` bei Fehler.
    """
    method = _detect_install_method()
    _log.debug("install_wheel: method=%s dry_run=%s path=%s", method, dry_run, wheel_path)

    if method == "conda":
        return False, (
            "Conda-Umgebung erkannt – automatisches Update nicht unterstützt.\n\n"
            "Bitte manuell aktualisieren:\n"
            f"  pip install --upgrade {wheel_path}"
        )

    if method == "system":
        return False, (
            "Kein virtuelles Environment erkannt – automatisches Update nicht unterstützt.\n\n"
            "Bitte in einem venv ausführen oder manuell aktualisieren:\n"
            f"  pip install --upgrade {wheel_path}"
        )

    if method == "pipx":
        if dry_run:
            try:
                result = subprocess.run(
                    ["pipx", "--version"], capture_output=True, text=True
                )
                return result.returncode == 0, ("" if result.returncode == 0
                                                else result.stderr.strip())
            except FileNotFoundError:
                return False, "pipx nicht gefunden"
        cmd = ["pipx", "install", "--force", str(wheel_path)]
    else:
        # "pip" oder "unknown" → pip versuchen
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", str(wheel_path)]
        if dry_run:
            cmd.append("--dry-run")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        return False, str(exc)

    if result.returncode == 0:
        return True, ""
    return False, (result.stderr or result.stdout).strip()


def fallback_command(wheel_path: Path) -> str:
    """Manuellen Installations-Befehl als Fallback-Text liefern."""
    method = _detect_install_method()
    if method == "pipx":
        return f"pipx install --force {wheel_path}"
    return f"{sys.executable} -m pip install --upgrade {wheel_path}"


def restart_app() -> None:
    """Startet die Anwendung neu.

    - **Linux/macOS:** ``os.execv()`` ersetzt den laufenden Prozess in-place.
    - **Windows:** ``subprocess.Popen`` + ``sys.exit(0)``.
    """
    if sys.platform == "win32":
        subprocess.Popen([sys.executable] + sys.argv)
        sys.exit(0)
    else:
        os.execv(sys.executable, [sys.executable] + sys.argv)


class UpdateCheckWorker(QThread):
    """Hintergrund-Thread für die Update-Prüfung beim Programmstart.

    Signals:
        update_available(str, str): (latest_tag, release_url) wenn Update verfügbar.
        no_update():                aktuell oder Fehler.
    """

    update_available = pyqtSignal(str, str)
    no_update        = pyqtSignal()

    def __init__(self, current_version: str, channel: str = "stable",
                 parent=None) -> None:
        super().__init__(parent)
        self._current = current_version
        self._channel = channel

    def run(self) -> None:
        result = check_for_update(self._current, channel=self._channel)
        if result:
            self.update_available.emit(*result)
        else:
            self.no_update.emit()


class UpdateInstallWorker(QThread):
    """Hintergrund-Thread: Download + Install eines Wheel-Pakets.

    Signals:
        progress(int, int):  (heruntergeladene Bytes, Gesamt-Bytes; 0 = unbekannt)
        status(str):         ``"downloading"`` oder ``"installing"``
        finished(bool, str): ``(True, "")`` bei Erfolg;
                             ``(False, fehlermeldung)`` bei Fehler.
                             Im Fehlerfall enthält *fehlermeldung* auch den
                             manuellen Fallback-Befehl (nach doppeltem Zeilenumbruch).
    """

    progress = pyqtSignal(int, int)
    status   = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, tag: str, url: str, dry_run: bool = False,
                 channel: str = "stable", parent=None) -> None:
        super().__init__(parent)
        self._tag     = tag
        self._url     = url
        self._dry_run = dry_run
        self._channel = channel
        self._abort   = False

    def abort(self) -> None:
        """Download/Install abbrechen (wird beim nächsten Chunk geprüft)."""
        self._abort = True

    def run(self) -> None:
        import tempfile

        fname = self._url.rsplit("/", 1)[-1] or f"update_{self._tag}.whl"
        with tempfile.TemporaryDirectory(prefix="pdf-signer-update-") as tmp:
            dest = Path(tmp) / fname

            # --- Download ---
            try:
                def _cb(done: int, total: int) -> None:
                    if self._abort:
                        raise InterruptedError("Abgebrochen")
                    self.progress.emit(done, total)

                self.status.emit("downloading")
                download_file(self._url, dest, _cb)
            except InterruptedError:
                self.finished.emit(False, "aborted")
                return
            except Exception as exc:
                self.finished.emit(False, str(exc))
                return

            if self._abort:
                self.finished.emit(False, "aborted")
                return

            # --- Install ---
            self.status.emit("installing")
            ok, err = install_wheel(dest, dry_run=self._dry_run)
            if ok:
                self.finished.emit(True, "")
            else:
                fb  = fallback_command(dest)
                msg = f"{err}\n\n{fb}" if err else fb
                self.finished.emit(False, msg)
