# SPDX-License-Identifier: GPL-3.0-or-later
"""
PDF QES Signer – visual signature field placement and QES signing via PKCS#11.

Version: 0.1
License: GPL-3.0-or-later
"""

from pathlib import Path as _Path
import subprocess as _subprocess

__version__ = "0.1"
__author__  = "PDF QES Signer contributors"
__license__ = "GPL-3.0-or-later"


def _get_git_commit() -> str:
    try:
        result = _subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True,
            cwd=str(_Path(__file__).parent.parent),
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


__commit__ = _get_git_commit()
