"""Run npm from the project's venv (nodejs-wheel) so no system Node.js is needed.

python scripts/npm.py install        # inside web/
python scripts/npm.py run build
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import nodejs_wheel
from nodejs_wheel import npm

if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1] / "web")
    node_dir = Path(nodejs_wheel.__file__).parent
    os.environ["PATH"] = f"{node_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    raise SystemExit(npm(sys.argv[1:]))
