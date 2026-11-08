"""GUI entry point: ``octov-gui [--config config.yaml] [sample ...]``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtWidgets import QApplication

from octov.core.config import ConfigError, load_config
from octov.gui.main_window import MainWindow


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="octov-gui")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("samples", nargs="*", type=Path)
    args = parser.parse_args(argv)

    config_path = args.config
    if config_path is None and Path("config.yaml").is_file():
        config_path = Path("config.yaml")
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("OctoV")
    app.setOrganizationName("OctoV")
    window = MainWindow(config)
    window.show()
    for sample in args.samples:
        window.load_sample(sample)
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
