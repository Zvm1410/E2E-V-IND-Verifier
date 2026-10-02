import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from app.ui.window import MainWindow


def _load_stylesheet(base_dir: Path) -> str:
    stylesheet_path = base_dir / "app" / "ui" / "theme" / "style.qss"
    return stylesheet_path.read_text(encoding="utf-8")


def main() -> None:
    base_dir = Path(__file__).resolve().parent.parent
    config_path = base_dir / "config" / "election.json"
    kiosk = "--windowed" not in sys.argv

    app = QApplication(sys.argv)
    app.setStyleSheet(_load_stylesheet(base_dir))

    window = MainWindow(config_path=str(config_path), kiosk=kiosk)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
