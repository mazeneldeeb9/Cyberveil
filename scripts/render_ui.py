from __future__ import annotations

import argparse
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from cyberveil.storage import Database
from cyberveil.ui.app import create_application
from cyberveil.ui.main_window import MainWindow


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render a CYBERVEIL page for visual QA.")
    parser.add_argument("output", nargs="?", default="tmp/ui-dashboard.png")
    parser.add_argument("--page", default="dashboard")
    parser.add_argument("--language", choices=("en", "ar"), default="en")
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=900)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    app = create_application()
    database = Database(Path("tmp/render-ui.db"))
    window = MainWindow(database)
    settings = window.settings.model_copy(update={"language": args.language})
    window.save_settings(settings)
    window.settings_page.set_settings(settings)
    window.navigate(args.page, remember=False)
    window.resize(args.width, args.height)
    window.show()
    app.processEvents()
    if not window.grab().save(str(output)):
        return 1
    window.close()
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
