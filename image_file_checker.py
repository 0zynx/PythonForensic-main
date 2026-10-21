"""Validation for standalone PNG image files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError


def inspect_png(image_path: Path) -> dict[str, Any]:
    """Check that a file is a decodable PNG and return basic image details."""
    path = Path(image_path).expanduser().resolve()
    report: dict[str, Any] = {
        "image_path": str(path),
        "format": None,
        "valid": False,
        "width": None,
        "height": None,
        "mode": None,
        "error": None,
    }

    try:
        with Image.open(path) as image:
            report["format"] = image.format
            report["width"] = image.width
            report["height"] = image.height
            report["mode"] = image.mode
            if image.format != "PNG":
                report["error"] = f"Expected PNG content, detected {image.format}."
                return report
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        report["error"] = str(exc) or type(exc).__name__
        return report

    report["valid"] = True
    return report


def write_png_report(output_dir: Path, report: dict[str, Any]) -> Path:
    """Write the PNG validation report and return its path."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "image_check.json"
    with report_path.open("w", encoding="utf-8", newline="\n") as report_file:
        json.dump(report, report_file, ensure_ascii=False, indent=2)
        report_file.write("\n")
    return report_path
