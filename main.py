"""Command-line entry point: ingest, parse, recover, carve, verify and report."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Sequence

from carver import carve
from fs_parser import ParsedIndex, parse_image
from fs_recover import allocated_ranges, recover_deleted
from image_file_checker import inspect_png, write_png_report
from image_loader import LoadedImage, _sha256_file, load_image
from index_writer import write_index
from report import write_report
from verification import hash_originals, verify_results

LOGGER = logging.getLogger(__name__)


def _build_summary(image: LoadedImage, parsed: ParsedIndex) -> dict[str, object]:
    rows = parsed.rows
    files = [row for row in rows if row["type"] == "file"]
    return {
        "image_path": str(image.path),
        "image_sha256": image.sha256,
        "partitions_found": parsed.partitions_found,
        "fs_types": parsed.fs_types,
        "total_files": len(files),
        "allocated_files": sum(row["status"] == "allocated" for row in files),
        "deleted_files": sum(row["status"] == "deleted" for row in files),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run the pipeline and return a process exit code."""
    parser = argparse.ArgumentParser(
        description="Check a PNG file or analyse a raw/E01 disk image."
    )
    parser.add_argument("--image", required=True, type=Path, help="Input image path")
    parser.add_argument("--out-dir", required=True, type=Path, help="Output directory")
    parser.add_argument("--recover", action="store_true",
                        help="Recover deleted files from file-system records")
    parser.add_argument("--carve", action="store_true",
                        help="Carve files by signature (unallocated space only, if a file system exists)")
    parser.add_argument("--originals", type=Path,
                        help="Folder of original files; recovered files are matched by SHA-256")
    parser.add_argument("--report", action="store_true", help="Write report.html and results.json")

    arguments = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    loaded_image: LoadedImage | None = None
    try:
        if arguments.image.suffix.casefold() == ".png":
            report = inspect_png(arguments.image)
            report_path = write_png_report(arguments.out_dir, report)
            if report["valid"]:
                LOGGER.info(
                    "PNG is valid (%s x %s); report written to %s",
                    report["width"],
                    report["height"],
                    report_path,
                )
                return 0
            LOGGER.error("PNG validation failed: %s", report["error"])
            return 1

        loaded_image = load_image(arguments.image)
        parsed = parse_image(loaded_image)
        summary = _build_summary(loaded_image, parsed)
        write_index(arguments.out_dir, parsed.rows, summary)
        LOGGER.info("Wrote %s records to %s", len(parsed.rows), arguments.out_dir)

        fs_found = bool(parsed.fs_types)
        fs_results: list[dict] = []
        carved: list[dict] = []

        if arguments.recover:
            if fs_found:
                fs_results = recover_deleted(
                    loaded_image.path, parsed.rows, arguments.out_dir / "recovered_fs"
                )
                LOGGER.info("Recovered %s deleted files from file-system records", len(fs_results))
            else:
                LOGGER.info("No file system found; skipping record-based recovery")

        if arguments.carve:
            skip = allocated_ranges(parsed.rows) if fs_found else None
            LOGGER.info(
                "Carving %s", "unallocated space only" if skip is not None else "the whole image"
            )
            carved = carve(str(loaded_image.path), str(arguments.out_dir / "recovered"), skip)
            LOGGER.info("Carved %s files (%s valid)", len(carved),
                        sum(1 for r in carved if r["valid"]))

        verification = None
        if arguments.originals:
            originals = hash_originals(arguments.originals)
            verification = verify_results(fs_results + carved, originals)
            LOGGER.info("Verified %s of %s originals recovered byte-for-byte",
                        verification["recovered"], verification["total"])

        if arguments.report:
            unchanged = _sha256_file(loaded_image.path) == loaded_image.sha256
            LOGGER.info("Image hash unchanged after analysis: %s", unchanged)
            path = write_report(arguments.out_dir, summary, fs_results, carved, verification, unchanged)
            LOGGER.info("Report written to %s", path)

    except Exception as exc:
        LOGGER.error("Image analysis failed: %s", exc)
        return 1
    finally:
        if loaded_image is not None:
            loaded_image.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())