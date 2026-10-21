"""Stage 3: recover deleted files using the records the file system left behind."""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from carver import is_valid

LOGGER = logging.getLogger(__name__)
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".pcx"}

# file signature -> type label (first bytes of a real file of that type)
SIGNATURES = [
    (b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF8", "gif"),
    (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"), (b"II*\x00", "tif"), (b"MM\x00*", "tif"),
    (b"RIFF", "riff"), (b"BM", "bmp"),
]
# extension -> the type label a genuine file with that extension should have
EXT_FAMILY = {
    ".jpg": "jpg", ".jpeg": "jpg", ".png": "png", ".gif": "gif", ".pdf": "pdf",
    ".zip": "zip", ".docx": "zip", ".xlsx": "zip", ".pptx": "zip", ".tif": "tif",
    ".tiff": "tif", ".wav": "riff", ".bmp": "bmp",
}
TEXT_EXTS = {".txt", ".csv", ".log", ".md", ".json", ".xml", ".html"}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def detect_type(blob: bytes) -> str | None:
    for sig, label in SIGNATURES:
        if blob.startswith(sig):
            return label
    return None


def check_content(blob: bytes, ext: str) -> tuple[str, str | None, bool]:
    """Return (content_status, detected_type, type_mismatch) for recovered bytes."""
    sample = blob[:65536]
    if not sample:
        return "empty", None, False
    if sample.count(0) / len(sample) >= 0.99:
        return "wiped_zeros", None, False
    if len(set(sample)) == 1:
        return "wiped_pattern", None, False
    detected = detect_type(blob)
    expected = EXT_FAMILY.get(ext)
    if detected:
        return "intact", detected, bool(expected and detected != expected)
    if expected:  # should have a known signature but has none
        return ("overwritten" if _entropy(sample) > 7.5 else "corrupt_or_replaced"), None, False
    if ext in TEXT_EXTS:
        return ("overwritten" if _entropy(sample) > 6.5 else "intact"), None, False
    return "unverified", None, False


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "unnamed"


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def allocated_ranges(rows: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """Byte ranges held by files and folders that still exist."""
    out = []
    for row in rows:
        if row["status"] != "allocated":
            continue
        for run in row["data_runs"]:
            if run["start_offset"] is not None:
                out.append((run["start_offset"], run["start_offset"] + run["length"]))
    return _merge(out)


def _overlaps(runs: list[tuple[int, int]], in_use: list[tuple[int, int]]) -> bool:
    return any(s < ue and e > us for s, e in runs for us, ue in in_use)


def recover_deleted(image_path: Path | str, rows: list[dict[str, Any]], out_dir: Path | str) -> list[dict[str, Any]]:
    """Read each deleted file's data back from the image, using its leftover record.

    Files keep their original name, size and timestamps. If the file's storage has since been
    given to another file, the result is flagged because its content cannot be trusted.
    """
    os.makedirs(out_dir, exist_ok=True)
    in_use = allocated_ranges(rows)
    results: list[dict[str, Any]] = []
    with open(image_path, "rb") as image:
        for row in rows:
            if row["type"] != "file" or row["status"] != "deleted" or row["size"] <= 0:
                continue
            runs = [(r["start_offset"], r["start_offset"] + r["length"])
                    for r in row["data_runs"] if r["start_offset"] is not None]
            if not runs:
                LOGGER.warning("No data location for deleted file %s", row["path"])
                continue
            data = bytearray()
            for run in row["data_runs"]:
                if run["start_offset"] is None:
                    data += b"\x00" * run["length"]
                else:
                    image.seek(run["start_offset"])
                    data += image.read(run["length"])
            blob = bytes(data[: row["size"]])
            reused = _overlaps(runs, in_use)
            name = f"{row['inode']}_{_safe(row['name'])}"
            with open(os.path.join(out_dir, name), "wb") as out:
                out.write(blob)
            ext = Path(row["name"]).suffix.lower()
            status, detected, mismatch = check_content(blob, ext)
            is_image = ext in IMAGE_EXTS and status == "intact"
            results.append({
                "method": "file-system record",
                "file": name,
                "type": Path(row["name"]).suffix.lstrip(".").lower(),
                "original_path": row["path"],
                "inode": row["inode"],
                "offset": runs[0][0],
                "size": len(blob),
                "created_utc": row.get("created_utc"),
                "modified_utc": row.get("modified_utc"),
                "accessed_utc": row.get("accessed_utc"),
                "valid": is_valid(blob) if is_image else None,
                "content_status": status,
                "detected_type": detected,
                "type_mismatch": mismatch,
                "storage_reused": reused,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "md5": hashlib.md5(blob).hexdigest(),
            })
    return results