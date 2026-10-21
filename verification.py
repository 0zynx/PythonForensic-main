"""Stage 5: prove recovered files are identical to known originals (SHA-256)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_originals(folder: Path | str) -> dict[str, str]:
    """Map SHA-256 -> file name for every file in the originals folder."""
    return {_sha256(p): p.name for p in sorted(Path(folder).iterdir()) if p.is_file()}


def verify_results(results: list[dict[str, Any]], originals: dict[str, str]) -> dict[str, Any]:
    """Tag each recovered file with the original it matches, and report per-original status."""
    for result in results:
        result["matches_original"] = originals.get(result["sha256"])
    per_original = []
    for digest, name in originals.items():
        methods = sorted({r["method"] for r in results if r["sha256"] == digest})
        per_original.append({"original": name, "sha256": digest,
                             "recovered": bool(methods), "methods": methods})
    recovered = sum(1 for o in per_original if o["recovered"])
    return {"per_original": per_original, "recovered": recovered, "total": len(per_original)}
