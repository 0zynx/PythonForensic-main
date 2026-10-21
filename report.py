"""Stage 6: write the forensic examination report (HTML) and a machine-readable results.json."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

CSS = """
@page{size:A4;margin:18mm 16mm 20mm 16mm}
*{box-sizing:border-box}
body{font-family:Georgia,"Times New Roman",serif;color:#111;background:#fff;margin:0 auto;max-width:900px;
  padding:2rem 2.2rem;font-size:11pt;line-height:1.45}
h1{font-size:19pt;margin:0 0 .2rem 0;padding-bottom:.4rem;border-bottom:3px double #111}
.ref{font-size:10pt;color:#333;margin-bottom:1.2rem}
h2{font-size:12pt;margin:1.5rem 0 .5rem 0;padding-bottom:.2rem;border-bottom:1px solid #111;text-transform:uppercase;letter-spacing:.04em}
p{margin:.4rem 0}
table{border-collapse:collapse;width:100%;margin:.4rem 0 .8rem 0;font-size:9.5pt}
th,td{border:1px solid #777;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#ececec}
table.kv th{width:28%;background:#f3f3f3}
.mono{font-family:Consolas,"Courier New",monospace;font-size:8.5pt;word-break:break-all}
ol{margin:.3rem 0 .3rem 1.2rem;padding:0}li{margin:.2rem 0}
@media print{body{padding:0;max-width:none}}
"""

RESULT = {
    "intact": "Structure intact",
    "wiped_zeros": "Data erased (zero-filled)",
    "wiped_pattern": "Data overwritten with a constant pattern",
    "overwritten": "Data replaced with random content",
    "corrupt_or_replaced": "No valid file signature; content corrupt or replaced",
    "unverified": "File type not examined",
    "empty": "Empty file",
}
BAD = {"wiped_zeros", "wiped_pattern", "overwritten", "corrupt_or_replaced", "empty"}


def _kv(rows: list[tuple[str, str]]) -> str:
    return '<table class="kv">' + "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows) + "</table>"


def _result(r: dict[str, Any]) -> str:
    status = r.get("content_status")
    if status is None:
        text = {True: "Decoded successfully", False: "Failed to decode", None: "Not examined"}[r.get("valid")]
    else:
        text = RESULT.get(status, escape(str(status)))
    notes = []
    if r.get("type_mismatch"):
        notes.append(f"Extension does not match content (content is {escape(str(r.get('detected_type')))})")
    if r.get("storage_reused"):
        notes.append("Storage since reallocated to another file; content unreliable")
    return text + "".join(f"<br>{n}" for n in notes)


def _reference(r: dict[str, Any]) -> str:
    if "matches_original" not in r:
        return "&ndash;"
    return f"Identical to {escape(r['matches_original'])}" if r["matches_original"] else "No matching reference"


def _findings(results: list[dict[str, Any]], prefix: str, from_records: bool, has_ref: bool) -> tuple[str, str]:
    rows, hashes = [], []
    for i, r in enumerate(results, 1):
        ex = f"{prefix}-{i:02d}"
        name = escape(r.get("original_path", r["file"]) if from_records else r["file"])
        cells = [ex, name, escape(str(r.get("type", ""))) or "&ndash;", f"{r['size']:,}", f"{r['offset']:,}"]
        if from_records:
            cells.append(escape(str(r["modified_utc"])) if r.get("modified_utc") else "&ndash;")
        cells.append(_result(r))
        if has_ref:
            cells.append(_reference(r))
        rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        hashes.append(f'<tr><td>{ex}</td><td class="mono">{r["sha256"]}</td><td class="mono">{r["md5"]}</td></tr>')
    head = ["Exhibit", "Original path" if from_records else "Recovered file", "Type", "Size (bytes)", "Image offset"]
    if from_records:
        head.append("Last modified (UTC)")
    head.append("Result")
    if has_ref:
        head.append("Reference comparison")
    table = "<table><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr>" + "".join(rows) + "</table>"
    return table, "".join(hashes)


def write_report(out_dir: Path | str, summary: dict[str, Any], fs_results: list[dict[str, Any]],
                 carved: list[dict[str, Any]], verification: dict[str, Any] | None,
                 image_unchanged: bool) -> Path:
    out_dir = Path(out_dir)
    utc_now = datetime.now(timezone.utc)
    local_now = utc_now.astimezone()
    generated = f"{utc_now:%Y-%m-%d %H:%M} UTC ({local_now:%H:%M} local, UTC{local_now:%z})"
    sha = str(summary.get("image_sha256") or "")
    case_id = f"DFT-{utc_now:%Y%m%d}-{sha[:8].upper() or 'UNKNOWN'}"
    image_name = Path(str(summary.get("image_path", ""))).name
    fs_types = ", ".join(str(t["type"]) for t in summary.get("fs_types", []))
    has_ref = verification is not None

    integrity = ("The image was hashed again after the examination. The value is identical to the acquisition hash; "
                 "the image was opened read-only and was not modified." if image_unchanged else
                 "WARNING: the image hash after the examination differs from the acquisition hash.")

    body = [
        f"<h1>Forensic Examination Report</h1><div class='ref'>Case reference: {case_id} &nbsp;|&nbsp; Date: {generated}</div>",
        "<h2>1. Evidence examined</h2>" + _kv([
            ("Item", f'Disk image <span class="mono">{escape(image_name)}</span> (raw)'),
            ("SHA-256 at acquisition", f'<span class="mono">{escape(sha)}</span>'),
            ("File system", escape(fs_types) if fs_types else "None identified"),
            ("Existing / deleted files listed", f"{summary.get('allocated_files', 0)} / {summary.get('deleted_files', 0)}"),
        ]),
    ]
    n = 2
    hash_rows = ""
    if fs_results:
        t, h = _findings(fs_results, "R", True, has_ref)
        body.append(f"<h2>{n}. Files recovered from file-system records</h2>{t}")
        hash_rows += h
        n += 1
    if carved:
        t, h = _findings(carved, "C", False, has_ref)
        body.append(f"<h2>{n}. Files recovered by signature carving</h2>{t}")
        hash_rows += h
        n += 1
    if not fs_results and not carved:
        body.append(f"<h2>{n}. Findings</h2><p>No files were recovered.</p>")
        n += 1
    if hash_rows:
        body.append(f"<h2>{n}. Hash values</h2><table><tr><th>Exhibit</th><th>SHA-256</th><th>MD5</th></tr>{hash_rows}</table>")
        n += 1
    if has_ref:
        per = "".join(
            f"<tr><td>{escape(o['original'])}</td><td>{'Recovered, identical' if o['recovered'] else 'Not recovered'}</td>"
            f"<td>{escape(', '.join(o['methods']) or '–')}</td></tr>" for o in verification["per_original"])
        body.append(f"<h2>{n}. Comparison with reference files</h2><p>{verification['recovered']} of "
                    f"{verification['total']} reference files were found in the image as byte-for-byte identical copies.</p>"
                    f"<table><tr><th>Reference file</th><th>Result</th><th>Recovered by</th></tr>{per}</table>")
        n += 1
    body.append(f"<h2>{n}. Evidence integrity</h2><p>{integrity}</p>")

    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Examination Report {case_id}</title>'
            f"<style>{CSS}</style></head><body>{''.join(body)}</body></html>")
    path = out_dir / "report.html"
    path.write_text(html, encoding="utf-8")
    (out_dir / "results.json").write_text(
        json.dumps({"case_reference": case_id, "summary": summary, "recovered_from_records": fs_results,
                    "carved": carved, "verification": verification, "image_unchanged": image_unchanged}, indent=2),
        encoding="utf-8")
    return path