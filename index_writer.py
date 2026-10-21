"""Write the stable downstream file-index formats."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

INDEX_COLUMNS = (
    "partition_index",
    "path",
    "name",
    "inode",
    "type",
    "size",
    "created_utc",
    "modified_utc",
    "accessed_utc",
    "changed_utc",
    "status",
    "data_runs",
)


def write_index(
    output_dir: Path,
    rows: Iterable[Mapping[str, Any]],
    summary: Mapping[str, Any],
) -> None:
    """Write matching CSV and JSON indexes and the run summary."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    normalized_rows = [
        {column: row.get(column) for column in INDEX_COLUMNS} for row in rows
    ]

    with (destination / "file_index.csv").open(
        "w", encoding="utf-8", newline=""
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=INDEX_COLUMNS,
            extrasaction="raise",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in normalized_rows:
            csv_row = dict(row)
            csv_row["data_runs"] = json.dumps(
                csv_row["data_runs"], ensure_ascii=False, separators=(",", ":")
            )
            writer.writerow(csv_row)

    with (destination / "file_index.json").open(
        "w", encoding="utf-8", newline="\n"
    ) as json_file:
        json.dump(normalized_rows, json_file, ensure_ascii=False, indent=2)
        json_file.write("\n")

    with (destination / "summary.json").open(
        "w", encoding="utf-8", newline="\n"
    ) as summary_file:
        json.dump(dict(summary), summary_file, ensure_ascii=False, indent=2)
        summary_file.write("\n")
