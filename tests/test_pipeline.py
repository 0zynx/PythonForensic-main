from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest
from PIL import Image

from fs_parser import parse_image
from image_file_checker import inspect_png
from image_loader import load_image
from index_writer import INDEX_COLUMNS, write_index
from main import _build_summary, main

DATA_DIR = Path(__file__).parent / "data"
FIXTURE = DATA_DIR / "fat12.img"


def test_cli_validates_standalone_png(tmp_path: Path) -> None:
    png_path = tmp_path / "sample.PNG"
    Image.new("RGB", (3, 2), color="red").save(png_path)

    result = main(["--image", str(png_path), "--out-dir", str(tmp_path / "out")])

    assert result == 0
    report = json.loads(
        (tmp_path / "out" / "image_check.json").read_text(encoding="utf-8")
    )
    assert report["valid"] is True
    assert report["format"] == "PNG"
    assert (report["width"], report["height"]) == (3, 2)


def test_cli_reports_corrupt_png(tmp_path: Path) -> None:
    png_path = tmp_path / "broken.png"
    png_path.write_bytes(b"not a png")

    result = main(["--image", str(png_path), "--out-dir", str(tmp_path / "out")])

    assert result == 1
    report = json.loads(
        (tmp_path / "out" / "image_check.json").read_text(encoding="utf-8")
    )
    assert report["valid"] is False
    assert report["error"]


def test_png_checker_rejects_non_png_content(tmp_path: Path) -> None:
    renamed_jpeg = tmp_path / "renamed.png"
    Image.new("RGB", (2, 2), color="blue").save(renamed_jpeg, format="JPEG")

    report = inspect_png(renamed_jpeg)

    assert report["valid"] is False
    assert report["format"] == "JPEG"


def test_e01_without_pyewf_has_a_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image_path = tmp_path / "evidence.E01"
    image_path.write_bytes(b"optional E01 test")
    monkeypatch.setitem(sys.modules, "pyewf", None)

    with pytest.raises(
        RuntimeError, match="E01 images require libewf and the optional pyewf"
    ):
        load_image(image_path)


def test_bare_fat_image_is_indexed_and_hashed() -> None:
    with FIXTURE.open("rb") as image_file:
        expected_hash = hashlib.sha256(image_file.read()).hexdigest()

    loaded = load_image(FIXTURE)
    try:
        parsed = parse_image(loaded)
        assert loaded.sha256 == expected_hash
        assert parsed.partitions_found[0]["byte_offset"] == 0
        assert len(parsed.fs_types) == 1
        assert "FAT" in str(parsed.fs_types[0]["type"]).upper()
        target = next(row for row in parsed.rows if row["name"] == "HELLO.TXT")
        assert target["path"] == "/HELLO.TXT"
        assert target["type"] == "file"
        assert target["size"] == len(b"forensic fixture\n")
        assert target["status"] == "allocated"
        assert target["data_runs"] == [{"start_offset": 16896, "length": 512}]
        assert any(row["type"] == "file" and row["status"] == "deleted" for row in parsed.rows)
    finally:
        loaded.close()


def test_csv_and_json_have_the_same_index_rows(tmp_path: Path) -> None:
    loaded = load_image(FIXTURE)
    try:
        parsed = parse_image(loaded)
        summary = _build_summary(loaded, parsed)
        write_index(tmp_path, parsed.rows, summary)
    finally:
        loaded.close()

    json_rows = json.loads((tmp_path / "file_index.json").read_text(encoding="utf-8"))
    with (tmp_path / "file_index.csv").open(
        "r", encoding="utf-8", newline=""
    ) as csv_file:
        reader = csv.DictReader(csv_file)
        assert tuple(reader.fieldnames or ()) == INDEX_COLUMNS
        csv_rows = list(reader)

    assert len(csv_rows) == len(json_rows)
    for csv_row, json_row in zip(csv_rows, json_rows, strict=True):
        assert csv_row.keys() == json_row.keys()
        for key in INDEX_COLUMNS:
            if key == "data_runs":
                assert json.loads(csv_row[key]) == json_row[key]
            elif key in {"partition_index", "inode", "size"}:
                assert int(csv_row[key]) == json_row[key]
            elif key in {"created_utc", "modified_utc", "accessed_utc", "changed_utc"}:
                assert csv_row[key] == (json_row[key] or "")
            else:
                assert csv_row[key] == json_row[key]

    summary_data = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary_data["image_sha256"] == loaded.sha256
    assert summary_data["total_files"] >= 1
