# Image Ingestion & File System Parsing

A read-only Python 3.11 ingestion stage for raw/dd and optional E01 disk images. It records the image SHA-256, discovers partitions and file systems with pytsk3, and writes a file index for downstream recovery stages.

## Setup

### macOS

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If pip reports that no compatible `pytsk3` wheel is available, use Python 3.11. On macOS, install the Xcode command line tools with `xcode-select --install` and retry the install. The pinned release provides Python 3.11 wheels for current Intel and Apple Silicon macOS environments.

### Windows 10/11 (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, run the venv interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use a 64-bit Python 3.11 installation. If pip says there is no compatible `pytsk3` wheel, install Python 3.11 and upgrade pip before retrying; the pinned release includes a Windows x64 Python 3.11 wheel. E01 support is optional; install `pyewf` separately if needed. Raw `.dd` images do not require it.

## Run

```sh
python main.py --image /path/to/evidence.dd --out-dir /path/to/index-output
```

Standalone PNG files can also be checked directly:

```sh
python main.py --image /path/to/photo.png --out-dir /path/to/check-output
```

This writes `image_check.json` with the detected format, validity, dimensions, color mode, and any validation error. Corrupt PNGs produce a report and a nonzero exit code. This check does not create a disk-file index; JPG files are not supported by this PNG-only check.

The image is opened read-only. No mount, administrator privileges, or loop device is used. E01 files are read through `pyewf` when installed. Without it, the CLI explains that E01 requires libewf/pyewf and that raw `.dd` works without it.

## Index schema

`file_index.csv` and `file_index.json` contain the same rows and these columns, in this order:

| Column | Meaning |
| --- | --- |
| `partition_index` | Zero-based index from the discovered volume table; `0` for a bare file-system image. |
| `path` | Full image path using `/`; orphaned entries begin with `<orphan>/`. Names are preserved as found, not sanitized. |
| `name` | Name exactly as decoded from the image (invalid UTF-8 is replaced). |
| `inode` | File-system metadata address (inode/MFT entry number). |
| `type` | `file` or `dir`. |
| `size` | Logical size in bytes. |
| `created_utc` | Creation timestamp in ISO 8601 UTC, or JSON null when unavailable. |
| `modified_utc` | Modification timestamp in ISO 8601 UTC, or JSON null when unavailable. |
| `accessed_utc` | Access timestamp in ISO 8601 UTC, or JSON null when unavailable. |
| `changed_utc` | Metadata-change timestamp in ISO 8601 UTC, or JSON null when unavailable. |
| `status` | `allocated` only when both TSK name and metadata flags mark the entry allocated; otherwise `deleted`. |
| `data_runs` | JSON array of byte ranges: `[{"start_offset": 123, "length": 4096}]`. Offsets are absolute from the start of the image; sparse runs have a null `start_offset`. Empty when TSK exposes no runs. |

CSV stores `data_runs` as compact JSON in one field, and timestamps/unknown values as empty fields. JSON preserves arrays and nulls as native JSON values. The carving stage should use `data_runs` for physical extents and `path`, `inode`, `partition_index`, and `status` as file identity/context; this stage does not sanitize names or hash file contents.

`summary.json` records `image_path`, `image_sha256`, `partitions_found`, `fs_types`, and counts `total_files`, `allocated_files`, and `deleted_files`. File counts exclude directory rows.

## Tests

```sh
python -m pytest
```

The GitHub Actions workflow runs the same tests on `macos-latest` and `windows-latest` with Python 3.11.
