"""Partition discovery and resilient file-system indexing with pytsk3."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytsk3

from image_loader import LoadedImage

LOGGER = logging.getLogger(__name__)
MAX_ENTRIES = 1_000_000
MAX_DEPTH = 256
_ORPHAN_DIRECTORY_NAME = "$OrphanFiles"


@dataclass(frozen=True)
class ParsedIndex:
    """File records and image layout information discovered by the parser."""

    rows: list[dict[str, Any]]
    partitions_found: list[dict[str, int]]
    fs_types: list[dict[str, int | str]]


def _decode_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _timestamp(value: Any) -> str | None:
    if value is None or value == 0:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def _fs_type_name(fs_type: int) -> str:
    for constant_name in dir(pytsk3):
        if not constant_name.startswith("TSK_FS_TYPE_"):
            continue
        value = getattr(pytsk3, constant_name, None)
        if isinstance(value, int) and value == fs_type:
            return constant_name.removeprefix("TSK_FS_TYPE_")
    return f"UNKNOWN_{fs_type}"


def _find_partitions(image: Any) -> list[dict[str, int | bool]]:
    partitions: list[dict[str, int | bool]] = []
    try:
        volume = pytsk3.Volume_Info(image)
        sector_size = int(getattr(image.info, "sector_size", 512) or 512)
        for index, partition in enumerate(volume):
            start_sector = int(partition.start)
            length_sectors = int(partition.len)
            flags = int(partition.flags)
            partitions.append(
                {
                    "partition_index": index,
                    "start_sector": start_sector,
                    "length_sectors": length_sectors,
                    "byte_offset": start_sector * sector_size,
                    "is_metadata": bool(
                        flags & getattr(pytsk3, "TSK_VS_PART_FLAG_META", 0)
                    ),
                }
            )
    except Exception as exc:
        LOGGER.debug("No readable partition table; trying a bare file system: %s", exc)

    if not partitions:
        partitions.append(
            {
                "partition_index": 0,
                "start_sector": 0,
                "length_sectors": 0,
                "byte_offset": 0,
                "is_metadata": False,
            }
        )
    return partitions


def _entry_status(name_flags: int, meta_flags: int, force_deleted: bool) -> str:
    if force_deleted:
        return "deleted"
    name_alloc = getattr(pytsk3, "TSK_FS_NAME_FLAG_ALLOC", 0)
    name_unalloc = getattr(pytsk3, "TSK_FS_NAME_FLAG_UNALLOC", 0)
    meta_alloc = getattr(pytsk3, "TSK_FS_META_FLAG_ALLOC", 0)
    meta_unalloc = getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 0)
    if name_flags & name_unalloc or meta_flags & meta_unalloc:
        return "deleted"
    if name_flags & name_alloc and meta_flags & meta_alloc:
        return "allocated"
    return "deleted"


def _data_runs(entry: Any, fs: Any, fs_offset: int) -> list[dict[str, int | None]]:
    runs: list[dict[str, int | None]] = []
    sparse_flag = getattr(pytsk3, "TSK_FS_ATTR_RUN_FLAG_SPARSE", 0)
    block_size = int(fs.info.block_size)
    try:
        file_object = entry.as_file() if hasattr(entry, "as_file") else entry
        for attribute in file_object:
            for run in attribute:
                length = int(run.len) * block_size
                is_sparse = bool(int(run.flags) & sparse_flag) if sparse_flag else False
                start_offset = (
                    None
                    if is_sparse or int(run.addr) < 0
                    else fs_offset + int(run.addr) * block_size
                )
                runs.append({"start_offset": start_offset, "length": length})
    except Exception as exc:
        LOGGER.debug("Data runs unavailable for an entry: %s", exc)
    return runs


def _parse_filesystem(
    fs: Any,
    partition_index: int,
    fs_offset: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    visited_directories: set[int] = set()
    entry_count = 0
    orphan_inode = getattr(pytsk3, "TSK_FS_ORPHANDIR_INUM", None)

    def walk(directory: Any, parent_path: str, depth: int, orphan: bool) -> None:
        nonlocal entry_count
        if depth > MAX_DEPTH:
            LOGGER.warning("Directory depth limit reached below %s", parent_path)
            return

        try:
            for entry in directory:
                if entry_count >= MAX_ENTRIES:
                    LOGGER.warning("Entry limit (%s) reached; stopping this file system", MAX_ENTRIES)
                    return
                entry_count += 1
                try:
                    name_info = entry.info.name
                    name = _decode_name(name_info.name)
                    if name in {".", ".."}:
                        continue
                    meta = entry.info.meta
                    if meta is None:
                        LOGGER.warning("Skipping entry with missing metadata: %r", name)
                        continue

                    inode = int(meta.addr)
                    is_orphan_container = name == _ORPHAN_DIRECTORY_NAME or (
                        orphan_inode is not None and inode == orphan_inode
                    )
                    is_orphan_record = bool(
                        int(meta.flags)
                        & getattr(pytsk3, "TSK_FS_META_FLAG_ORPHAN", 0)
                    )
                    full_path = (
                        f"{parent_path.rstrip('/')}/{name}"
                        if parent_path != "/"
                        else f"/{name}"
                    )
                    is_directory = is_orphan_container or meta.type == getattr(
                        pytsk3, "TSK_FS_META_TYPE_DIR", object()
                    )
                    if is_orphan_record and not orphan:
                        full_path = f"<orphan>/{name}"
                    status = _entry_status(
                        int(name_info.flags),
                        int(meta.flags),
                        orphan or is_orphan_container or is_orphan_record,
                    )
                    rows.append(
                        {
                            "partition_index": partition_index,
                            "path": full_path,
                            "name": name,
                            "inode": inode,
                            "type": "dir" if is_directory else "file",
                            "size": int(meta.size or 0),
                            "created_utc": _timestamp(getattr(meta, "crtime", None)),
                            "modified_utc": _timestamp(getattr(meta, "mtime", None)),
                            "accessed_utc": _timestamp(getattr(meta, "atime", None)),
                            "changed_utc": _timestamp(getattr(meta, "ctime", None)),
                            "status": status,
                            "data_runs": _data_runs(entry, fs, fs_offset),
                        }
                    )

                    if is_directory:
                        if inode in visited_directories:
                            LOGGER.warning("Directory cycle or repeat detected at %s", full_path)
                            continue
                        visited_directories.add(inode)
                        try:
                            child_dir = fs.open_dir(inode=inode)
                            child_path = (
                                "<orphan>" if is_orphan_container else full_path
                            )
                            walk(
                                child_dir,
                                child_path,
                                depth + 1,
                                orphan or is_orphan_container or is_orphan_record,
                            )
                        except Exception as exc:
                            LOGGER.warning("Cannot open directory %s: %s", full_path, exc)
                except Exception:
                    LOGGER.exception("Skipping malformed directory entry")
        except Exception:
            LOGGER.exception("Directory walk failed below %s", parent_path)

    try:
        root = fs.open_dir(path="/")
    except Exception as exc:
        LOGGER.warning("Unable to open file-system root: %s", exc)
        return rows

    try:
        root_meta = root.info.meta
        if root_meta is not None:
            visited_directories.add(int(root_meta.addr))
    except Exception:
        pass
    walk(root, "/", 0, False)

    if orphan_inode is not None and int(orphan_inode) not in visited_directories:
        try:
            orphan_dir = fs.open_dir(inode=orphan_inode)
            walk(orphan_dir, "<orphan>", 0, True)
        except Exception as exc:
            LOGGER.debug("No orphan directory available: %s", exc)
    return rows


def parse_image(loaded_image: LoadedImage) -> ParsedIndex:
    """Enumerate file systems and return file and directory records."""
    partitions = _find_partitions(loaded_image.image)
    partition_summary = [
        {
            "partition_index": int(partition["partition_index"]),
            "start_sector": int(partition["start_sector"]),
            "length_sectors": int(partition["length_sectors"]),
            "byte_offset": int(partition["byte_offset"]),
        }
        for partition in partitions
    ]
    rows: list[dict[str, Any]] = []
    fs_types: list[dict[str, int | str]] = []

    for partition in partitions:
        if partition["is_metadata"]:
            continue
        partition_index = int(partition["partition_index"])
        fs_offset = int(partition["byte_offset"])
        try:
            fs = pytsk3.FS_Info(loaded_image.image, offset=fs_offset)
        except Exception as exc:
            LOGGER.info("Skipping non-file-system partition %s: %s", partition_index, exc)
            continue

        type_name = _fs_type_name(int(fs.info.ftype))
        fs_types.append({"partition_index": partition_index, "type": type_name})
        LOGGER.info("Partition %s: file system %s", partition_index, type_name)
        rows.extend(_parse_filesystem(fs, partition_index, fs_offset))

    return ParsedIndex(rows, partition_summary, fs_types)
