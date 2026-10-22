
"""Read-only disk image loading and evidence hashing."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytsk3

LOGGER = logging.getLogger(__name__)
HASH_CHUNK_SIZE = 1024 * 1024
EWF_SUFFIXES = {".e01", ".ex01"}


@dataclass
class LoadedImage:
    """An open TSK image and its evidence-file digest."""

    path: Path
    image: Any
    sha256: str
    _close_callback: Callable[[], None] | None = None

    def close(self) -> None:
        if self._close_callback is not None:
            self._close_callback()
            self._close_callback = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as image_file:
        while chunk := image_file.read(HASH_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _open_ewf(path: Path) -> tuple[Any, Callable[[], None]]:
    try:
        import pyewf
    except ImportError as exc:
        raise RuntimeError(
            "E01 images require libewf and the optional pyewf package."
        ) from exc

    segments = pyewf.glob(str(path))
    if not segments:
        raise FileNotFoundError(f"No E01 segments found for {path}")

    handle = pyewf.handle()
    handle.open(segments)

    class EwfImage(pytsk3.Img_Info):
        def __init__(self) -> None:
            self._ewf_handle = handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self) -> int:
            return self._ewf_handle.get_media_size()

    try:
        return EwfImage(), handle.close
    except Exception:
        handle.close()
        raise


class SegmentedRawImage(pytsk3.Img_Info):
    """Read sequential raw image segments as one logical image."""

    def __init__(self, paths: list[Path]) -> None:
        self._paths = paths
        self._sizes = [p.stat().st_size for p in paths]
        self._total_size = sum(self._sizes)
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def get_size(self) -> int:
        return self._total_size

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Negative image offset or read size")
        if offset >= self._total_size or size == 0:
            return b""

        remaining = min(size, self._total_size - offset)
        result = bytearray()
        segment_start = 0

        for path, segment_size in zip(self._paths, self._sizes):
            segment_end = segment_start + segment_size

            if offset < segment_end and remaining:
                local_offset = max(0, offset - segment_start)
                take = min(segment_size - local_offset, remaining)

                with path.open("rb") as stream:
                    stream.seek(local_offset)
                    chunk = stream.read(take)

                result.extend(chunk)
                offset += len(chunk)
                remaining -= len(chunk)

                if len(chunk) != take:
                    raise OSError(f"Short read from image segment: {path}")

            segment_start = segment_end
            if remaining == 0:
                break

        return bytes(result)


def _segment_paths(path: Path) -> list[Path] | None:
    """Return consecutive .001, .002... files if this is a split raw image."""
    suffix = path.suffix.casefold()
    if len(suffix) != 4 or not suffix[1:].isdigit():
        return None

    number = int(suffix[1:])
    if number != 1:
        return None

    paths = []
    index = 1
    while True:
        segment = path.with_suffix(f".{index:03d}")
        if not segment.is_file():
            break
        paths.append(segment)
        index += 1

    return paths if len(paths) > 1 else None


def _sha256_segments(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        with path.open("rb") as stream:
            while chunk := stream.read(HASH_CHUNK_SIZE):
                digest.update(chunk)
    return digest.hexdigest()


def load_image(image_path: Path) -> LoadedImage:
    """Open a raw, split-raw, or supported E01 image read-only."""
    path = Path(image_path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"Image path is not a file: {path}")

    if path.suffix.casefold() in EWF_SUFFIXES:
        digest = _sha256_file(path)
        LOGGER.info("Image SHA-256: %s  %s", digest, path)
        image, close_callback = _open_ewf(path)
        return LoadedImage(path, image, digest, close_callback)

    segments = _segment_paths(path)
    if segments:
        digest = _sha256_segments(segments)
        LOGGER.info(
            "Split raw image: %d segments, %d bytes total",
            len(segments),
            sum(p.stat().st_size for p in segments),
        )
        image = SegmentedRawImage(segments)
    else:
        digest = _sha256_file(path)
        image = pytsk3.Img_Info(str(path))

    LOGGER.info("Image SHA-256: %s  %s", digest, path)
    return LoadedImage(path, image, digest)
