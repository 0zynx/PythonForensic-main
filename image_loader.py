"""Read-only disk image loading and evidence hashing."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytsk3

LOGGER = logging.getLogger(__name__)
_HASH_CHUNK_SIZE = 1024 * 1024
_EWF_SUFFIXES = {".e01", ".ex01"}


@dataclass
class LoadedImage:
    """An open TSK image and its evidence-file digest."""

    path: Path
    image: Any
    sha256: str
    _close_callback: Callable[[], None] | None = None

    def close(self) -> None:
        """Release any resources held by the image backend."""
        if self._close_callback is not None:
            self._close_callback()
            self._close_callback = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as image_file:
        while chunk := image_file.read(_HASH_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _open_ewf(path: Path) -> tuple[Any, Callable[[], None]]:
    try:
        import pyewf
    except ImportError as exc:
        raise RuntimeError(
            "E01 images require libewf and the optional pyewf Python package; "
            "raw .dd images work without it."
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


def load_image(image_path: Path) -> LoadedImage:
    """Open a raw image read-only and record its SHA-256 digest.

    E01 images are supported when the optional ``pyewf`` package is installed.
    """
    path = Path(image_path).expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"Image path is not a file: {path}")

    digest = _sha256_file(path)
    LOGGER.info("Image SHA-256: %s  %s", digest, path)

    if path.suffix.casefold() in _EWF_SUFFIXES:
        image, close_callback = _open_ewf(path)
        return LoadedImage(path, image, digest, close_callback)

    try:
        image = pytsk3.Img_Info(str(path))
    except Exception as exc:
        raise RuntimeError(f"Unable to open raw image read-only: {path}") from exc
    return LoadedImage(path, image, digest)
