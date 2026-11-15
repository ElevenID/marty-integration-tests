"""Bounded file and tar readers for immutable verifier artifacts.

Keep preflight, inode/mtime checks, allocation caps and raw tar validation together.
These helpers do not load images, invoke subprocesses or create evidence.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tarfile
from pathlib import Path
from typing import BinaryIO

MAX_TAR_SPECIAL_HEADER_BYTES = 64 * 1024


MAX_TOTAL_TAR_SPECIAL_HEADER_BYTES = 4 * 1024 * 1024


MAX_TAR_SPECIAL_HEADERS = 256


TAR_BLOCK_BYTES = 512


TAR_SPECIAL_HEADER_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.SOLARIS_XHDTYPE,
    }
)


# Python's tar reader does not consume data blocks for these supported types,
# even when a malformed raw header declares a non-zero size.
TAR_NON_DATA_HEADER_TYPES = frozenset(
    {
        tarfile.LNKTYPE,
        tarfile.SYMTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.DIRTYPE,
        tarfile.FIFOTYPE,
    }
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _bytes_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _preflight_regular_file(path: Path, *, label: str, maximum_bytes: int) -> int:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
    _require(0 < metadata.st_size <= maximum_bytes, f"{label} is too large or empty")
    return metadata.st_size


def _read_bounded_regular_file(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
    _require(0 < metadata.st_size <= maximum_bytes, f"{label} is too large or empty")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_dev == metadata.st_dev
            and opened.st_ino == metadata.st_ino
            and opened.st_size == metadata.st_size,
            f"{label} changed before it was read",
        )
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            _require(bool(chunk), f"{label} changed while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        _require(handle.read(1) == b"", f"{label} changed while it was read")
        after = os.fstat(handle.fileno())
        current = path.lstat()
    raw = b"".join(chunks)
    _require(
        len(raw) == metadata.st_size
        and stat.S_ISREG(after.st_mode)
        and after.st_dev == opened.st_dev
        and after.st_ino == opened.st_ino
        and after.st_size == opened.st_size
        and after.st_mtime_ns == opened.st_mtime_ns
        and stat.S_ISREG(current.st_mode)
        and current.st_dev == opened.st_dev
        and current.st_ino == opened.st_ino
        and current.st_size == opened.st_size
        and current.st_mtime_ns == opened.st_mtime_ns,
        f"{label} changed while it was read",
    )
    return raw


def _digest_bounded_regular_file(path: Path, *, label: str, maximum_bytes: int) -> str:
    metadata = path.lstat()
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
    _require(0 < metadata.st_size <= maximum_bytes, f"{label} is too large or empty")
    digest = hashlib.sha256()
    copied = 0
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_dev == metadata.st_dev
            and opened.st_ino == metadata.st_ino
            and opened.st_size == metadata.st_size,
            f"{label} changed before it was hashed",
        )
        remaining = metadata.st_size
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            _require(bool(chunk), f"{label} changed while it was hashed")
            copied += len(chunk)
            remaining -= len(chunk)
            digest.update(chunk)
        _require(handle.read(1) == b"", f"{label} changed while it was hashed")
        after = os.fstat(handle.fileno())
        current = path.lstat()
    _require(
        copied == metadata.st_size
        and stat.S_ISREG(after.st_mode)
        and after.st_dev == opened.st_dev
        and after.st_ino == opened.st_ino
        and after.st_size == opened.st_size
        and after.st_mtime_ns == opened.st_mtime_ns
        and stat.S_ISREG(current.st_mode)
        and current.st_dev == opened.st_dev
        and current.st_ino == opened.st_ino
        and current.st_size == opened.st_size
        and current.st_mtime_ns == opened.st_mtime_ns,
        f"{label} changed while it was hashed",
    )
    return f"sha256:{digest.hexdigest()}"


def _tar_number(field: bytes, *, label: str) -> int:
    try:
        value = tarfile.nti(field)
    except tarfile.InvalidHeaderError as exc:
        raise ValueError(f"{label} contains a malformed tar size") from exc
    _require(value >= 0, f"{label} contains a negative tar size")
    return value


def _validate_pax_metadata(payload: bytes, *, label: str) -> None:
    position = 0
    while position < len(payload):
        if payload[position:] == bytes(len(payload) - position):
            break
        separator = payload.find(b" ", position)
        _require(separator > position, f"{label} contains malformed PAX metadata")
        length_bytes = payload[position:separator]
        _require(length_bytes.isdigit(), f"{label} contains malformed PAX metadata")
        length = int(length_bytes)
        end = position + length
        _require(length >= 5 and end <= len(payload), f"{label} contains malformed PAX metadata")
        record = payload[separator + 1 : end]
        _require(record.endswith(b"\n") and b"=" in record, f"{label} contains malformed PAX metadata")
        key, value = record[:-1].split(b"=", 1)
        _require(bool(key), f"{label} contains malformed PAX metadata")
        _require(not key.startswith(b"GNU.sparse."), f"{label} contains unsupported sparse PAX metadata")
        if key == b"size":
            _require(value.isdigit(), f"{label} contains malformed PAX size metadata")
            # Candidate and layer caps fit in the ordinary tar size field. Reject
            # this unnecessary offset override instead of duplicating tarfile's
            # recursive local/global PAX precedence rules.
            raise ValueError(f"{label} contains unsupported PAX size metadata")
        position = end


def _scan_tar_headers(
    source: BinaryIO,
    *,
    stream_bytes: int,
    maximum_members: int,
    label: str,
) -> None:
    """Bound special tar metadata before tarfile can allocate it."""
    _require(
        stream_bytes % TAR_BLOCK_BYTES == 0,
        f"{label} contains a truncated tar block",
    )
    source.seek(0)
    offset = 0
    member_count = 0
    special_count = 0
    special_bytes = 0
    while offset + TAR_BLOCK_BYTES <= stream_bytes:
        source.seek(offset)
        header = source.read(TAR_BLOCK_BYTES)
        _require(len(header) == TAR_BLOCK_BYTES, f"{label} contains a truncated tar header")
        if header == bytes(TAR_BLOCK_BYTES):
            remaining = stream_bytes - offset - TAR_BLOCK_BYTES
            _require(
                remaining >= TAR_BLOCK_BYTES,
                f"{label} is missing the canonical tar end-of-archive",
            )
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                _require(
                    bool(chunk) and not any(chunk),
                    f"{label} contains non-zero data after its end-of-archive",
                )
                remaining -= len(chunk)
            return
        member_count += 1
        _require(
            member_count <= maximum_members + MAX_TAR_SPECIAL_HEADERS,
            f"{label} contains too many raw tar headers",
        )
        raw_size = _tar_number(header[124:136], label=label)
        typeflag = header[156:157] or tarfile.REGTYPE
        _require(typeflag != tarfile.GNUTYPE_SPARSE, f"{label} contains unsupported GNU sparse metadata")
        if typeflag in TAR_SPECIAL_HEADER_TYPES:
            special_count += 1
            special_bytes += raw_size
            _require(special_count <= MAX_TAR_SPECIAL_HEADERS, f"{label} contains too many special tar headers")
            _require(
                raw_size <= MAX_TAR_SPECIAL_HEADER_BYTES,
                f"{label} special tar header is too large",
            )
            _require(
                special_bytes <= MAX_TOTAL_TAR_SPECIAL_HEADER_BYTES,
                f"{label} aggregate special tar headers are too large",
            )
            payload_size = raw_size
        else:
            _require(
                typeflag not in TAR_NON_DATA_HEADER_TYPES or raw_size == 0,
                f"{label} non-data tar member declares a payload",
            )
            payload_size = raw_size
        padded_size = ((payload_size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES
        next_offset = offset + TAR_BLOCK_BYTES + padded_size
        _require(next_offset <= stream_bytes, f"{label} contains a truncated tar member")
        if typeflag in {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE}:
            payload = source.read(raw_size)
            _require(len(payload) == raw_size, f"{label} contains truncated PAX metadata")
            _validate_pax_metadata(payload, label=label)
        offset = next_offset
    raise ValueError(f"{label} is missing the canonical tar end-of-archive")
