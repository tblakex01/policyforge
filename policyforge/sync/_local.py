"""Handle-checked local policy files for cloud sync."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

from policyforge.sync.base import MAX_POLICY_BYTES


class UnsafeLocalPathError(ValueError):
    """A local policy path cannot be proven to stay beneath the sync root."""


def _open_file_path(fd: int) -> Path:
    """Resolve an open file by handle, rather than by its mutable pathname."""
    if os.name == "nt":
        import ctypes
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_path = kernel32.GetFinalPathNameByHandleW
        get_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        get_path.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_path(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise UnsafeLocalPathError("Cannot resolve open file handle")
        actual = buffer.value
        if actual.startswith("\\\\?\\UNC\\"):
            actual = "\\\\" + actual[8:]
        elif actual.startswith("\\\\?\\"):
            actual = actual[4:]
        return Path(actual).resolve(strict=True)
    if sys.platform == "linux":
        return Path(os.readlink(f"/proc/self/fd/{fd}")).resolve(strict=True)
    if sys.platform == "darwin":
        import fcntl

        get_path = getattr(fcntl, "F_GETPATH", None)
        if get_path is not None:
            result = fcntl.fcntl(fd, get_path, b"\0" * 4096)
            return Path(result.split(b"\0", 1)[0].decode()).resolve(strict=True)
    raise UnsafeLocalPathError("Cannot verify open file location on this platform")


class LocalPolicyStore:
    """Read and install policy files without following paths outside a fixed root."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)

    def _path(self, relative: Path) -> Path:
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise UnsafeLocalPathError(f"Unsafe local path: {relative}")
        return self.root / relative

    def _reject_links(self, path: Path) -> None:
        relative = path.relative_to(self.root)
        current = self.root
        for component in relative.parts:
            current /= component
            try:
                details = current.lstat()
            except FileNotFoundError:
                continue
            attributes = getattr(details, "st_file_attributes", 0)
            if stat.S_ISLNK(details.st_mode) or attributes & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ):
                raise UnsafeLocalPathError(f"Unsafe local path contains a link: {current}")
            if not current.resolve(strict=True).is_relative_to(self.root):
                raise UnsafeLocalPathError(f"Unsafe local path escapes root: {current}")

    def _open_checked(self, path: Path, flags: int) -> int:
        self._reject_links(path)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            actual = _open_file_path(fd)
            details = os.fstat(fd)
            if not actual.is_relative_to(self.root):
                raise UnsafeLocalPathError(f"Unsafe local path escapes root: {path}")
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise UnsafeLocalPathError(f"Unsafe local path is not a regular file: {path}")
            self._reject_links(path)
            return fd
        except Exception:
            os.close(fd)
            raise

    def snapshot(self, relative: Path, staged: Path) -> Path:
        """Copy a verified local file to private staging before cloud upload."""
        path = self._path(relative)
        fd = self._open_checked(path, os.O_RDONLY)
        with os.fdopen(fd, "rb") as source, staged.open("xb") as destination:
            copied = 0
            while chunk := source.read(64 * 1024):
                copied += len(chunk)
                if copied > MAX_POLICY_BYTES:
                    raise ValueError("Local policy size exceeds maximum")
                destination.write(chunk)
        return staged

    def validate(self, relative: Path) -> None:
        """Reject linked or escaping path components before local access."""
        self._reject_links(self._path(relative))

    def install(self, relative: Path, staged: Path) -> None:
        """Write a staged download through a verified local file handle."""
        path = self._path(relative)
        current = self.root
        for component in relative.parts[:-1]:
            current /= component
            self._reject_links(current)
            current.mkdir(exist_ok=True)
            self._reject_links(current)
        self._reject_links(path)
        flags = os.O_WRONLY if path.exists() else os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = self._open_checked(path, flags)
        with os.fdopen(fd, "wb") as destination, staged.open("rb") as source:
            destination.truncate(0)
            shutil.copyfileobj(source, destination)
            destination.flush()
            os.fsync(destination.fileno())
