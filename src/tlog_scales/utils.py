import hashlib
import base64
import os
import tempfile

from pathlib import Path

import requests

try:
    from .__about__ import __version__ as TLOG_SCALES_VERSION # ty: ignore[unresolved-import,unused-ignore-comment]
except ImportError:
    TLOG_SCALES_VERSION = "unknown"


def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64dec(text: str) -> bytes:
    return base64.b64decode(text)


def sha256(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers['User-Agent'] = f'tlog-scales/{TLOG_SCALES_VERSION}'

    return session


def atomic_write(path: Path, data: bytes) -> None:
    path = path.resolve()

    # Keep a reference to the parent dir for the duration of the operation. Tessera argues[1]:
    #
    #   This dance ensures that the inode of the specified directory cannot be
    #   evicted from the kernel inode cache while the operation is underway,
    #   and so any error which occurs while updating metadata about a file
    #   operation which happens _within_ that directory is detected.
    #
    # [1] https://github.com/transparency-dev/tessera/blob/ab720fc8dc0e2ab7afcc41095c563d1e8f32384f/storage/posix/file_ops.go#L35-L39

    parent = path.parent
    dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)

    try:
        fd, tmp_path = tempfile.mkstemp(dir=parent, suffix=".tmp")

        try:
            os.write(fd, data)
            os.fsync(fd)
        except:
            os.close(fd)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

            raise

        os.close(fd)

        try:
            os.replace(tmp_path, path)
        except:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

            raise

        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
