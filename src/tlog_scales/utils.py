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


def vkey_id(name: str, sig_type: int, pubkey: bytes) -> int:
    return int.from_bytes(sha256(
        name.encode() +
        b'\n' +
        sig_type.to_bytes() +
        pubkey
    )[:4])


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers['User-Agent'] = f'tlog-scales/{TLOG_SCALES_VERSION}'

    return session


def sync_write(dst: Path, data: bytes) -> None:
    with dst.open('wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def atomic_write(path: Path, data: bytes) -> None:
    path = path.resolve()

    with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
        tmp = f.name

    try:
        os.replace(tmp, path)
    except:
        try:
            os.remove(tmp)
        except OSError:
            pass

        raise
