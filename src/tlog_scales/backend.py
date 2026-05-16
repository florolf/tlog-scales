import typing
from typing import Optional

from pathlib import Path

from . import utils


class TilesBackend(typing.Protocol):
    def get(self, *path: str) -> Optional[bytes]:
        ...


class LocalBackend:
    def __init__(self, base: Path):
        self.base = base

    def get(self, *path: str) -> Optional[bytes]:
        p = self.base.joinpath(*path)
        try:
            return p.read_bytes()
        except FileNotFoundError:
            return None


class HttpBackend:
    def __init__(self, base: str):
        self.base = base.rstrip('/')
        self.session = utils.make_session()

    def get(self, *path: str) -> Optional[bytes]:
        url = self.base + '/' + '/'.join(path)

        result = self.session.get(url)
        if result.status_code != 200:
            return None

        return result.content


def make_backend(loc: str) -> TilesBackend:
    if loc.startswith('/') or loc.startswith('./'):
        return LocalBackend(Path(loc))

    if loc.startswith('file://'):
        return LocalBackend(Path(loc[7:]))

    if loc.startswith('http://') or loc.startswith('https://'):
        return HttpBackend(loc)

    raise ValueError(f'unsupported backend location {loc}')
