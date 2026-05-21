from collections import OrderedDict
from typing import Self, Optional

from . import tiles
from .tlog import Checkpoint, ConsistencyProof, InclusionProof
from .backend import TilesBackend
from .utils import sha256


class Tile:
    def __init__(self, entries: list[bytes]):
        if len(entries) > 256:
            raise ValueError(f'tile too large: {len(entries)}')

        self.entries = entries

    @property
    def length(self):
        return len(self.entries)

    def __getitem__(self, index):
        return self.entries[index]

    @classmethod
    def from_hash_bytes(cls, data: bytes) -> Self:
        if len(data) % 32:
            raise ValueError('hash tile data needs to be a multiple of 32 bytes')

        return cls([data[i:i+32] for i in range(0, len(data), 32)])

    @classmethod
    def from_entries_bytes(cls, data: bytes) -> Self:
        entries = []
        while data:
            entry_length = int.from_bytes(data[:2])

            if len(data) < 2 + entry_length:
                raise ValueError("entry tile is truncated")

            entries.append(data[2:2+entry_length])

            data = data[2+entry_length:]

        return cls(entries)


class TileCache:
    def __init__(self, max_size: int = 32):
        self.tiles: OrderedDict[tuple[int, int], Tile] = OrderedDict()
        self.max_size = max_size

    def get(self, l: int, n: int) -> Optional[Tile]:
        key = (l, n)
        if key not in self.tiles:
            return None

        self.tiles.move_to_end(key)
        return self.tiles[key]

    def put(self, l: int, n: int, tile: Tile) -> None:
        key = (l, n)
        self.tiles[key] = tile
        self.tiles.move_to_end(key)

        while len(self.tiles) > self.max_size:
            self.tiles.popitem(last=False)


class TilesReader:
    def __init__(self, backend: TilesBackend):
        self.backend = backend
        self.size = None
        self.tile_cache = TileCache()

    def _get_tile(self, l: int, n: int, partial: int = 0) -> Optional[Tile]:
        path = tiles.tile_path(l, n, partial)
        data = self.backend.get(*path)
        if data is None:
            return None

        if l == -1:
            return Tile.from_entries_bytes(data)
        else:
            return Tile.from_hash_bytes(data)

    def _get_from_tile(self, l: int, n: int, i: int) -> bytes:
        assert self.size is not None

        cached_tile = self.tile_cache.get(l, n)
        if cached_tile is not None and cached_tile.length > i:
            return cached_tile[i]

        level_entries = tiles.level_entries(self.size, l)
        current_tile, current_partial_size = divmod(level_entries, 256)

        tile = None
        if n == current_tile:
            tile = self._get_tile(l, n, current_partial_size)
        if tile is None:
            tile = self._get_tile(l, n)

        if tile is None:
            raise RuntimeError(f'could not get tile at L={l}, N={n}')

        if cached_tile is None or tile.length > cached_tile.length:
            self.tile_cache.put(l, n, tile)

        return tile[i]

    def get_checkpoint(self) -> Checkpoint:
        data = self.backend.get('checkpoint')
        if data is None:
            raise RuntimeError('no checkpoint found')

        cp_text = data.decode()
        cp = Checkpoint.from_text(cp_text)

        self.size = cp.size

        return cp

    def set_size(self, size: int) -> None:
        self.size = size

    @staticmethod
    def mth_in_tile(start: int, end: int) -> Optional[tuple[int, int, int]]:
        l = 0
        while start & 0xff == 0 and end & 0xff == 0:
            start >>= 8
            end >>= 8
            l += 1

        if end != start+1:
            return None

        n, i = divmod(start, 256)

        return l, n, i

    def mth(self, start: int, end: int) -> bytes:
        assert self.size is not None
        assert 0 <= start <= end <= self.size

        size = end - start
        if size == 0:
            return sha256(b'')

        tile_coord = self.mth_in_tile(start, end)
        if tile_coord is not None:
            return self._get_from_tile(*tile_coord)

        k = tiles.next_split(size)
        return sha256(b'\x01' + self.mth(start, start + k) + self.mth(start + k, end))

    def calculate_root_hash(self) -> bytes:
        assert self.size is not None
        return self.mth(0, self.size)

    def get_consistency_proof(self, old_size: int, new_size: int) -> ConsistencyProof:
        assert self.size is not None
        assert 0 <= old_size <= new_size <= self.size

        def subproof(m: int, start: int, size: int, b: bool) -> list[bytes]:
            if m == size:
                return [] if b else [self.mth(start, start+size)]
            k = tiles.next_split(size)
            if m <= k:
                return subproof(m, start, k, b) + [self.mth(start + k, start + size)]
            else:
                return subproof(m - k, start + k, size - k, False) + [self.mth(start, start + k)]

        return ConsistencyProof(
            old_size, new_size,
            subproof(old_size, 0, new_size, True)
        )

    def get_inclusion_proof(self, idx: int, size: int) -> InclusionProof:
        assert size > 0
        assert 0 <= idx <= size

        def path(m: int, offset: int, size: int) -> list[bytes]:
            if size == 1:
                return []

            k = tiles.next_split(size)
            if m < k:
                return path(m, offset, k) + [self.mth(offset + k, offset + size)]
            else:
                return path(m - k, offset + k, size - k) + [self.mth(offset, offset + k)]

        return InclusionProof(
            idx, size, path(idx, 0, size)
        )

    def get_entry(self, idx: int) -> bytes:
        tile, offset = divmod(idx, 256)
        return self._get_from_tile(-1, tile, offset)
