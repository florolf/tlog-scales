import shutil

from pathlib import Path
from typing import Self

from . import tiles, utils, tlog, reader, backend, signing

class TilesWriter:
    def __init__(self, root: Path, origin: str, size: int):
        self.origin = origin
        self.size = size
        self.root = root

        self.pending: list[bytes] = []

        self.reader = reader.TilesReader(backend.LocalBackend(root))
        self.reader.set_size(size)

    @classmethod
    def from_path(cls, root: Path) -> Self:
        cp_path = root / 'checkpoint'
        cp = tlog.Checkpoint.from_text(cp_path.read_text())

        return cls(root, cp.origin, cp.size)

    @classmethod
    def create(cls, root: Path, origin: str) -> Self:
        root.mkdir(parents=True)
        return cls(root, origin, 0)

    def add_leaf(self, data: bytes) -> None:
        self.pending.append(data)

    def _tile_path(self, l: int, n: int, partial: int = 0) -> Path:
        return self.root.joinpath(*tiles.tile_path(l, n, partial))

    def _append_tile(self, level: int, elements: list[bytes]):
        if not elements:
            return

        current_tile, partial = tiles.level_tiles(self.size, level)

        # fill up and potentially complete an existing partial tile
        if partial:
            old_data = self._tile_path(level, current_tile, partial).read_bytes()

            # TODO:
            #  - Validate that old_data has the expected length (should never
            #    be shorter but might be longer if we crashed during a previous
            #    commit)
            #
            #  - The partial might be missing entirely and have gotten replace
            #    by a full tile (and possibly subsequent tiles) for the same
            #    reason

            max_this = 256 - partial
            this, elements = elements[:max_this], elements[max_this:]

            new_size = partial + len(this)

            if new_size == 256:
                this_path = self._tile_path(level, current_tile, 0)
                current_tile += 1
            else:
                this_path = self._tile_path(level, current_tile, new_size)

            utils.atomic_write(this_path, old_data + b''.join(this))

        # write full tiles and potentially a new partial
        for start in range(0, len(elements), 256):
            this = elements[start:start + 256]

            if len(this) == 256:
                this_path = self._tile_path(level, current_tile, 0)
                current_tile += 1
            else:
                this_path = self._tile_path(level, current_tile, len(this))

            this_path.parent.mkdir(parents=True, exist_ok=True)
            utils.atomic_write(this_path, b''.join(this))

    def _hash_full_tile(self, l: int, n: int) -> bytes:
        data = self._tile_path(l, n).read_bytes()
        hashes = [data[i:i+32] for i in range(0, len(data), 32)]

        while len(hashes) > 1:
            hashes = [
                utils.sha256(b'\x01' + hashes[i] + hashes[i+1])
                for i in range(0, len(hashes), 2)
            ]

        return hashes[0]

    def gc(self) -> None:
        def _gc(p: Path) -> None:
            for child in p.iterdir():
                if not child.is_dir():
                    continue

                n = child.name
                if n.startswith('x'):
                    _gc(child)
                elif n.endswith('.p'):
                    full = n[:-2]
                    if (p / full).exists():
                        shutil.rmtree(child)

        tiles_root = self.root / 'tile'

        if not tiles_root.exists():
            return

        for child in tiles_root.iterdir():
            if child.is_dir():
                _gc(child)

    def commit(self, signers: list[signing.NoteSigner], gc: bool = True) -> None:
        entries = []
        for leaf in self.pending:
            entries.append(len(leaf).to_bytes(length=2) + leaf)
        self._append_tile(-1, entries)

        entries = []
        for leaf in self.pending:
            entries.append(utils.sha256(b'\x00' + leaf))
        self._append_tile(0, entries)

        new_size = self.size + len(self.pending)

        old_full_tiles = self.size // 256
        new_full_tiles = new_size // 256
        level = 1
        while old_full_tiles != new_full_tiles:
            entries = []
            for idx in range(old_full_tiles, new_full_tiles):
                entries.append(self._hash_full_tile(level-1, idx))

            self._append_tile(level, entries)

            level += 1
            old_full_tiles //= 256
            new_full_tiles //= 256

        self.reader.set_size(new_size)
        try:
            root_hash = self.reader.calculate_root_hash()
            cp = tlog.Checkpoint.make_signed(self.origin, new_size, root_hash, signers)
            utils.atomic_write(self.root / "checkpoint", cp.serialize().encode())
        except Exception as e:
            self.reader.set_size(self.size)
            raise e

        self.size = new_size
        self.pending = []

        if gc:
            self.gc()
