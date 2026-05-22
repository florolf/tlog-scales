from pathlib import Path
from typing import Callable

import pytest

from tlog_scales import tiles
from tlog_scales.backend import LocalBackend
from tlog_scales.reader import Tile, TilesReader
from tlog_scales.signing import DummySigner
from tlog_scales.utils import sha256
from tlog_scales.writer import TilesWriter


class TestTilePath:
    def test_tile_path(self) -> None:
        assert tiles.tile_path(0, 0) == ["tile", "0", "000"]
        assert tiles.tile_path(0, 1000) == ["tile", "0", "x001", "000"]
        assert tiles.tile_path(0, 1234067) == ["tile", "0", "x001", "x234", "067"]

        assert tiles.tile_path(1, 0) == ["tile", "1", "000"]
        assert tiles.tile_path(-1, 0) == ["tile", "entries", "000"]


class TestTile:
    def test_too_large(self) -> None:
        with pytest.raises(ValueError, match="tile too large"):
            Tile([b'\x00' * 32] * 257)

    def test_from_hash_bytes_bad_length(self) -> None:
        with pytest.raises(ValueError, match="multiple of 32"):
            Tile.from_hash_bytes(b'\x00' * 33)

    def test_from_entries_bytes_truncated(self) -> None:
        # header claims 10-byte entry but only 5 bytes follow
        data = (10).to_bytes(2) + b'\x00' * 5
        with pytest.raises(ValueError, match="truncated"):
            Tile.from_entries_bytes(data)


class TestTilesReader:
    def test_missing_checkpoint(self, tmp_path: Path) -> None:
        reader = TilesReader(LocalBackend(tmp_path))
        with pytest.raises(RuntimeError, match="no checkpoint found"):
            reader.get_checkpoint()

    def test_missing_tile(self, tmp_path: Path) -> None:
        reader = TilesReader(LocalBackend(tmp_path))
        reader.set_size(1)
        with pytest.raises(RuntimeError, match="could not get tile"):
            reader._get_from_tile(0, 0, 0)

    def test_root_hash_matches_checkpoint(self, populated_log: Callable[[int], Path]) -> None:
        root = populated_log(500)

        reader = TilesReader(LocalBackend(root))
        cp = reader.get_checkpoint()

        assert cp.size == 500
        assert reader.calculate_root_hash() == cp.root_hash

    def test_pairwise_consistency_proofs(self, tmp_path: Path) -> None:
        sizes = [1, 2, 5, 255, 256, 257, 500, 513]

        writer = TilesWriter(tmp_path, "example.com/test", 0)
        ctr = 0
        root_hashes: dict[int, bytes] = {}
        for size in sizes:
            while ctr < size:
                writer.add_leaf(ctr.to_bytes(8))
                ctr += 1
            writer.commit([DummySigner()])
            root_hashes[size] = writer.reader.calculate_root_hash()

        reader = TilesReader(LocalBackend(tmp_path))
        reader.get_checkpoint()

        for old in sizes:
            for new in sizes:
                if old >= new:
                    continue

                proof = reader.get_consistency_proof(old, new)
                proof.check(root_hashes[old], root_hashes[new])

    def test_inclusion_proofs(self, tmp_path: Path) -> None:
        sizes = [1, 2, 5, 255, 256, 257, 500, 513]

        writer = TilesWriter(tmp_path, "example.com/test", 0)
        ctr = 0
        root_hashes: dict[int, bytes] = {}
        for size in sizes:
            while ctr < size:
                writer.add_leaf(ctr.to_bytes(8))
                ctr += 1
            writer.commit([DummySigner()])
            root_hashes[size] = writer.reader.calculate_root_hash()

        reader = TilesReader(LocalBackend(tmp_path))
        reader.set_size(sizes[-1])

        for size in sizes:
            for i in sizes:
                if i >= size:
                    continue
                leaf_hash = sha256(b'\x00' + i.to_bytes(8))
                proof = reader.get_inclusion_proof(i, size)
                proof.check(leaf_hash, root_hashes[size])

    def test_get_entry(self, tmp_path: Path) -> None:
        writer = TilesWriter(tmp_path, "example.com/test", 0)
        for i in range(513):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()])

        reader = TilesReader(LocalBackend(tmp_path))
        reader.get_checkpoint()

        for i in range(513):
            assert reader.get_entry(i) == i.to_bytes(8), f"entry {i} mismatch"

    def test_full_tile_fallback(self, tmp_path: Path) -> None:
        writer = TilesWriter(tmp_path, "example.com/test", 0)
        for i in range(5):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()])

        # The reader fetches a checkpoint
        reader = TilesReader(LocalBackend(tmp_path))
        old_cp = reader.get_checkpoint()
        assert old_cp.size == 5

        # At size 5, level-0 tile 0 is a partial of length 5.
        partial_path = tmp_path / "tile" / "0" / "000.p"
        assert (partial_path / "5").exists()

        # In the meantime, the log now adds more entries
        for i in range(5, 260):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()])

        # This causes the partial tile to get deleted and a full tile to be created
        assert not partial_path.exists()
        assert (tmp_path / "tile" / "0" / "000").exists()

        # The reader still believes size == 5; reading must fall back from the
        # (now-missing) partial to the full tile
        proof = reader.get_inclusion_proof(4, old_cp.size)

        leaf_hash = sha256(b'\x00' + (4).to_bytes(8))
        proof.check(leaf_hash, old_cp.root_hash)
