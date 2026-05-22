from pathlib import Path
from typing import Callable

import pytest

from tlog_scales import tiles
from tlog_scales.backend import LocalBackend
from tlog_scales.reader import Tile, TilesReader
from tlog_scales.signing import DummySigner
from tlog_scales.tlog import ConsistencyProof, InclusionProof
from tlog_scales.utils import sha256
from tlog_scales.writer import TilesWriter


def check_consistency_proof(cp: ConsistencyProof, old_hash: bytes, new_hash: bytes) -> bool:
    # This function is a literal translation of RFC 9162, section 2.1.4.2.
    # "Verifying Consistency between Two Tree Heads", except for the
    # following block.
    #
    # We add this since the RFC verification algorithm has the precondition
    # 0 < old_size < new_size, which implies that there is something to
    # prove. However there are two trivial cases that still make sense to
    # consider here for consistency even though they don't happen in real
    # Sigsum protocol interactions:
    #
    #  - old_size == new_size and old_hash == new_hash, i.e. a tree head is
    #    consistent with itself
    #
    #  - an empty tree (old_size == 0, old_hash = MTH({}) = HASH()) is
    #    consistent with everything
    #
    # In those cases, there is nothing to prove and thus node_hashes is
    # empty.

    if not cp.node_hashes:
        if cp.old_size == cp.new_size and old_hash == new_hash:
            return True

        if cp.old_size == 0 and old_hash == sha256(b''):
            return True

    if not (0 < cp.old_size < cp.new_size):
        return False

    # RFC names and logic from here on
    consistency_path = cp.node_hashes.copy()
    first = cp.old_size
    second = cp.new_size
    first_hash = old_hash
    second_hash = new_hash

    # 1. If consistency_path is an empty array, stop and fail the proof
    # verification.
    if not consistency_path:
        return False

    # 2. If first is an exact power of 2, then prepend first_hash to the
    # consistency_path array.
    if first & (first - 1) == 0:
        consistency_path.insert(0, first_hash)

    # 3. Set fn to first - 1 and sn to second - 1.
    fn = first - 1
    sn = second - 1

    # 4. If LSB(fn) is set, then right-shift both fn and sn equally until
    # LSB(fn) is not set.
    while (fn & 1) != 0:
        fn >>= 1
        sn >>= 1

    # 5. Set both fr and sr to the first value in the consistency_path
    # array.
    fr = consistency_path[0]
    sr = consistency_path[0]

    # 6. For each subsequent value c in the consistency_path array:
    for c in consistency_path[1:]:
        # a. If sn is 0, then stop the iteration and fail the proof
        # verification.
        if sn == 0:
            return False

        # b. If LSB(fn) is set, or if fn is equal to sn, then:
        if (fn & 1) == 1 or fn == sn:
            # i. Set fr to HASH(0x01 || c || fr).
            fr = sha256(b'\x01' + c + fr)

            # ii. Set sr to HASH(0x01 || c || sr).
            sr = sha256(b'\x01' + c + sr)

            # iii. If LSB(fn) is not set, then right-shift both fn and sn
            # equally until either LSB(fn) is set or fn is 0.
            if (fn & 1) == 0:
                while True:
                    fn >>= 1
                    sn >>= 1

                    if (fn & 1) == 1 or fn == 0:
                        break
        # Otherwise:
        else:
            # i. Set sr to HASH(0x01 || sr || c).
            sr = sha256(b'\x01' + sr + c)

        # c. Finally, right-shift both fn and sn one time.
        fn >>= 1
        sn >>= 1

    # 7. After completing iterating through the consistency_path array as
    # described above, verify that the fr calculated is equal to the
    # first_hash supplied, that the sr calculated is equal to the
    # second_hash supplied, and that sn is 0.
    return fr == first_hash and sr == second_hash and sn == 0


def check_inclusion_proof(ip: InclusionProof, leaf_hash: bytes, root_hash: bytes, tree_size: int) -> None:
    # RFC 9162, section 2.1.3.2

    assert ip.leaf_index < tree_size

    fn = ip.leaf_index
    sn = tree_size - 1

    r = leaf_hash
    for p in ip.node_hashes:
        assert sn != 0
        if fn & 1 or fn == sn:
            r = sha256(b'\x01' + p + r)

            if fn & 1 == 0:
                while True:
                    fn >>= 1
                    sn >>= 1

                    if fn & 1 != 0 or fn == 0:
                        break
        else:
            r = sha256(b'\x01' + r + p)

        fn >>= 1
        sn >>= 1

    assert sn == 0
    assert r == root_hash


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
                assert check_consistency_proof(proof, root_hashes[old], root_hashes[new]), \
                    f"consistency proof failed for {old} -> {new}"

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
                check_inclusion_proof(proof, leaf_hash, root_hashes[size], size)

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
        check_inclusion_proof(proof, leaf_hash, old_cp.root_hash, old_cp.size)
