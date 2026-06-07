from pathlib import Path
from typing import Callable

import pytest

from tlog_scales.signing import DummySigner
from tlog_scales.tlog import Checkpoint
from tlog_scales.utils import sha256
from tlog_scales.writer import TilesWriter


ORIGIN = "example.com/test"


def _read_checkpoint(root: Path) -> Checkpoint:
    return Checkpoint.from_text((root / "checkpoint").read_text())


def _hash_file_hex(file: Path) -> str:
    return sha256(file.read_bytes()).hex()


def test_empty_log(tmp_path: Path) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)
    writer.commit([DummySigner()])

    cp = _read_checkpoint(tmp_path)
    assert cp.origin == ORIGIN
    assert cp.size == 0
    assert cp.root_hash == sha256(b"")
    assert len(cp.signatures) == 1


def test_single_entry(tmp_path: Path) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)

    leaf = b"hello"
    writer.add_leaf(leaf)
    writer.commit([DummySigner()])

    # entry tile: 2-byte length prefix + raw leaf bytes
    entry_path = tmp_path / "tile" / "entries" / "000.p" / "1"
    assert entry_path.read_bytes() == len(leaf).to_bytes(length=2) + leaf

    # level-0 tile: single leaf hash
    leaf_hash = sha256(b"\x00" + leaf)
    level0_path = tmp_path / "tile" / "0" / "000.p" / "1"
    assert level0_path.read_bytes() == leaf_hash

    # no higher-level tiles for a single entry
    assert not tmp_path.joinpath("tile", "1").exists()

    cp = _read_checkpoint(tmp_path)
    assert cp.origin == ORIGIN
    assert cp.size == 1

    # MTH of a size==1 tree is just the leaf hash
    assert cp.root_hash == leaf_hash
    assert len(cp.signatures) == 1


def test_many_entries(tmp_path: Path) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)

    for i in range(0, 500):
        writer.add_leaf(i.to_bytes(8))

    writer.commit([DummySigner(key_id=0)])

    # known good data as validated by tessera/tlog_fsck
    assert _hash_file_hex(tmp_path / "tile" / "entries" / "000")           == "f4bae1960a3cedc6303230167918d50a56329bea77c58fbc22445dc195b60774"
    assert _hash_file_hex(tmp_path / "tile" / "entries" / "001.p" / "244") == "b3276e3f675ec36fb28d8c09e4566a1b3038681d968af0e13fce8c9904ef1c45"
    assert _hash_file_hex(tmp_path / "tile" / "0" / "000")                 == "20cd0859c7fb4ae9eeac1d244887e6f9342d86ce0b1a1c7bb244915d3d0dc971"
    assert _hash_file_hex(tmp_path / "tile" / "0" / "001.p" / "244")       == "02ed988bacba01ac7917ea0bb9c29dbaa1d7bcf23fef761e24daf4893aeb8f1c"
    assert _hash_file_hex(tmp_path / "tile" / "1" / "000.p" / "1")         == "6798b752c531ad04237b025eaf98e4e00ee73d3af503cc71b8b220de3573b550"
    assert _hash_file_hex(tmp_path / "checkpoint")                         == "e81bf73e4b2e63a6ef4b91a4d145761d5baff9146f199dfef521a85321d80ee3"

def test_batching_equivalence(tmp_path: Path) -> None:
    n = 600

    shapes = {
        "oneshot": [n],
        "per-leaf": [1] * n,
        "mixed": [1, 254, 1, 1, 257, 86],
    }
    assert all(sum(s) == n for s in shapes.values())

    roots: dict[str, bytes] = {}
    for name, batches in shapes.items():
        root = tmp_path / name
        root.mkdir()
        writer = TilesWriter(root, ORIGIN, 0)

        ctr = 0
        for batch in batches:
            for _ in range(batch):
                writer.add_leaf(ctr.to_bytes(8))
                ctr += 1
            writer.commit([DummySigner()])

        roots[name] = _read_checkpoint(root).root_hash

    assert len(set(roots.values())) == 1, roots


def test_open_from_path(tmp_path: Path, populated_log: Callable[[int], Path]) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)
    for i in range(100):
        writer.add_leaf(i.to_bytes(8))
    writer.commit([DummySigner()])

    # reopen
    writer = TilesWriter.from_path(tmp_path)
    assert writer.origin == ORIGIN
    assert writer.size == 100
    for i in range(100, 300):
        writer.add_leaf(i.to_bytes(8))
    writer.commit([DummySigner()])

    assert _read_checkpoint(tmp_path).root_hash == _read_checkpoint(populated_log(300)).root_hash


def test_create(tmp_path: Path) -> None:
    root = tmp_path / "log"
    writer = TilesWriter.create(root, ORIGIN)
    writer.commit([DummySigner()])

    cp = _read_checkpoint(root)

    assert root.is_dir()
    assert cp.origin == ORIGIN
    assert cp.size == 0


def test_create_existing_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(FileExistsError):
        TilesWriter.create(tmp_path, ORIGIN)


def test_commit_gc(tmp_path: Path) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)

    prev = 0
    for boundary in [100, 300]:
        for i in range(prev, boundary):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()])
        prev = boundary

    assert (tmp_path / "tile" / "entries" / "000").exists()
    assert not (tmp_path / "tile" / "entries" / "000.p").exists()

    assert not (tmp_path / "tile" / "entries" / "001").exists()
    assert (tmp_path / "tile" / "entries" / "001.p").exists()


def test_manual_gc(tmp_path: Path) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)

    prev = 0
    for boundary in [100, 300]:
        for i in range(prev, boundary):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()], gc=False)
        prev = boundary

    assert (tmp_path / "tile" / "entries" / "000").exists()
    assert (tmp_path / "tile" / "entries" / "000.p").exists()

    assert (tmp_path / "tile" / "entries" / "001.p").exists()

    writer.gc()

    assert (tmp_path / "tile" / "entries" / "000").exists()
    assert not (tmp_path / "tile" / "entries" / "000.p").exists()

    assert not (tmp_path / "tile" / "entries" / "001").exists()
    assert (tmp_path / "tile" / "entries" / "001.p").exists()


def test_gc_large_tree(tmp_path: Path) -> None:
    writer = TilesWriter(tmp_path, ORIGIN, 0)

    prev = 0
    for boundary in [256 * 1000 + 100, 256 * 1000 + 300]:
        for i in range(prev, boundary):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()], gc=False)
        prev = boundary

    x_dir = tmp_path / "tile" / "entries" / "x001"

    assert (x_dir / "000").exists()
    assert (x_dir / "000.p").exists()
    assert (x_dir / "001.p").exists()

    writer.gc()

    assert (x_dir / "000").exists()
    assert not (x_dir / "000.p").exists()
    assert (x_dir / "001.p").exists()
