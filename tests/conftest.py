from pathlib import Path
from typing import Callable

import pytest

from tlog_scales.signing import DummySigner
from tlog_scales.writer import TilesWriter


@pytest.fixture
def populated_log(tmp_path_factory: pytest.TempPathFactory) -> Callable[[int], Path]:
    def _build(n: int) -> Path:
        root = tmp_path_factory.mktemp("log")

        writer = TilesWriter(root, "example.com/test", 0)
        for i in range(n):
            writer.add_leaf(i.to_bytes(8))
        writer.commit([DummySigner()])

        return root

    return _build
