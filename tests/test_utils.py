from tlog_scales.reader import Tile, TileCache


class TestTileCache:
    def test_lru_eviction1(self) -> None:
        cache = TileCache(max_size=2)
        t0 = Tile([b'\x00'])
        t1 = Tile([b'\x01'])
        t2 = Tile([b'\x02'])

        cache.put(0, 0, t0)
        cache.put(0, 1, t1)

        assert cache.get(0, 0) is t0
        assert cache.get(0, 1) is t1

        cache.put(0, 2, t2)

        assert cache.get(0, 0) is None
        assert cache.get(0, 1) is t1
        assert cache.get(0, 2) is t2

    def test_lru_eviction2(self) -> None:
        cache = TileCache(max_size=2)
        t0 = Tile([b'\x00'])
        t1 = Tile([b'\x01'])
        t2 = Tile([b'\x02'])

        cache.put(0, 0, t0)
        cache.put(0, 1, t1)

        # different access order, should evict (0,1) below
        assert cache.get(0, 1) is t1
        assert cache.get(0, 0) is t0

        cache.put(0, 2, t2)

        assert cache.get(0, 0) is t0
        assert cache.get(0, 1) is None
        assert cache.get(0, 2) is t2
