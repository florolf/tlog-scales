def next_split(x: int) -> int:
    """Largest power of two smaller than x"""
    assert x > 1
    return 1 << ((x - 1).bit_length() - 1)


def tile_path(l: int, n: int, partial: int = 0) -> list[str]:
        elements = ['%03d' % (n % 1000)]
        while n >= 1000:
            n //= 1000
            elements.insert(0, 'x%03d' % (n % 1000))

        if partial:
            elements[-1] += '.p'
            elements.append('%d' % partial)

        return ['tile', str(l) if l >= 0 else 'entries', *elements]


def level_entries(tree_size: int, level: int) -> int:
        if level == -1:
            level = 0

        return tree_size // 256**level


def level_tiles(tree_size: int, level: int) -> tuple[int, int]:
    entries = level_entries(tree_size, level)
    completed_tiles, partial_size = divmod(entries, 256)
    return completed_tiles, partial_size
