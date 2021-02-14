from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from os import urandom
from typing import Optional

from .challenge52 import Block, Hasher, HashState, WeakHash


def dummy_blocks(hasher: Hasher, n: int) -> list[Block]:
    """Return a fixed dummy block, repeated `n` times

    The same `hasher` should cause the same dummy block to be returned

    This is meant to be used when it doesn't matter what value a block has so
    that the output is the same between runs (which makes debugging easier)"""
    return [bytes(hasher.BLOCK_SIZE)] * n


@dataclass
class ShortLongPair:
    short: Block
    long: list[Block]


def gen_short_long_pair(
    hasher: Hasher, long_len: int, initial: HashState
) -> ShortLongPair:
    """Returns a pair of 2 messages, one of length 1 block and the other of length
    `long_len` blocks"""
    long_prefix = dummy_blocks(hasher, long_len - 1)
    # can't just compute the hash normally because we don't want the padding to be added
    prefix_hash = initial
    for block in long_prefix:
        prefix_hash = hasher.one_round(block, prefix_hash)

    hashes: defaultdict[HashState, list[Optional[Block]]] = defaultdict(
        lambda: [None, None]
    )

    def check_hash_succeeded(h: HashState) -> Optional[ShortLongPair]:
        short, long = hashes[h]
        if short is not None and long is not None:
            return ShortLongPair(short, long_prefix + [long])
        else:
            return None

    while True:
        rand_block = urandom(hasher.BLOCK_SIZE)
        short = hasher.one_round(rand_block, initial)
        hashes[short][0] = rand_block
        long = hasher.one_round(rand_block, prefix_hash)
        hashes[long][1] = rand_block
        pair1, pair2 = check_hash_succeeded(short), check_hash_succeeded(long)
        if pair1 is not None:
            return pair1
        if pair2 is not None:
            return pair2


def main():
    pass


# TODO: use pytest to run tests (and maybe just use relative imports for importing other sets)
def test_short_long_pair():
    weak = WeakHash()
    initial = 0xABCD
    long_len = 12
    pair = gen_short_long_pair(weak, long_len, initial)
    assert len(pair.long) == long_len
    assert weak(pair.short, initial) == weak(b"".join(pair.long), initial)



if __name__ == "__main__":
    main()
