from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from hypothesis import given

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

    # increment from 0 to the largest possible value
    # based on the algorithm from the paper
    max_val: int = 2 ** (hasher.BLOCK_SIZE * 8 // 2)

    for n in range(max_val):
        rand_block = n.to_bytes(hasher.BLOCK_SIZE, byteorder="big")
        short = hasher.one_round(rand_block, initial)
        hashes[short][0] = rand_block
        long = hasher.one_round(rand_block, prefix_hash)
        hashes[long][1] = rand_block
        pair1, pair2 = check_hash_succeeded(short), check_hash_succeeded(long)
        if pair1 is not None:
            return pair1
        if pair2 is not None:
            return pair2


def expandable_message(
    hasher: Hasher, k: int, initial: HashState
) -> list[ShortLongPair]:
    """Return a list of collisions between short and long messages that can be
    adapted to get a length in the range (k, k + 2^k - 1)"""
    pairs = []
    prev = initial
    for i in range(1, k + 1):
        long_len = 2 ** (k - i) + 1
        pairs.append(gen_short_long_pair(hasher, long_len, prev))
        prev = initial

    return pairs


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


def test_expandable_message():
    weak = WeakHash()
    initial = 0xABCD
    k = 13
    expandable = expandable_message(weak, k, initial)
    assert sum(len(l.long) for l in expandable) == k + (2 ** k) - 1
    assert len(expandable) == k
    prev = initial
    count = 0
    print(len(expandable))
    for pair in expandable:
        short = weak(pair.short, prev)
        long = weak(b"".join(pair.long), prev)
        assert short == long
        print(f"{count} pairs are correct")
        prev = short


if __name__ == "__main__":
    main()
