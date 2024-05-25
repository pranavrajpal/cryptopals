from __future__ import annotations

import random
import string
import struct
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterator, Optional

from more_itertools import sliding_window

from cryptopals.set1.challenge6 import get_blocks
from cryptopals.set2.challenge1 import pkcs7_pad

from .challenge52 import Block, Hasher, HashState, WeakHash


def to_bytes(blocks: list[Block]) -> bytes:
    return b"".join(blocks)


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
    # Hash that both messages start with
    start_hash: HashState
    # Hash that both of these messages produce
    end_hash: HashState


def rand_blocks(block_size: int) -> Iterator[Block]:
    # increment from 0 to the largest possible value
    # based on the algorithm from the paper
    max_val: int = 2 ** (block_size * 8 // 2)
    return (n.to_bytes(block_size, byteorder="big") for n in range(max_val))


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

    # Map from resulting state to a block that produced it for both short and long
    # blocks respectively
    hashes: defaultdict[HashState, list[Optional[Block]]] = defaultdict(
        lambda: [None, None]
    )

    def check_hash_succeeded(h: HashState) -> Optional[ShortLongPair]:
        short, long = hashes[h]
        if short is not None and long is not None:
            return ShortLongPair(short, long_prefix + [long], initial, h)
        else:
            return None

    for rand_block in rand_blocks(hasher.BLOCK_SIZE):
        short = hasher.one_round(rand_block, initial)
        hashes[short][0] = rand_block
        long = hasher.one_round(rand_block, prefix_hash)
        hashes[long][1] = rand_block
        pair1, pair2 = check_hash_succeeded(short), check_hash_succeeded(long)
        if pair1 is not None:
            return pair1
        if pair2 is not None:
            return pair2

    assert False, "Couldn't find a collision"


def expandable_message(
    hasher: Hasher, k: int, initial: HashState
) -> list[ShortLongPair]:
    """Return a list of collisions between short and long messages that can be
    adapted to get a length in the range (k, k + 2^k - 1)"""
    pairs = []
    prev = initial
    for i in range(1, k + 1):
        long_len = 2 ** (k - i) + 1
        pair = gen_short_long_pair(hasher, long_len, prev)
        pairs.append(pair)
        assert (
            hasher(pair.short, prev, padding=False)
            == hasher(to_bytes(pair.long), prev, padding=False)
            == pair.end_hash
        )
        prev = pair.end_hash

    return pairs


def convert_to_length(
    expandable: list[ShortLongPair], goal_num_blocks: int
) -> list[Block]:
    k = len(expandable)
    assert k <= goal_num_blocks <= k + 2**k - 1
    # Bits of above_min tell us whether to use the long version (if 1) or the short
    # version (if 0)
    above_min = goal_num_blocks - k
    print(f"{goal_num_blocks = }")
    so_far: list[Block] = []
    for i, pair in enumerate(expandable):
        current_bit = (above_min >> (k - 1 - i)) & 1
        so_far += pair.long if current_bit else [pair.short]
    assert len(so_far) == goal_num_blocks
    return so_far


def get_intermediate_hashes(
    hasher: Hasher, msg: bytes, initial: HashState
) -> dict[HashState, int]:
    """Get map from intermediate hash state after some block i to the index of that block i"""
    padded = pkcs7_pad(msg, hasher.BLOCK_SIZE)
    blocks = get_blocks(padded, hasher.BLOCK_SIZE)

    h = initial

    map: dict[HashState, int] = {}

    for i, block in enumerate(blocks):
        h = hasher.one_round(block, h)
        map[h] = i

    assert map[hasher(msg, initial)] == len(blocks) - 1
    return map


def main():
    # TODO: try larger k and different seed
    k = 3
    random.seed(0)
    hasher = WeakHash()
    initial = 0xBEEF
    # Message to try finding a collision with
    msg = "".join(random.choices(string.printable, k=2**k * hasher.BLOCK_SIZE)).encode()
    msg_blocks = get_blocks(msg, hasher.BLOCK_SIZE)
    intermediate_map = get_intermediate_hashes(hasher, msg, initial)

    expandable = expandable_message(hasher, k, initial)
    expandable_final = expandable[-1].end_hash

    bridge = None

    for rand_block in rand_blocks(hasher.BLOCK_SIZE):
        end_hash = hasher(rand_block, expandable_final, padding=False)
        idx = intermediate_map.get(end_hash, None)
        if idx is not None:
            expandable_msg_len = idx
            if k <= expandable_msg_len <= k + 2**k - 1:
                bridge = rand_block, idx
                break
    assert bridge is not None, "Couldn't find bridge block"

    bridge_block, bridge_idx = bridge
    suffix = msg_blocks[bridge_idx + 1 :]
    prefix = convert_to_length(expandable, bridge_idx)

    preimage_blocks = prefix + [bridge_block] + suffix
    assert hasher(to_bytes(prefix), initial, padding=False) == expandable_final
    assert hasher(bridge_block, expandable_final, padding=False) == hasher(
        to_bytes(msg_blocks[: bridge_idx + 1]), initial, padding=False
    )

    assert len(preimage_blocks) == len(msg_blocks)
    preimage = to_bytes(preimage_blocks)

    assert hasher(preimage, initial) == hasher(
        msg, initial
    ), "Preimage has different hash"
    print(
        f"{msg = }\n{preimage = }\n{hasher(preimage, initial) = }, {hasher(msg, initial) = }"
    )

    pass


# TODO: use pytest to run tests (and maybe just use relative imports for importing other sets)
def test_short_long_pair():
    weak = WeakHash()
    initial = 0xABCD
    long_len = 12
    pair = gen_short_long_pair(weak, long_len, initial)
    assert len(pair.long) == long_len
    assert pair.start_hash == initial

    # Use hash of empty string so that all of them add the same padding block of all 0x16 to the end of the
    # message
    assert (
        weak(pair.short, initial, padding=False)
        == weak(to_bytes(pair.long), initial, padding=False)
        == pair.end_hash
    )


def test_get_intermediate_messages():
    hasher = WeakHash()
    initial = 0xF00E
    k = 7
    random.seed(0)
    msg = "".join(random.choices(string.printable, k=2**k * hasher.BLOCK_SIZE)).encode()
    padded_msg_blocks = get_blocks(pkcs7_pad(msg, hasher.BLOCK_SIZE), hasher.BLOCK_SIZE)
    intermediate_map = get_intermediate_hashes(hasher, msg, initial)

    # Intermediate map will have one extra entry since padding adds one block
    assert len(intermediate_map) == len(padded_msg_blocks)

    for end_hash, block_idx in intermediate_map.items():
        assert (
            hasher(to_bytes(padded_msg_blocks[: block_idx + 1]), initial, padding=False)
            == end_hash
        )


def test_expandable_message():
    weak = WeakHash()
    initial = 0xABCD
    k = 13
    expandable = expandable_message(weak, k, initial)
    assert sum(len(l.long) for l in expandable) == k + (2**k) - 1
    assert len(expandable) == k

    # Make sure the hashes match up between sections
    for pair1, pair2 in sliding_window(expandable, 2):
        assert pair1.end_hash == pair2.start_hash

    assert expandable[0].start_hash == initial

    for pair in expandable:
        short_hash = weak(pair.short, pair.start_hash, padding=False)
        long_hash = weak(to_bytes(pair.long), pair.start_hash, padding=False)
        assert short_hash == long_hash == pair.end_hash

    # prev = initial
    # for i, pair in enumerate(expandable):
    #     print(f"{i = }")
    #     short = weak(pair.short, prev, padding=False)
    #     long = weak(to_bytes(pair.long), prev, padding=False)
    #     assert i != 0
    #     assert short == long == pair.end_hash, i
    #     prev = short


def test_creating_message_of_given_length():
    weak = WeakHash()
    initial = 0xCAFE
    k = 13
    expandable = expandable_message(weak, k, initial)
    shortest = convert_to_length(expandable, k)
    assert len(shortest) == k

    for length in range(k + 1, k + 2**k - 1 + 1):
        msg = convert_to_length(expandable, length)
        assert len(msg) == length


if __name__ == "__main__":
    main()
