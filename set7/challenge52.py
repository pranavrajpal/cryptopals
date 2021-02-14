from __future__ import annotations

import itertools
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from os import urandom
from typing import Iterable

import more_itertools  # type: ignore
from Crypto.Cipher import DES

from set1.challenge8 import get_blocks
from set2.challenge1 import pkcs7_pad

HashState = int

Block = bytes


class Hasher(ABC):
    @property
    @abstractmethod
    def BLOCK_SIZE(self) -> int:
        raise NotImplementedError

    def __call__(self, message: bytes, initial: HashState) -> HashState:
        """Run the entire hash"""
        # initial H value
        h: int = initial

        padded = pkcs7_pad(message, self.BLOCK_SIZE)
        blocks = get_blocks(padded, self.BLOCK_SIZE)
        for block in blocks:
            h = self.one_round(block, h)
        return h

    @abstractmethod
    def one_round(self, block: Block, initial: HashState) -> HashState:
        """One round of the hash"""
        raise NotImplementedError


class WeakHash(Hasher):
    """A very weak hash that should be easy to break

    `initial` should be a 16-bit number

    The return value will be a 16-bit number"""

    # DES has a block size of 8, so we'll use 8
    BLOCK_SIZE = 8

    def one_round(self, block: Block, state: HashState) -> HashState:
        """Perform one round of the weak hash, returning the new state after the round"""
        # use DES because it will probably be very fast/easy to break
        key = struct.pack(">Q", state)
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(block)
        # ignore the top 6 bytes
        return struct.unpack(">6xH", encrypted)[0]


class StrongerHash(Hasher):
    BLOCK_SIZE = 8

    def one_round(self, block: Block, state: HashState) -> HashState:
        key = struct.pack(">Q", state)
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(block)
        # only ignore 4 bytes to make it harder to break
        return struct.unpack(">4xI", encrypted)[0]


# can't make this an instance of Hasher because there's no easy way to define this
# in terms of each individual round of both hashes
def combined_hash(message: bytes, state: HashState) -> HashState:
    """The output of this is a 6-byte integer (the top 2 bytes are from the weak hash,
    and the bottom 4 are from the stronger hash)"""

    weak = WeakHash()
    strong = StrongerHash()
    weak_out = weak(message, state)
    strong_out = strong(message, state)
    return (weak_out << 32) | strong_out


@dataclass
class Collision:
    final: int
    messages: tuple[Block, Block]


def find_collisions(
    hasher: Hasher, initial: HashState, iterations: int
) -> Iterable[bytes]:
    """Return list of `2 ** iterations` messages that all collide with each other"""
    collisions = list_collisions(hasher, initial, iterations)
    message_pairs = (c.messages for c in collisions)
    prod = itertools.product(*message_pairs)
    return map(lambda t: b"".join(t), prod)


def list_collisions(hasher: Hasher, initial: HashState, blocks: int) -> list[Collision]:
    """Find collisions in `hash_func` using the initial state `initial`

    Returns a list of Collisions where each Collision represents a collision in one block
    with 2 blocks that hash to the same final value (which is collision.final)

    The initial value for any block is equal to the final value for the previous block"""
    prev_h = initial
    collisions = []
    for _ in range(blocks):
        collision = brute_force_collision(hasher, prev_h)
        prev_h = collision.final
        collisions.append(collision)
    return collisions


def brute_force_collision(hasher: Hasher, initial: HashState) -> Collision:
    hashes: dict[int, Block] = {}
    count = 0
    while True:
        count += 1
        rand_block = urandom(hasher.BLOCK_SIZE)
        h = hasher.one_round(rand_block, initial)
        if h in hashes:
            # found collision b/c previous block had same hash
            return Collision(h, (rand_block, hashes[h]))
        hashes[h] = rand_block
        # print(f"{count} blocks tried")


def break_combined_hash(initial: HashState) -> tuple[bytes, bytes]:
    weak = WeakHash()
    strong = StrongerHash()
    while True:
        print("Trying new set of colliding messages")
        strong_hashes: dict[HashState, bytes] = {}
        count = 0
        for message in find_collisions(weak, initial, 30):
            print(f"{count} messages tried")
            h = strong(message, initial)
            if h in strong_hashes:
                # found a collision in the stronger hash
                return (message, strong_hashes[h])
            strong_hashes[h] = message
            count += 1


def main():
    test_find_collision()
    test_break_combined_hash()


def test_find_collision():
    hasher = WeakHash()
    initial = 0xABCD
    messages = find_collisions(hasher, initial, 10)
    hashes = [hasher(m, initial) for m in messages]
    assert more_itertools.all_equal(hashes)
    print("All hashes are equal")
    assert len(set(messages)) == sum(map(lambda b: 1, messages))
    print("No messages are repeated")


def test_break_combined_hash():
    print("Trying to break combined hash")
    weak = WeakHash()
    strong = StrongerHash()
    initial = 0xABCD
    m1, m2 = break_combined_hash(initial)
    assert m1 != m2
    print("Messages aren't the same")
    assert weak(m1, initial) == weak(m2, initial)
    print("Weak hash collides")
    assert strong(m1, initial) == strong(m2, initial)
    print("Strong hash collides")
    assert combined_hash(m1, initial) == combined_hash(m2, initial)
    print("Combined hash collides")


if __name__ == "__main__":
    main()
