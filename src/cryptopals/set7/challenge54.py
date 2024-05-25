from collections import defaultdict
from dataclasses import dataclass

from more_itertools import grouper

from .challenge52 import Block, Hasher, HashState, WeakHash
from .challenge53 import rand_blocks, to_bytes

# TODO: maybe finish this? (have logic for generating collision tree, just need to use that to figure out getting to
# some initial state in tree and handling padding)


def generate_collision(
    hasher: Hasher, left_initial: HashState, right_initial: HashState
) -> tuple[Block, Block]:

    # Maps from output of hash function to block (using left and right initial values)
    left_outputs: dict[HashState, Block] = {}
    right_outputs: dict[HashState, Block] = {}

    def is_collision_target(final_hash: HashState) -> tuple[Block, Block] | None:
        left_block = left_outputs.get(final_hash, None)
        right_block = right_outputs.get(final_hash, None)
        if left_block is not None and right_block is not None:
            return left_block, right_block
        return None

    for block in rand_blocks(hasher.BLOCK_SIZE):
        left_final = hasher(block, left_initial, padding=False)
        right_final = hasher(block, right_initial, padding=False)
        left_outputs[left_final] = block
        right_outputs[right_final] = block

        if (possible_collision := is_collision_target(left_final)) is not None:
            return possible_collision
        if (possible_collision := is_collision_target(right_final)) is not None:
            return possible_collision

    assert False, "Couldn't find collision"


# Map from initial hash to the block to use to get to somewhere in the next level
TreeLevel = dict[HashState, Block]


def generate_collision_tree(hasher: Hasher, k: int) -> list[TreeLevel]:
    prev_hashes: list[HashState] = list(range(2**k))
    tree: list[TreeLevel] = []
    for _ in range(k):
        current_level: TreeLevel = {}
        current_end_hashes: list[HashState] = list()
        for left_initial, right_initial in grouper(prev_hashes, 2, incomplete="strict"):
            left_block, right_block = generate_collision(
                hasher, left_initial, right_initial
            )
            current_level[left_initial] = left_block
            current_level[right_initial] = right_block

            final_hash = hasher(left_block, left_initial, padding=False)
            current_end_hashes.append(final_hash)
        prev_hashes = current_end_hashes
        tree.append(current_level)
    return tree


def test_generate_collision():
    left_initial = 0
    right_initial = 5
    hasher = WeakHash()
    left_block, right_block = generate_collision(hasher, left_initial, right_initial)

    assert hasher(left_block, left_initial, padding=False) == hasher(
        right_block, right_initial, padding=False
    )


def test_generate_tree():
    hasher = WeakHash()
    k = 10
    tree = generate_collision_tree(hasher, k)
    final_initial, final_block = list(tree[-1].items())[0]

    target_hash = hasher(final_block, final_initial, padding=False)

    initial_hashes = list(tree[0])
    for start_hash in initial_hashes:
        h = start_hash
        msg_blocks: list[Block] = []
        for tree_level_idx in range(k):
            next_block = tree[tree_level_idx][h]
            msg_blocks.append(next_block)
            h = hasher(next_block, h, padding=False)
        assert len(msg_blocks) == k

        assert hasher(to_bytes(msg_blocks), start_hash, padding=False) == target_hash
