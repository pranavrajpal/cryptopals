from challenge5 import MersenneTwister
from enum import Enum
import secrets
import random


def untemper(rng, tempered):
    constants = rng.constants
    y3 = undo_bit_shift_right_anded(tempered, constants.l, 32)
    y2 = undo_bit_shift_left_anded(y3, constants.t, constants.c, 32)
    y1 = undo_bit_shift_left_anded(y2, constants.s, constants.b, 32)
    state = undo_bit_shift_right_anded(y1, constants.u, 32, anded=constants.d)
    return state


def undo_bit_shift_left_anded(final, shift_amt, anded, bit_size):
    # can't recover initial value if not shifted at all
    assert shift_amt != 0

    value = final
    initial_value = 0
    i = 0
    while i * shift_amt < bit_size:
        high_len = bit_size - (i + 1) * shift_amt
        low_mask = ((1 << shift_amt) - 1) << (i * shift_amt)
        # if low_len > 0:
        #     high_mask = ((1 << shift_amt) - 1) << low_len
        # else:
        #     high_mask = ((1 << shift_amt) - 1) >> -low_len
        low_initial = value & low_mask
        initial_value |= low_initial
        to_xor = (low_initial << shift_amt) & anded
        value ^= to_xor
        i += 1
    return initial_value


def test_bit_shift_left_anded():
    original = secrets.randbits(32)
    anded = secrets.randbits(32)
    bit_shift = random.randint(1, 32)
    print(f"Bit shift: {bit_shift}")
    print(f"Anded: {anded}")
    print(f"Original: {original}")
    modified = original ^ ((original << bit_shift) & anded)
    print(f"Modified: {modified}, {bin(modified)}")
    recovered = undo_bit_shift_left_anded(modified, bit_shift, anded, 32)
    print(f"Recovered: {recovered}, {bin(recovered)}")
    correct = recovered == original
    assert correct
    print(f"Correct?: {correct}")


def undo_bit_shift_right_anded(final, shift_amt, bit_size, anded=None):
    # can't recover initial value if not shifted at all
    assert shift_amt != 0

    value = final
    initial_value = 0
    i = 0
    while i * shift_amt < bit_size:
        low_len = bit_size - (i + 1) * shift_amt
        if low_len > 0:
            high_mask = ((1 << shift_amt) - 1) << low_len
        else:
            high_mask = ((1 << shift_amt) - 1) >> -low_len
        high_initial = value & high_mask
        initial_value |= high_initial
        if anded is None:
            to_xor = high_initial >> shift_amt
        else:
            to_xor = (high_initial >> shift_amt) & anded
        value ^= to_xor
        i += 1
    return initial_value


def test_bit_shift_right_no_and():
    original = secrets.randbits(32)
    bit_shift = random.randint(1, 32)
    print(f"Original: {original}")
    modified = original ^ (original >> bit_shift)
    print(f"Modified: {modified}")
    recovered = undo_bit_shift_right_anded(modified, bit_shift, 32)
    print(f"Recovered: {recovered}")
    print(f"Difference: {bin(recovered - original)}, {bin(original - recovered)}")
    correct = recovered == original
    assert correct
    print(f"Correct?: {correct}")


def test_bit_shift_right_anded():
    original = secrets.randbits(32)
    bit_shift = random.randint(1, 32)
    anded = secrets.randbits(32)
    print(f"Anded: {anded}")
    print(f"Bit shift: {bit_shift}")
    print(f"Original: {original}")
    modified = original ^ ((original >> bit_shift) & anded)
    print(f"Modified: {modified}")
    recovered = undo_bit_shift_right_anded(modified, bit_shift, 32, anded)
    print(f"Recovered: {recovered}")
    print(f"Difference: {bin(recovered - original)}, {bin(original - recovered)}")
    correct = recovered == original
    assert correct
    print(f"Correct?: {correct}")


def recover_state(rng):
    rng_state = []
    for i in range(624):
        rand_num = rng.extract_number()
        internal_state = untemper(rng, rand_num)
        print(f"Calculating num {i + 1}")
        rng_state.append(internal_state)
    print()
    return rng_state


def clone_rng(rng):
    rng_state = recover_state(rng)
    cloned_rng = MersenneTwister(rng_state)
    return cloned_rng


def challenge7():
    rng = MersenneTwister()
    seed = secrets.randbits(32)
    rng.seed_mt(seed)
    cloned_rng = clone_rng(rng)
    for i in range(10000):
        original = rng.extract_number()
        cloned = cloned_rng.extract_number()
        correct = original == cloned
        assert correct
        print(f"\r{i + 1} numbers are correct", end="")
    print()


def test_all():
    for i in range(10000):
        test_bit_shift_right_anded()
        test_bit_shift_right_no_and()
        test_bit_shift_left_anded()


if __name__ == "__main__":
    challenge7()
