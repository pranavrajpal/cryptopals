import array
import math
import random
import secrets
import struct
import time

from challenge5 import MersenneTwister
from challenge7 import recover_state, undo_bit_shift_right_anded
from Crypto.Random import get_random_bytes

from set1.challenge1_2 import xor_bytes
from set1.challenge8 import get_blocks


def mersenne_stream_cipher(seed, bytestring):
    rng = MersenneTwister()
    rng.seed_mt(seed)
    keystream = get_bytestring(rng, len(bytestring))
    return xor_bytes(bytestring, keystream)


def get_bytestring(rng, length):
    numbers_to_generate = math.ceil(length)
    bytestring = b""
    for i in range(numbers_to_generate):
        bytestring += struct.pack("I", rng.extract_number())
    to_return = bytestring[:length]
    return to_return


def mersenne_stream_cipher_prefix(bytestring):
    seed = secrets.randbits(16)
    length = random.randint(0, 20)
    prefix = get_random_bytes(length)
    return mersenne_stream_cipher(seed, prefix + bytestring)


def recover_16_bit_seed():
    message = b"A" * 14
    encrypted = mersenne_stream_cipher_prefix(message)
    prefix_len = len(encrypted) - len(message)
    encrypted_message = encrypted[-len(message) :]
    keystream_message = xor_bytes(encrypted_message, message)
    num_offset_message = (4 - (prefix_len % 4)) % 4
    number_blocks = get_blocks(keystream_message[num_offset_message:], 4)
    # TODO: use untemper function to get state at relevant position
    nums = []
    for block in number_blocks:
        if len(block) < 4:
            break
        else:
            nums.append(struct.unpack("I", block)[0])
    num_pos = (prefix_len + num_offset_message) // 4

    for seed_guess in range(2 ** 16):
        print(f"Trying seed guess: {seed_guess}")
        if guess_seed(seed_guess, num_pos, nums):
            return seed_guess


def temper(rng, state_val):
    constants = rng.constants
    y = state_val

    y ^= (y >> constants.u) & constants.d
    y ^= (y << constants.s) & constants.b
    y ^= (y << constants.t) & constants.c
    y ^= y >> constants.l
    return y


def guess_seed(seed, start_index, expected_nums):
    rng = MersenneTwister()
    rng.seed_mt(seed)
    # extract a number to cause the RNG to call the twist function
    rng.extract_number()
    state_array = rng.state[start_index : start_index + len(expected_nums)]
    for state_num, expected_num in zip(state_array, expected_nums):
        if temper(rng, state_num) != expected_num:
            return False
    return True


def test_mersenne_stream_cipher():
    message = b"Hello, World!! AAAAAAAAAAABB"
    seed = secrets.randbits(16)
    encrypted = mersenne_stream_cipher(seed, message)
    print(f"Encrypted: {encrypted}")
    decrypted = mersenne_stream_cipher(seed, encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Decrypted correctly? {decrypted == message}")


def generate_password_reset_token():
    unix_time = int(time.time())
    rng = MersenneTwister()
    rng.seed_mt(unix_time)
    print(unix_time)
    return get_bytestring(rng, 50)


def break_password_reset_token(token):
    unix_time = int(time.time())
    INTERVAL_SIZE = 100
    length = (len(token) // 4) * 4
    numbers = array.array("I", token[:length])
    for guess in range(unix_time - INTERVAL_SIZE, unix_time + INTERVAL_SIZE):
        rng = MersenneTwister()
        rng.seed_mt(guess)
        found_valid = True
        for num in numbers:
            if num != rng.extract_number():
                found_valid = False
                break
        if found_valid:
            return True, guess
    return False


def challenge8():
    # MT19937 stream cipher -----------------------
    seed = secrets.randbits(16)
    mersenne_stream_cipher(seed, b"AAAAA")
    seed = recover_16_bit_seed()
    print(f"Seed: {seed}")

    # Password Reset Token ------------------------
    token = generate_password_reset_token()
    is_seeded_with_time, seed = break_password_reset_token(token)
    print(f"Is seeded with time? {is_seeded_with_time}")
    print(f"Seed: {seed}")


if __name__ == "__main__":
    # test_mersenne_stream_cipher()
    # test_prev_state()
    challenge8()
