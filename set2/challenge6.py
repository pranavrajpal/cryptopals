import math
import random
from typing import List, Tuple

from Crypto.Random import get_random_bytes

from ..conversions import base64_to_bytes
from ..set1.challenge8 import get_blocks

from .challenge1 import pkcs7_pad, pkcs7_unpad
from .challenge3 import encrypt_AES_ECB, find_AES_mode
from .challenge4 import determine_block_size


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)
        prefix_length = random.randint(5, 20)
        self.prefix = get_random_bytes(prefix_length)
        base64_encoded = b"""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
        self.unknown_string = base64_to_bytes(base64_encoded)

    def encrypt(self, input_bytes):
        padded = pkcs7_pad(self.prefix + input_bytes + self.unknown_string, 16)
        encrypted = encrypt_AES_ECB(padded, self.key)
        return encrypted


def get_prefix_length(encryption_func, block_size):
    # keep increasing input length until prefix length between previous input and current input doesn't change
    # means that just added byte is at the beginning of a block
    prefix_length_changes: List[Tuple[int, int]] = []

    prev_prefix_length = None
    for input_length in range(100):
        before_adding = b"A" * input_length
        after_adding = b"A" * (input_length + 1)
        before_output = encryption_func(before_adding)
        after_output = encryption_func(after_adding)
        prefix_length = find_common_prefix_length(before_output, after_output)
        if prev_prefix_length is not None and prefix_length != prev_prefix_length:
            prefix_length_changes.append((input_length, prefix_length))
        prev_prefix_length = prefix_length
    input_length, blocks_prefix = prefix_length_changes[0]
    return block_size * blocks_prefix - input_length


def find_common_prefix_length(bytestring1, bytestring2):
    blocks1 = get_blocks(bytestring1, 16)
    blocks2 = get_blocks(bytestring2, 16)
    common_blocks = 0
    for block1, block2 in zip(blocks1, blocks2):
        if block1 == block2:
            common_blocks += 1
        else:
            break
    return common_blocks


def find_appended_prefix(encryption_func, prefix_length, block_size):
    known = b""
    while True:
        ith_char = get_one_byte_prefix(
            encryption_func, prefix_length, known, block_size
        )
        if ith_char == None:
            break
        known += ith_char
    return known


def get_one_byte_prefix(encryption_func, prefix_length, known, block_size):
    prefix_num_blocks = math.ceil(prefix_length / block_size)
    align_block_padding = prefix_num_blocks * block_size - prefix_length
    # round known length up if greater than or equal to block size
    input_max_blocks = len(known) // block_size + 1
    padding_length = align_block_padding + (
        block_size * input_max_blocks - len(known) - 1
    )
    padding = b"A" * padding_length

    def get_range(bytestring):
        blocks = get_blocks(bytestring, 16)
        return blocks[prefix_num_blocks : prefix_num_blocks + input_max_blocks]

    # [prefix_num_blocks: prefix_num_blocks + input_max_blocks]
    expected_output = get_range(encryption_func(padding))
    for input_byte in range(0, 0xFF + 1):
        as_bytestring = bytes([input_byte])
        guess_output = get_range(encryption_func(padding + known + as_bytestring))
        if guess_output == expected_output:
            return as_bytestring


def challenge6():
    cipher = Encryption()
    mode = find_AES_mode(cipher.encrypt)
    print(f"Mode: {mode}")
    block_size = determine_block_size(cipher.encrypt)
    print(f"Block size: {block_size}")
    prefix_length = get_prefix_length(cipher.encrypt, block_size)
    print(f"Prefix Length: {prefix_length}")
    unknown_bytes = find_appended_prefix(cipher.encrypt, prefix_length, block_size)
    unknown_string = pkcs7_unpad(unknown_bytes).decode("utf-8")
    print(f"Unknown string: {unknown_string}")


if __name__ == "__main__":
    challenge6()
