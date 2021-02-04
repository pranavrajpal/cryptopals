from challenge3 import encrypt_AES_ECB
from conversions import base64_to_bytes
from challenge1 import pkcs7_pad, pkcs7_unpad
from Crypto.Random import get_random_bytes
from challenge3 import find_AES_mode
from set1.challenge8 import get_blocks


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)
        base64_encoded = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
        self.unknown_string = base64_to_bytes(base64_encoded)

    def encrypt_append(self, input_bytes):
        padded = pkcs7_pad(input_bytes + self.unknown_string, 16)
        encrypted = encrypt_AES_ECB(padded, self.key)
        return encrypted


def determine_block_size(encryption_func):
    # list of block sizes which going to caused the output to change size
    changing_block_sizes = []
    previous_length = None
    for input_length in range(1, 50):
        input_bytes = b'A' * input_length
        encrypted = encryption_func(input_bytes)
        output_length = len(encrypted)
        if previous_length is not None and output_length != previous_length:
            # length changed
            changing_block_sizes.append(input_length)
        previous_length = output_length
    return changing_block_sizes[1] - changing_block_sizes[0]


def find_appended_AES_ECB(encryption_func, block_size):
    unknown_string = bytearray()
    for i in range(1000):
        ith_char = get_one_byte(encryption_func, unknown_string, block_size)
        if ith_char is None:
            break
        unknown_string += ith_char
    return unknown_string


def get_one_byte(encryption_func, known, block_size):
    known_length = len(known)
    # number of blocks expected to be the same - increases when known_length increases above block_size
    num_blocks = known_length // block_size
    # need an extra block in addition to blocks that are already known
    beginning_padding = b'A' * \
        ((num_blocks + 1) * block_size - 1 - known_length)
    beginning_message = beginning_padding + known
    # encrypt only the padding to allow last byte to be new unknown data
    with_secret = encryption_func(beginning_padding)
    blocks = get_blocks(with_secret, 16)
    goal_first_block = blocks[:num_blocks + 1]
    for byte_guess in range(0, 0xff + 1):
        as_byte = bytes([byte_guess])
        full_message = beginning_message + as_byte
        with_guess = encryption_func(full_message)
        guess_first_block = get_blocks(with_guess, 16)[:num_blocks + 1]
        if goal_first_block == guess_first_block:
            return as_byte


def challenge4():
    cipher = Encryption()
    block_size = determine_block_size(cipher.encrypt_append)
    print(f'Block Size: {block_size}')
    mode = find_AES_mode(cipher.encrypt_append)
    print(f'Mode: {mode}')
    unknown_string_padded = find_appended_AES_ECB(
        cipher.encrypt_append, block_size)
    unpadded = pkcs7_unpad(unknown_string_padded)
    print(f'Unknown string:')
    print(unpadded.decode('utf8'))
    # print(f'With unknown string: {cipher.encrypt_append(b"")}')
    # print(f'With guess: {encrypt_AES_ECB(unknown_string)}')


if __name__ == "__main__":
    challenge4()
