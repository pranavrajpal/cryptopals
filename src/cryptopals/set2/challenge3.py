import random

from Crypto.Random import get_random_bytes

from ..set1.challenge8 import get_num_duplicates

from .challenge1 import pkcs7_pad
from .challenge2 import encrypt_AES_CBC, encrypt_AES_ECB


def encryption_oracle(input_bytes):
    # randomly chooses either cbc or ecb - pads with pkcs 7
    prepended_length = random.randint(5, 10)
    appended_length = random.randint(5, 10)
    prepended = get_random_bytes(prepended_length)
    appended = get_random_bytes(appended_length)
    is_ecb = random.choice([True, False])
    unpadded_plaintext = prepended + input_bytes + appended
    plaintext = pkcs7_pad(unpadded_plaintext, 16)
    key = get_random_bytes(16)
    if is_ecb:
        encrypted = encrypt_AES_ECB(plaintext, key)
    else:
        iv = get_random_bytes(16)
        encrypted = encrypt_AES_CBC(plaintext, key, iv)
    return encrypted


def find_AES_mode(encryption_function):
    block_size = 16
    # 4 blocks is enough to fill out first and last block and have several identical blocks in the middle
    num_blocks = 4
    message = b"A" * block_size * num_blocks
    encrypted = encryption_function(message)
    duplicates = get_num_duplicates(encrypted, block_size)
    # will have duplicates due to duplicate message blocks if ECB
    if duplicates > 0:
        mode = "ECB"
    else:
        mode = "CBC"
    return mode


def challenge3():
    guessed_mode = find_AES_mode(encryption_oracle)
    print(guessed_mode)


if __name__ == "__main__":
    challenge3()
