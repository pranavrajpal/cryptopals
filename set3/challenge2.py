import struct

from conversions import base64_to_bytes
from set1.challenge1_2 import xor_bytes
from set1.challenge8 import get_blocks
from set2.challenge2 import encrypt_AES_ECB


def encrypt_AES_CTR(bytestring, key, nonce):
    """Takes an arbitrary length message `bytestring`, a 16-byte `key`, and
    an integer `nonce` that is at most 8 bytes"""
    blocks = get_blocks(bytestring, 16)
    keystream = generate_keystream(key, nonce, len(bytestring))
    return xor_bytes(bytestring, keystream)


def generate_keystream(key, nonce, length):
    counter = 0
    keystream = b""
    while len(keystream) <= length:
        counter_bytes = struct.pack("<2Q", nonce, counter)
        keystream_block = encrypt_AES_ECB(counter_bytes, key)
        keystream += keystream_block
        counter += 1
    return keystream[:length]


# def test_conversions():
#     bytestring = num_to_bytestring(0x0123456789ABCDEF31415926FEDCBA98)
#     print(f'Bytestring: {bytestring}')
#     num = bytestring_to_num(bytestring)
#     print(f'Num: {num}, Before: {0x0123456789ABCDEF31415926FEDCBA98}, equal?: {num == 0x0123456789ABCDEF31415926FEDCBA98}')


def challenge2():
    encrypted_base64 = (
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    encrypted = base64_to_bytes(encrypted_base64)
    decrypted = encrypt_AES_CTR(encrypted, b"YELLOW SUBMARINE", 0)
    print(decrypted.decode("utf-8"))


if __name__ == "__main__":
    challenge2()
    # test_conversions()
