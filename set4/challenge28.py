from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from set1.challenge8 import get_blocks
import secrets
import numpy as np
import struct
import random
# turn off overflow warnings
np.seterr(over='ignore')


def sha1_hash(message, registers=None, message_length_bits=None):
    if message_length_bits is None:
        # ml is message length in bits not bytes
        ml = 8 * len(message)
        padding_with_length = generate_sha1_padding(ml)
    else:
        # will break if message_length_bits is not a multiple of 512 bits away from ml
        padding_with_length = generate_sha1_padding(message_length_bits)
    processed_message = message + padding_with_length
    # assert 8 * len(processed_message) % 512 == 0
    blocks = get_blocks(processed_message, 64)

    # initial hash values
    if registers is None:
        h0, h1, h2, h3, h4 = map(
            np.uint32, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0])
    else:
        h0, h1, h2, h3, h4 = map(np.uint32, registers)
    for block in blocks:
        w = struct.unpack('>16I', block)
        w = list(map(np.uint32, w))
        # message schedule
        for i in range(16, 80):
            num = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
            w.append(np.uint32(num))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(0, 80):
            if 0 <= i <= 19:
                f = np.uint32((b & c) | ((~b) & d))
                k = np.uint32(0x5A827999)
            elif 20 <= i <= 39:
                f = np.uint32(b ^ c ^ d)
                k = np.uint32(0x6ED9EBA1)
            elif 40 <= i <= 59:
                f = np.uint32((b & c) | (b & d) | (c & d))
                k = np.uint32(0x8F1BBCDC)
            elif 60 <= i <= 79:
                f = np.uint32(b ^ c ^ d)
                k = np.uint32(0xCA62C1D6)

            temp = np.uint32(rol(a, 5) + f + e + k + w[i])
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp
        h0 = np.uint32(h0 + a)
        h1 = np.uint32(h1 + b)
        h2 = np.uint32(h2 + c)
        h3 = np.uint32(h3 + d)
        h4 = np.uint32(h4 + e)
    hh = struct.pack('>5I', h0, h1, h2, h3, h4)
    return hh


def rol(value, shift_amt, num_bits=32):
    rotated = value >> (num_bits - shift_amt)
    return ((value << shift_amt) | rotated) & ((1 << 32) - 1)


def generate_sha1_padding(message_length_bits):
    num_zero_bits_needed = (448 - message_length_bits - 1) % 512
    padding_length_bytes = (num_zero_bits_needed + 1) // 8
    padding = (1 << num_zero_bits_needed).to_bytes(padding_length_bytes, 'big')
    return padding + struct.pack('>Q', message_length_bits)


def test_sha1_hash():
    message = get_random_bytes(random.randint(50, 1000))
    # message = b''
    pycrypto_hash = SHA1.new()
    pycrypto_hash.update(message)
    print(f'Pycrypto hash: {pycrypto_hash.digest()}')
    my_hash = sha1_hash(message)
    print(f'My hash: {my_hash}')
    correct = my_hash == pycrypto_hash.digest()
    assert correct
    print(f'Correct? {correct}')


def challenge28():
    key = get_random_bytes(secrets.randbelow(100))
    message = b'hello'
    message_hash = sha1_hash(key + message)
    print(f'Original hash: {message_hash}')
    modified_message = sha1_hash(key + b'abcd')
    print(f'Message modified: {modified_message}')
    print(f'Equal? {modified_message == message_hash}')


if __name__ == "__main__":
    test_sha1_hash()
