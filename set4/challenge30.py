from challenge28 import generate_sha1_padding, rol
from set1.challenge8 import get_blocks
from conversions import hex_to_bytes, bytes_to_hex
import numpy as np
import struct
import array
from Crypto.Random import get_random_bytes
from set2.challenge8 import url_decode_bytes


# def sample_md4():
#     h = MD4.new()
#     h.update(b'')
#     print(h.digest())


def md4_hash(message, input_message_length_bits=None, registers=None):
    def f(x, y, z):
        return np.uint32((x & y) | ((~x) & z))

    def g(x, y, z):
        return np.uint32((x & y) | (x & z) | (y & z))

    def h(x, y, z):
        return np.uint32(x ^ y ^ z)

    def round1_brackets(a, b, c, d, k, s, block):
        return np.uint32(rol(a + f(b, c, d) + block[k], s))

    def round2_brackets(a, b, c, d, k, s, block):
        value_sum = np.uint32(a + g(b, c, d) + block[k]) + np.uint32(0x5A827999)
        to_ret = np.uint32(rol(value_sum, s))
        return to_ret

    def round3_brackets(a, b, c, d, k, s, block):
        value_sum = np.uint32(a + h(b, c, d) + block[k]) + np.uint32(0x6ED9EBA1)
        return np.uint32(rol(value_sum, s))

    def md5_round(a, b, c, d, k_values, s_values, brackets_func, block):
        for index in range(16):
            if index % 4 == 0:
                a = np.uint32(
                    brackets_func(
                        a, b, c, d, k_values[index], s_values[index % 4], block
                    )
                )
            elif index % 4 == 1:
                d = np.uint32(
                    brackets_func(
                        d, a, b, c, k_values[index], s_values[index % 4], block
                    )
                )
            elif index % 4 == 2:
                c = np.uint32(
                    brackets_func(
                        c, d, a, b, k_values[index], s_values[index % 4], block
                    )
                )
            else:
                b = np.uint32(
                    brackets_func(
                        b, c, d, a, k_values[index], s_values[index % 4], block
                    )
                )
        return map(np.uint32, (a, b, c, d))

    if input_message_length_bits is None:
        message_len_bits = (8 * len(message)) & ((1 << 64) - 1)
        padding = generate_md4_padding(message_len_bits)
    else:
        padding = generate_md4_padding(input_message_length_bits)
    padded_message = message + padding
    if registers is None:
        # <<< means left rotate
        a, b, c, d = map(
            np.uint32, (0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476)
        )
    else:
        a, b, c, d = map(np.uint32, registers)
    blocks = get_blocks(padded_message, 64)
    for bytestring in blocks:
        block = list(map(np.uint32, array.array("I", bytestring)))
        # X in algorithm is just block but with 32 bit values instead of bytes
        saved_a, saved_b, saved_c, saved_d = map(np.uint32, (a, b, c, d))
        # Round #1
        k_values_round1 = list(range(16))
        s_values_round1 = [3, 7, 11, 19]
        a, b, c, d = md5_round(
            a, b, c, d, k_values_round1, s_values_round1, round1_brackets, block
        )
        # Round #2

        k_values_round2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        s_values_round2 = [3, 5, 9, 13]
        a, b, c, d = md5_round(
            a, b, c, d, k_values_round2, s_values_round2, round2_brackets, block
        )

        # Round #3

        k_values_round3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        s_values_round3 = [3, 9, 11, 15]
        a, b, c, d = md5_round(
            a, b, c, d, k_values_round3, s_values_round3, round3_brackets, block
        )
        a += np.uint32(saved_a)
        b += np.uint32(saved_b)
        c += np.uint32(saved_c)
        d += np.uint32(saved_d)
    return struct.pack("<4I", a, b, c, d)


def generate_md4_padding(message_length_bits):
    num_zero_bits_needed = (448 - message_length_bits - 1) % 512
    padding_length_bytes = (num_zero_bits_needed + 1) // 8
    padding = (1 << num_zero_bits_needed).to_bytes(padding_length_bytes, "big")
    # chop off any bits higher than lower 64 when padding data with length
    return padding + struct.pack("<Q", message_length_bits & ((1 << 64) - 1))


def test_md4_hash():
    tests = {
        "": "31d6cfe0d16ae931b73c59d7e0c089c0",
        "a": "bde52cb31de33e46245e05fbdbd6fb24",
        "abc": "a448017aaf21d8525fc10ae87aa6729d",
        "message digest": "d9130a8164549fe818874806e1c7014b",
        "abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "043f8582f241db351ce627e153e7f0e4",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536",
    }
    for message, expected_output_hex in tests.items():
        expected_output = hex_to_bytes(expected_output_hex)
        print(f"Message: {message}")
        print(f"Expected output: {bytes_to_hex(expected_output)}")
        received_output = md4_hash(message.encode("utf-8"))
        print(f"Received output: {bytes_to_hex(received_output)}")
        assert received_output == expected_output
    print("MD4 implementation is working")


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)

    def generate_mac(self):
        message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        mac = md4_hash(self.key + message)
        return message, mac

    def check_mac(self, message, mac):
        calculated_mac = md4_hash(self.key + message)
        if calculated_mac != mac:
            return None
        else:
            dictionary = url_decode_bytes(message)
            is_admin = False
            if b"admin" in dictionary and dictionary[b"admin"] == b"true":
                is_admin = True
            return dictionary, is_admin


def md4_length_extension(cipher):
    message, mac = cipher.generate_mac()
    original_length_bytes = len(message) + 16
    glue_padding = generate_md4_padding(original_length_bytes * 8)
    to_append = b";admin=true"
    registers = struct.unpack("<4I", mac)
    new_length_bits = (original_length_bytes + len(glue_padding) + len(to_append)) * 8
    new_mac = md4_hash(
        to_append, input_message_length_bits=new_length_bits, registers=registers
    )
    new_message = message + glue_padding + to_append
    return cipher.check_mac(new_message, new_mac)


def challenge30():
    cipher = Encryption()
    result = md4_length_extension(cipher)
    print(f"Result: {result}")


if __name__ == "__main__":
    challenge30()
    # test_md4_hash()
