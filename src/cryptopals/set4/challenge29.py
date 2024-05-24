import struct

from Crypto.Random import get_random_bytes

from ..set2.challenge8 import url_decode_bytes
from ..set4.challenge28 import generate_sha1_padding, sha1_hash


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)

    def generate_mac(self):
        message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        mac = sha1_hash(self.key + message)
        return message, mac

    def check_mac(self, message, mac):
        calculated_mac = sha1_hash(self.key + message)
        if calculated_mac != mac:
            return None
        else:
            dictionary = url_decode_bytes(message)
            is_admin = False
            if b"admin" in dictionary and dictionary[b"admin"] == b"true":
                is_admin = True
            return dictionary, is_admin


def sha1_length_extension(cipher, key_length):
    message, mac = cipher.generate_mac()
    message_len_bits = (len(message) + key_length) * 8
    glue_padding = generate_sha1_padding(message_len_bits)

    registers = struct.unpack(">5I", mac)

    added_message = b";admin=true"
    final_block_length = message_len_bits + (len(glue_padding) + len(added_message)) * 8
    new_mac = sha1_hash(
        added_message, registers=registers, message_length_bits=final_block_length
    )
    to_decrypt = message + glue_padding + added_message
    return cipher.check_mac(to_decrypt, new_mac)


def challenge29():
    cipher = Encryption()
    result = sha1_length_extension(cipher, 16)
    print(f"Result: {result}")


def test_mac():
    cipher = Encryption()
    message, mac = cipher.generate_mac()
    print(cipher.check_mac(message, mac))
    print(cipher.check_mac(message + b";admin=true", mac))


if __name__ == "__main__":
    challenge29()
