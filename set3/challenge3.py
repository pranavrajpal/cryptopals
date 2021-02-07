from conversions import base64_to_bytes
from Crypto.Random import get_random_bytes
from set1.challenge1_2 import xor_bytes
from set1.challenge3 import brute_force_single_byte_xor

from .challenge2 import encrypt_AES_CTR
from .challenge3_data import decrypted_text


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, plaintext_list):
        encrypted = []
        for line in plaintext_list:
            as_bytes = base64_to_bytes(line)
            encrypted_line = encrypt_AES_CTR(as_bytes, self.key, 0)
            encrypted.append(encrypted_line)
        return encrypted


def get_bytestring_at_index(bytestring_list, index):
    bytes_list = []
    for bytestring in bytestring_list:
        if index < len(bytestring):
            bytes_list.append(bytestring[index])
    return bytes(bytes_list)


def guess_keystream(bytestring_list):
    current_bytes = get_bytestring_at_index(bytestring_list, 0)
    # start at 1 because above line already started at 0
    index = 1
    keystream = []
    while current_bytes != b"":
        keystream_bytes = brute_force_single_byte_xor(current_bytes)
        correct_byte, score, decrypted = keystream_bytes[0]
        keystream.append(correct_byte)
        current_bytes = get_bytestring_at_index(bytestring_list, index)
        index += 1
    return bytes(keystream)


def challenge3():
    cipher = Encryption()
    encrypted_list = cipher.encrypt(decrypted_text)
    keystream = guess_keystream(encrypted_list)
    plaintext_bytestring_list = []
    for encrypted_line in encrypted_list:
        shortened_keystream = keystream[: len(encrypted_line)]
        plaintext_line = xor_bytes(shortened_keystream, encrypted_line)
        plaintext_bytestring_list.append(plaintext_line)
    plaintext = [bytestring.decode("utf-8") for bytestring in plaintext_bytestring_list]
    print("\n".join(plaintext))


if __name__ == "__main__":
    challenge3()
