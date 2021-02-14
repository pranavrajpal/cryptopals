import secrets

from Crypto.Random import get_random_bytes

from ..set1.challenge1_2 import xor_bytes
from ..set2.challenge8 import url_decode_bytes
from ..set3.challenge2 import encrypt_AES_CTR


class Encryption:
    # copied from ..set2 challenge8
    def __init__(self):
        self.key = get_random_bytes(16)
        self.nonce = secrets.randbits(64)

    def encrypt(self, input_string):
        safe_input = input_string.replace(";", "%3B").replace("=", "%3D")
        safe_input_bytes = safe_input.encode("utf-8")
        to_encrypt = (
            b"comment1=cooking%20MCs;userdata="
            + safe_input_bytes
            + b";comment2=%20like%20a%20pound%20of%20bacon"
        )
        encrypted = encrypt_AES_CTR(to_encrypt, self.key, self.nonce)
        return encrypted

    def decrypt(self, encrypted_bytes):
        decrypted = encrypt_AES_CTR(encrypted_bytes, self.key, self.nonce)
        dictionary = url_decode_bytes(decrypted)
        is_admin = False
        if b"admin" in dictionary and (
            dictionary[b"admin"] == "true" or dictionary[b"admin"] == b"true"
        ):
            is_admin = True
        return (dictionary, is_admin)


def attack_CTR_bitflipping(cipher):
    goal_message = b"abcdefgh;admin=true"
    prefix_len = len(b"comment1=cooking%20MCs;userdata=")
    encrypted = cipher.encrypt("\0" * len(goal_message))
    suffix_len = len(encrypted) - (prefix_len + len(goal_message))
    to_xor = b"\0" * prefix_len + goal_message + b"\0" * suffix_len
    modified = xor_bytes(encrypted, to_xor)
    decrypted = cipher.decrypt(modified)
    return decrypted


def challenge26():
    cipher = Encryption()
    decrypted = attack_CTR_bitflipping(cipher)
    print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    challenge26()
