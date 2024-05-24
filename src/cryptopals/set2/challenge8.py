from Crypto.Random import get_random_bytes

from ..set1.challenge1_2 import xor_bytes
from ..set1.challenge8 import get_blocks
from ..set2.challenge1 import pkcs7_pad, pkcs7_unpad
from ..set2.challenge2 import decrypt_AES_CBC, encrypt_AES_CBC


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)

    def encrypt(self, input_string):
        safe_input = input_string.replace(";", "%3B").replace("=", "%3D")
        safe_input_bytes = safe_input.encode("utf-8")
        to_encrypt = (
            b"comment1=cooking%20MCs;userdata="
            + safe_input_bytes
            + b";comment2=%20like%20a%20pound%20of%20bacon"
        )
        padded = pkcs7_pad(to_encrypt, 16)
        encrypted = encrypt_AES_CBC(padded, self.key, self.iv)
        return encrypted

    def decrypt(self, encrypted_bytes):
        decrypted = decrypt_AES_CBC(encrypted_bytes, self.key, self.iv)
        unpadded = pkcs7_unpad(decrypted)
        dictionary = url_decode_bytes(unpadded)
        is_admin = False
        if b"admin" in dictionary and (
            dictionary[b"admin"] == "true" or dictionary[b"admin"] == b"true"
        ):
            is_admin = True
        return (dictionary, is_admin)


def url_decode_bytes(input_bytes, separator=b";"):
    pairs = input_bytes.split(b";")
    dictionary = {}
    for pair in pairs:
        key, val = pair.split(b"=")
        dictionary[bytes(key)] = bytes(val)
    return dictionary


def flip_bits_attack(cipher):
    goal_input = b"aaaaa;admin=true"
    to_xor = b"\x00" * 5 + b"\x01" + b"\x00" * 5 + b"\x01" + b"\x00" * 4
    modified_input = xor_bytes(goal_input, to_xor)
    modified_input_string = modified_input.decode("utf-8")
    encrypted = cipher.encrypt(modified_input_string)
    blocks = get_blocks(encrypted, 16)
    blocks[1] = xor_bytes(blocks[1], to_xor)
    modified_encrypted = b"".join(blocks)
    decrypted = cipher.decrypt(modified_encrypted)
    return decrypted


def challenge8():
    cipher = Encryption()
    output = flip_bits_attack(cipher)
    print(f"Output: {output}")


if __name__ == "__main__":
    challenge8()
