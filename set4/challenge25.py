from set3.challenge2 import encrypt_AES_CTR, generate_keystream
from Crypto.Random import get_random_bytes
from conversions import base64_to_bytes
from set1.challenge1_2 import xor_bytes
import secrets


class Encryption:
    def __init__(self, plaintext):
        self.key = get_random_bytes(16)
        self.nonce = secrets.randbits(64)
        print(f"Plaintext len: {len(plaintext)}")

        self.ciphertext = encrypt_AES_CTR(plaintext, self.key, self.nonce)

    def get_ciphertext(self):
        return self.ciphertext

    def edit(self, offset, newtext):
        keystream = generate_keystream(self.key, self.nonce, offset + len(newtext))[
            offset:
        ]
        before = self.ciphertext[:offset]
        after = self.ciphertext[offset + len(newtext) :]
        middle_encrypted = xor_bytes(keystream, newtext)
        return before + middle_encrypted + after


def get_plaintext_CTR_v2(cipher):
    # xor the keystream with all 0s to get the keystream
    ciphertext = cipher.get_ciphertext()
    print(len(ciphertext))
    keystream = cipher.edit(0, b"\x00" * len(ciphertext))
    plaintext = xor_bytes(keystream, ciphertext)
    return plaintext


def get_plaintext_CTR(cipher):
    ciphertext = cipher.get_ciphertext()
    plaintext = b""
    for index in range(len(ciphertext)):
        print(f"\rGetting character {index} out of {len(ciphertext)}")
        char = get_character_CTR(cipher, index)
        plaintext += char
    return plaintext


def get_character_CTR(cipher, offset):
    original = cipher.get_ciphertext()
    original_char = original[offset]
    for byte_guess in range(0, 0xFF + 1):
        bytestring = bytes([byte_guess])
        reencrypted = cipher.edit(offset, bytestring)
        if reencrypted[offset] == original_char:
            return bytestring


def challenge25():
    with open("25.txt") as handle:
        contents = base64_to_bytes(handle.read())
    cipher = Encryption(contents)
    plaintext = get_plaintext_CTR_v2(cipher)
    print(plaintext)
    print(f"Correct? {plaintext == contents}")


if __name__ == "__main__":
    challenge25()
