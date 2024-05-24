from Crypto.Cipher import AES

from ..conversions import base64_to_bytes


def decrypt_AES_ECB(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def challenge7():
    with open("7.txt") as file_handle:
        encrypted_b64 = file_handle.read()
    encrypted = base64_to_bytes(encrypted_b64)
    print(encrypted)


if __name__ == "__main__":
    challenge7()
