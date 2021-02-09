from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from conversions import base64_to_bytes
from set1.challenge1_2 import xor_bytes
from set1.challenge7 import decrypt_AES_ECB
from set1.challenge8 import get_blocks


def challenge2():
    with open("10.txt") as handle:
        base_64_contents = handle.read()
    contents = base64_to_bytes(base_64_contents)
    plaintext = decrypt_AES_CBC(contents, b"YELLOW SUBMARINE", b"\x00" * 16)
    print(plaintext.decode("utf8"))


def decrypt_AES_CBC(ciphertext, key, iv):
    unxored_plaintext = decrypt_AES_ECB(ciphertext, key)
    # -16 takes off last block - last block isn't xored with anything
    to_xor = iv + ciphertext[:-16]
    return xor_bytes(unxored_plaintext, to_xor)


def encrypt_AES_CBC(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES encrypts the bytestring `plaintext` in CBC mode using the given key and iv"""
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext is not the correct length")
    plaintext_blocks = get_blocks(plaintext, 16)
    prev_ciphertext_block = iv
    encrypted = b""
    for block in plaintext_blocks:
        after_xor = xor_bytes(block, prev_ciphertext_block)
        ciphertext_block = encrypt_AES_ECB(after_xor, key)
        prev_ciphertext_block = ciphertext_block
        encrypted += ciphertext_block
    return encrypted


def encrypt_AES_ECB(plaintext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def test_encrypt_AES():
    key = get_random_bytes(16)
    message = b"ABCDEFGHIJKLMNOP HELLO my name is abcdefghijklmn"
    encrypted = encrypt_AES_ECB(message, key)
    decrypted = decrypt_AES_ECB(encrypted, key)
    print("ECB: ", decrypted)
    iv = get_random_bytes(16)
    encrypted = encrypt_AES_CBC(message, key, iv)
    decrypted = decrypt_AES_CBC(encrypted, key, iv)
    print(f"CBC: {decrypted}")


if __name__ == "__main__":
    test_encrypt_AES()
    # challenge2()
