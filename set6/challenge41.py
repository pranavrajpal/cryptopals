from set5.challenge39 import rsa_decrypt, rsa_encrypt, rsa_generate_keys, inverse_mod
from set5.challenge36 import sha256_hash, bytes_to_num, num_to_bytes
import random


class EncryptionRSA:
    def __init__(self):
        self.e, self.d, self.n = rsa_generate_keys(num_bits=1024)
        self.previous_hashes = []

    def get_public_key(self):
        """Returns the public key as the tuple (e, n)"""
        return self.e, self.n

    def encrypt(self, message):
        return rsa_encrypt(message, self.e, self.n)

    def decrypt(self, ciphertext):
        ciphertext_hash = sha256_hash(num_to_bytes(ciphertext))
        if ciphertext_hash in self.previous_hashes:
            # message has been decrypted before
            return None
        self.previous_hashes.append(ciphertext_hash)
        return rsa_decrypt(ciphertext, self.d, self.n)


def unpadded_rsa_oracle(rsa, ciphertext):
    e, modulus = rsa.get_public_key()
    s = random.randint(0, 1000000) % modulus
    ciphertext_modified = (pow(s, e, modulus) * ciphertext) % modulus
    plaintext_modified = bytes_to_num(rsa.decrypt(ciphertext_modified))
    plaintext = (plaintext_modified * inverse_mod(s, modulus)) % modulus
    return num_to_bytes(plaintext)


def challenge41():
    rsa = EncryptionRSA()
    message = b"{time: 1356304276,\n  social: '555-55-5555',\n}"
    # message = b'This is a super secret message'
    ciphertext = rsa.encrypt(message)
    recovered_plaintext = rsa.decrypt(ciphertext)
    plaintext = unpadded_rsa_oracle(rsa, ciphertext)
    print(f"Plaintext: {plaintext}")


if __name__ == "__main__":
    challenge41()
