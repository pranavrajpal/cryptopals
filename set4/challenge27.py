from Crypto.Random import get_random_bytes
from set2.challenge1 import pkcs7_unpad, pkcs7_pad
from set2.challenge2 import encrypt_AES_CBC, decrypt_AES_CBC
from set2.challenge8 import url_decode_bytes
from set1.challenge1_2 import xor_bytes
from set1.challenge8 import get_blocks
from set2.challenge5 import url_decode, url_encode


class Encryption:
    # copied from set2 challenge8
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, input_string):
        padded = pkcs7_pad(input_string, 16)
        encrypted = encrypt_AES_CBC(padded, self.key, self.key)
        return encrypted

    def decrypt(self, encrypted_bytes):
        decrypted = decrypt_AES_CBC(encrypted_bytes, self.key, self.key)
        unpadded = pkcs7_unpad(decrypted)
        try:
            ascii_text = unpadded.encode('ascii')
        except:
            # return decrypted message when invalid ascii
            return unpadded
        # if valid ascii, then return nothing


def determine_padding(cipher, ciphertext):
    blocks = get_blocks(ciphertext, 16)
    c1 = blocks[0]
    for byte_guess in range(0, 0xff + 1):
        middle_block = bytes([0] * 15 + [byte_guess])
        modified = c1 + middle_block + c1
        try:
            cipher.decrypt(modified)
            return byte_guess
        except ValueError as e:
            # padding exception
            if 'PKCS' not in e.args[0]:
                print(e)
                raise


def recover_key(cipher, ciphertext):
    blocks = get_blocks(ciphertext, 16)
    c1 = blocks[0]
    # modified = c1 + b'\0' * 16 + c1
    # decrypted = cipher.decrypt(modified)
    padding_byte = determine_padding(cipher, ciphertext)
    modification = 0
    while True:
        modified_c1 = xor_bytes(modification.to_bytes(16, 'big'), c1)
        middle_block = bytes([0] * 15 + [padding_byte])
        modified_ciphertext = modified_c1 + middle_block + modified_c1
        decrypted = cipher.decrypt(modified_ciphertext)
        if decrypted is not None:
            # invalid ascii error
            decrypted_blocks = get_blocks(decrypted, 16)
            last_block_padded = pkcs7_pad(decrypted_blocks[2], 16)
            key_with_middle_block = xor_bytes(
                decrypted_blocks[0], last_block_padded)
            key = xor_bytes(middle_block, key_with_middle_block)
            return key
        modification += 1


def challenge27():
    cipher = Encryption()
    message = b'HELLO ABCDEFGH WORLD This is a test message 123456'
    ciphertext = cipher.encrypt(message)
    key = recover_key(cipher, ciphertext)
    recovered_plaintext = decrypt_AES_CBC(ciphertext, key, key)
    unpadded = pkcs7_unpad(recovered_plaintext).decode('utf-8')
    print(f'Key: {key}')
    print(f'Recovered plaintext: {unpadded}')


if __name__ == "__main__":
    challenge27()
