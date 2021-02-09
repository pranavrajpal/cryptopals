import random
from typing import Dict

from Crypto.Random import get_random_bytes

from conversions import base64_to_bytes
from set1.challenge1_2 import xor_bytes
from set1.challenge8 import get_blocks
from set2.challenge1 import pkcs7_pad, pkcs7_unpad
from set2.challenge2 import decrypt_AES_CBC, encrypt_AES_CBC


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)
        self.iv = get_random_bytes(16)

    def encrypt(self):
        encrypt_options = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ]
        input_text = base64_to_bytes(random.choice(encrypt_options))
        padded = pkcs7_pad(input_text, 16)
        encrypted = encrypt_AES_CBC(padded, self.key, self.iv)
        return (encrypted, self.iv)

    def decrypt(self, ciphertext):
        decrypted = decrypt_AES_CBC(ciphertext, self.key, self.iv)
        return check_valid_padding(decrypted)


def get_plaintext(cipher, ciphertext, iv, block_size):
    blocks = get_blocks(ciphertext, block_size)
    prev_block = iv

    known = b""
    for block in blocks:
        ith_block = get_key_one_block(cipher, prev_block, block, block_size)
        prev_block = block
        known = known + ith_block
    return known


def check_valid_padding(bytestring):
    try:
        pkcs7_unpad(bytestring)
        return True
    except ValueError as e:
        if "PKCS" in e.args[0]:
            return False
        else:
            raise


def get_key_one_block(cipher, prev_block, current_block, block_size):
    known = bytearray()
    found_solution = True
    for i in range(block_size):
        ith_char = get_key_one_byte(
            cipher, prev_block, current_block, known, block_size
        )
        if ith_char is None:
            found_solution = False
            break
        known.insert(0, ith_char)
    if found_solution:
        return known
    possible_guesses_padding = []
    for padding_guess in range(1, block_size + 1):
        known_padding = bytearray()
        correct_padding_guess = True
        for i in range(block_size):
            if i < padding_guess:
                ith_char = get_key_one_byte(
                    cipher,
                    prev_block,
                    current_block,
                    known_padding,
                    block_size,
                    padding=padding_guess,
                )
            else:
                ith_char = get_key_one_byte(
                    cipher, prev_block, current_block, known_padding, block_size
                )
            if ith_char is None:
                correct_padding_guess = False
                break
            known_padding.insert(0, ith_char)
        # check if all 16 characters found correctly
        if correct_padding_guess and check_valid_padding(known_padding):

            possible_guesses_padding.append(known_padding)
    if len(possible_guesses_padding) == 1:
        return possible_guesses_padding[0]
    else:
        # TODO: figure out what to do when multiple possibilites are possible - this just returns the element with the most padding
        pad_lengths = {
            bytes(bytestring): block_size - len(pkcs7_unpad(bytestring))
            for bytestring in possible_guesses_padding
        }
        most_padded = sorted(
            pad_lengths, key=lambda key: pad_lengths[key], reverse=True
        )
        return most_padded[0]

        # if len(known) < block_size:
        #     extra = b'A' * (block_size - len(known))
        #     known = extra + known


def get_key_one_byte(
    cipher, prev_block, current_block, known, block_size, padding=None
):
    byte_index = block_size - len(known) - 1
    original_ciphertext_byte = prev_block[byte_index]
    # expected_byte is the byte expected at the current position in the padding
    if padding is not None:
        # input value for padding is byte to expect for padding
        expected_byte = padding
    else:
        expected_byte = len(known) + 1

    already_known = b""
    if len(known) != 0:
        prev_block_end = prev_block[-len(known) :]
        xor_known = xor_bytes(known, [expected_byte] * len(known))
        already_known = xor_bytes(prev_block_end, xor_known)
    for byte_guess in range(0, 0xFF + 1):
        as_bytestring = bytes([byte_guess])
        prefix = prev_block[:byte_index]
        input_ciphertext = prefix + as_bytestring + already_known + current_block

        padded_correct = cipher.decrypt(input_ciphertext)

        if padded_correct:
            # found the correct byte
            # byte_guess xor intermediate_byte == expected_byte
            # return (byte_guess, expected_byte)

            intermediate_byte = expected_byte ^ byte_guess
            plaintext_byte = intermediate_byte ^ original_ciphertext_byte
            return plaintext_byte


def challenge1():
    cipher = Encryption()
    plaintext_dict: Dict[int, str] = {}
    while len(plaintext_dict) < 10:
        # pretty print output of number of strings found
        num_found = len(plaintext_dict)
        print(f"\rFound {num_found} lyrics", end="")

        ciphertext, iv = cipher.encrypt()
        plaintext_bytes = get_plaintext(cipher, ciphertext, iv, 16)
        plaintext_with_num = pkcs7_unpad(plaintext_bytes).decode("utf-8")
        num = int(plaintext_with_num[:6])
        plaintext = plaintext_with_num[6:]
        plaintext_dict[num] = plaintext

    print()
    sorted_dict = sorted(plaintext_dict)
    plaintext_final = [plaintext_dict[k] for k in sorted_dict]
    print("Plaintext:")
    print("\n".join(plaintext_final))


if __name__ == "__main__":
    challenge1()
