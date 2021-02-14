from fractions import Fraction
from itertools import zip_longest

import numpy as np

from ..conversions import base64_to_bytes
from ..set5.challenge36 import bytes_to_num, num_to_bytes
from ..set5.challenge39 import rsa_decrypt, rsa_encrypt, rsa_generate_keys


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


class ParityOracle:
    def __init__(self):
        self.plaintext = base64_to_bytes(
            "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
        )
        # self.plaintext = b'ABCD;'
        self.e, self.private, self.modulus = rsa_generate_keys(num_bits=1024)
        self.ciphertext = rsa_encrypt(self.plaintext, self.e, self.modulus)

    def get_public_key(self):
        """Returns the public key (n, e)"""
        return self.modulus, self.e

    def get_ciphertext(self):
        return self.ciphertext

    def decrypt_odd(self, ciphertext):
        """Decrypts the integer `ciphertext` and returns True if the plaintext is odd"""
        message = rsa_decrypt(ciphertext, self.private, self.modulus)
        message_num = bytes_to_num(message)
        # print(f'Message num: {bin(message_num)}')
        return message_num % 2 == 1


def get_plaintext_parity_oracle_v1(oracle):
    """Gets the plaintext from a parity oracle"""
    current_ciphertext = oracle.get_ciphertext()
    n, e = oracle.get_public_key()
    # plaintext is a list of booleans with the first element corresponding to the first bit of the message
    plaintext = []
    multiplier = (1 << e) % n
    # multiplier = pow(2, e, n)
    num_bits = 8 * ((n.bit_length() + 7) // 8)
    # high = n
    # return 0
    # while high > low:
    #     mid = (high + low) / 2

    for i in range(num_bits):
        current_ciphertext = (current_ciphertext * multiplier) % n
        is_odd = oracle.decrypt_odd(current_ciphertext)
        # if the plaintext is odd, the original message wrapped, meaning the high bit is a 1, otherwise the last bit is a 0
        plaintext.append(is_odd)
        # Whether the plaintext wraps and becomes odd is only dependent on the current iteration because
        # the plaintext would be even if it didn't wrap regardless of the original plaintext

        # FIXME: this breaks when the plaintext multiplied by whatever power of 2 reaches a bit length longer than
        # either the modulus or the primes involved (possibly causing it to wrap, making it give really weird results?)
        # uncomment the lines below and see where it fails to see the issue

        # current_plaintext = bytes_to_num(
        #     rsa_decrypt(current_ciphertext, oracle.private, n))
        # assert current_plaintext % bytes_to_num(b'Hello') == 0
        # print(current_plaintext // bytes_to_num(b'Hello'))
        print(i)
        print_bitstring(plaintext)

    # while current_ciphertext > 0:


def get_plaintext_parity_oracle(oracle):
    # TODO: this occasionally messes up the last byte of the plaintext (I don't know why)
    current_ciphertext = oracle.get_ciphertext()

    n, e = oracle.get_public_key()
    high = Fraction(n)
    low = Fraction(0)
    multiplier = pow(2, e, n)
    while abs(high - low) > 1:
        current_ciphertext = (current_ciphertext * multiplier) % n
        is_odd = oracle.decrypt_odd(current_ciphertext)
        if is_odd:
            # plaintext wrapped, in the upper half
            low = (high + low) / 2
        else:
            # plaintext didn't wrap, in the lower half
            # high = divide_round_up(high + low, 2)
            high = (high + low) / 2

        # current_plaintext = bytes_to_num(
        #     rsa_decrypt(current_ciphertext, oracle.private, n))
        # assert current_plaintext % bytes_to_num(b'A') == 0
        # print(current_plaintext // bytes_to_num(b'A'))

        # print(num_to_bytes(int(high)), low, high)
        print_bytes(num_to_bytes(int(high)))
        # print(math.floor(low), math.floor(high))
    high_int = int(high)
    low_int = int(low)
    print(f"High: {num_to_bytes(high_int)}")
    print(f"Low: {num_to_bytes(low_int)}")
    assert high_int - low_int == 1
    original_odd = oracle.decrypt_odd(oracle.get_ciphertext())
    if high_int % 2 == 1:
        odd_num = high_int
        even_num = low_int
    else:
        odd_num = low_int
        even_num = high_int
    if original_odd:
        plaintext = odd_num
    else:
        plaintext = even_num
    return num_to_bytes(plaintext)


def print_bytes(bytestring):
    """Prints the bytestring with escape sequences"""
    string = ""
    for c in bytestring:
        if 0x20 <= c < 0x7F:
            string += chr(c)
        else:
            string += r"\x" + hex(c)[2:]
    print(string)


def divide_round_up(a, b):
    """Calculates a / b rounded up to the nearest integer"""
    if a % b < b / 2:
        return a // b
    else:
        return (a // b) + 1


def print_bitstring(bitstring):
    """Takes a list of booleans, interprets them as bits in a UTF-8 encoded string, and then prints them"""
    byte_list = []
    for bits in grouper(bitstring, 8, fillvalue=False):
        num = int(np.packbits(np.uint8(bits)))
        byte_list.append(num)
    bytestring = bytes(byte_list)
    try:
        as_string = bytestring.decode("utf-8")
        print(as_string)
    except UnicodeDecodeError:
        print(bytestring)


def challenge46():
    oracle = ParityOracle()
    plaintext = get_plaintext_parity_oracle(oracle)
    print(f"Final plaintext: {plaintext}")


if __name__ == "__main__":
    challenge46()
