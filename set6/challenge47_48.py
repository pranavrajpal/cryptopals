import math
from itertools import zip_longest
from typing import List, Optional

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

from ..set5.challenge36 import num_to_bytes
from ..set5.challenge39 import rsa_decrypt, rsa_encrypt, rsa_generate_keys


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


class PKCSOracle:
    def __init__(self, message=b"kick it, CC", num_bits=128):
        self.e, self.private, self.modulus = rsa_generate_keys(num_bits=num_bits)
        self.block_length = ceildiv(self.modulus.bit_length(), 8)
        self.plaintext = pkcs_pad_encryption(message, self.block_length)
        self.ciphertext = rsa_encrypt(self.plaintext, self.e, self.modulus)

    def get_public_key(self):
        """Returns the public key (n, e)"""
        return self.modulus, self.e

    def get_ciphertext(self):
        return self.ciphertext

    def decrypt_pkcs(self, ciphertext):
        """Decrypts the integer `ciphertext` and returns True if the plaintext is PKCS conformant"""
        message = rsa_decrypt(ciphertext, self.private, self.modulus)
        message_correct_length = message.rjust(self.block_length, b"\x00")
        # assert len(message_correct_length) == self.block_length

        # Note: this attack takes much longer when adding the requirement that there must be a null
        # byte in the message because more messages have to be tried to reach this requirement
        # 10 = 2 for b'\x00\x02' and at least 8 padding bytes
        if message_correct_length.startswith(b"\x00\x02"):
            print(True, message_correct_length)
            # return b'\x00' in message_correct_length[10:]
            return True
        # print(False, message_correct_length)
        return False


def pkcs_pad_encryption(message, block_length):
    """Pads the bytestring `message` into a PKCS1.5 block for encryption"""

    def get_random_nonnull_bytes(length):
        bytestring = bytearray(b"\x00" + get_random_bytes(length - 1))
        try:
            while True:
                null_index = bytestring.index(b"\x00")
                bytestring[null_index] = randint(1, 255)
        except ValueError:
            return bytestring

    message_length = len(message)
    padding_length = block_length - (3 + message_length)
    if padding_length < 8:
        raise ValueError("not enough padding")
    padding = get_random_nonnull_bytes(padding_length)
    block = b"\x00\x02" + padding + b"\x00" + message
    return block


def pkcs_unpad_encryption(bytestring, block_length):
    """Takes a PKCS1.5 block and returns the message"""
    correct_length_bytestring = bytestring.rjust(block_length, b"\x00")
    if correct_length_bytestring[:2] != b"\x00\x02":
        raise ValueError(
            f"Bytestring isn't PKCS1.5 formatted: {correct_length_bytestring}"
        )
    null_index = correct_length_bytestring.index(b"\x00", 2)
    return correct_length_bytestring[null_index + 1 :]


# ------------------ Old PKCS padding oracle code ------------------------------------

# def pkcs_padding_oracle_v1(oracle):
#     def increment_until_pkcs(start, maximum=math.inf):
#         """Start with s = `start` and keep incrementing s until ciphertext * (s ** e) is PKCS1.5 conforming

#         Specify a maximum to stop at - will keep going forever if not specified"""
#         s = start
#         while s < maximum:
#             is_pkcs = oracle.decrypt_pkcs(ciphertext * pow(s, e, n))
#             if is_pkcs:
#                 return s
#             s += 1

#     def find_r_and_s(s_prev, message_range):
#         """Returns the tuple (ri, si)"""
#         a, b = message_range
#         ri = ceildiv(2 * (b * s_prev - 2 * B), n)
#         print('Ri =', ri)
#         while True:
#             lower_s_bound = ceildiv((2 * B + ri * n), b)
#             upper_s_bound = ((3 * B + ri * n) // a)
#             si = increment_until_pkcs(lower_s_bound, upper_s_bound)
#             print('Bounds', lower_s_bound, upper_s_bound,
#                   upper_s_bound - lower_s_bound)
#             if si is not None:
#                 return ri, si
#             ri += 1

#     ciphertext = oracle.get_ciphertext()
#     n, e = oracle.get_public_key()
#     B = 1 << (n.bit_length() - 16)
#     message_range = [2*B, 3 * B - 1]
#     # Step 2a
#     s_prev = increment_until_pkcs(ceildiv(n, (3 * B)))

#     while True:
#         # Step 2c
#         a, b = message_range
#         ri, si = find_r_and_s(s_prev, message_range)
#         # Step 3
#         message_range[0] = max(a, ceildiv((2 * B + ri * n), si))
#         message_range[1] = min(b, ((3 * B - 1 + ri * n) // si))
#         if message_range[0] == message_range[1]:
#             return message_range[0]
#         s_prev = si
#         print(f'Range: {message_range}')
#         print(f'Difference: {message_range[1] - message_range[0]}')

# ------------------ End old PKCS padding oracle code ------------------------------------


def ceildiv(a, b):
    """Returns the ceiling of a / b, equivalent to math.ceil(a / b)"""
    return (a + b - 1) // b


def pkcs_padding_oracle(oracle):
    c0 = oracle.get_ciphertext()

    n, e = oracle.get_public_key()
    B = 1 << (n.bit_length() - 16)
    # message_range is a list of closed intervals, each represented by a tuple of (lower_bound, upper_bound)
    message_range = [(2 * B, 3 * B - 1)]

    def increment_until_pkcs(start_val: int, max_val=math.inf) -> Optional[int]:
        """Increment `start_val` until it is a valid PKCS ciphertext, keeping the value in
        the interval [start_val, max_val)"""
        s = start_val
        while True:
            ciphertext = c0 * pow(s, e, n)
            if oracle.decrypt_pkcs(ciphertext):
                return s
            if s >= max_val:
                return None
            s += 1

    def find_r_and_s(current_s):
        """Returns the tuple (ri, si)"""
        # assuming only one interval left
        a, b = message_range[0]
        ri = ceildiv(2 * (b * current_s - 2 * B), n)
        while True:
            si_lower_bound = ceildiv((2 * B + ri * n), b)
            si_upper_bound = (3 * B + ri * n) // a
            si = increment_until_pkcs(si_lower_bound, max_val=si_upper_bound)
            if si is not None:
                return ri, si
            ri += 1

    def remove_duplicate_intervals(interval_list):
        """Takes a list of closed intervals of the form [(opening, closing)] and returns a list of intervals without any overlapping regions"""
        # sorts by the first element of the tuple automatically
        sorted_intervals = sorted(interval_list)

        def interval_in_order(interval):
            if interval[0] > interval[1]:
                interval = interval[1], interval[0]
            return interval

        def get_nonoverlapping(interval1, interval2):
            """Returns a list of intervals that are not overlapping that will either have 2 nonoverlapping intervals or 1 interval"""
            if interval1[1] >= interval2[0]:
                return [(interval1[0], interval2[1])]
            else:
                return [interval1, interval2]

        while True:
            new_intervals = []
            for interval1, interval2 in grouper(sorted_intervals, 2):
                if interval2 is None:
                    new_intervals.append(interval1)
                    break
                new_intervals.extend(get_nonoverlapping(interval1, interval2))
            # repeat this process until list isn't changed
            if len(sorted_intervals) == len(new_intervals):
                break
            sorted_intervals = new_intervals
        return new_intervals

    s: List[Optional[int]] = [None]
    # find s1 = s[0] (Step 2a)
    s[0] = increment_until_pkcs(ceildiv(n, 3 * B))
    print(f"Found s1: {s[0]}")

    while True:
        if len(message_range) >= 2:
            # Step 2b (searching with multiple intervals)
            # should have found s[0] by now, so s[-1] shouldn't be None
            new_s = increment_until_pkcs(s[-1] + 1)  # type: ignore
            s.append(new_s)
        else:
            # Step 2c (searching with one interval)
            ri, si = find_r_and_s(s[-1])
            s.append(si)
        # Step 3 (Narrowing the set of solutions)
        current_s = s[-1]
        new_message_range = []
        # FIXME: a is somehow ending up greater than b in one of the intervals, which is messing
        # up the calculations for r's upper and lower bounds, leading to an r interval size of 0,
        # which causes the message range to become empty, leading to an IndexError in find_r_and_s
        # when it tries to access message_range[0]
        # FIXME: see above comment - also r_upper_bound is sometimes less than r_lower_bound, and
        # some runs freeze at some point and take a really long time (probably in find_r_and_s)
        # This has worked once, printing out the correct message, but is very unreliable
        print(f"Message_range length: {len(message_range)}")
        for a, b in message_range:
            assert a <= b
            r_lower_bound = ceildiv((a * current_s - 3 * B + 1), n)
            r_upper_bound = (b * current_s - 2 * B) // n
            print(a, b, current_s, a <= b)
            # if r_lower_bound > r_upper_bound:
            #     continue

            print(f"R interval size = {r_upper_bound - r_lower_bound}")
            for r in range(r_lower_bound, r_upper_bound + 1):
                m_lower = max(a, ceildiv((2 * B + r * n), current_s))
                m_upper = min(b, ((3 * B - 1 + r * n) // current_s))
                assert m_lower <= m_upper
                # if m_lower <= m_upper:
                new_message_range.append((m_lower, m_upper))
        message_range = remove_duplicate_intervals(new_message_range)
        # message_range = new_message_range
        # message_range.extend(new_message_range)
        # message_range = remove_duplicate_intervals(message_range)
        # print(f'Amount in message intervals: {')
        # print(f'Length: {len(message_range)}')
        # Step 4 (Computing the solution)
        if len(message_range) == 1:
            print("Message range length = 1", message_range)
            a, b = message_range[0]
            if a == b:
                # a = b = original plaintext
                return num_to_bytes(a)


def amount_in_intervals(interval_list):
    """Returns the total amount of numbers covered by the intervals in the interval list"""
    amount = 0
    for a, b in interval_list:
        amount += b - a
    return amount


def challenge47():
    oracle = PKCSOracle()
    # Test that the oracle is working
    assert oracle.decrypt_pkcs(oracle.get_ciphertext())
    assert not oracle.decrypt_pkcs(oracle.get_ciphertext() + 1)
    padded_plaintext = pkcs_padding_oracle(oracle)
    plaintext = pkcs_unpad_encryption(padded_plaintext, oracle.block_length)
    print(f"Challenge 47 Plaintext: {plaintext}")


def challenge48():
    message = b"This is a longer message"
    # 384 = 768 / 2 (384-bit primes means 768 bit modulus)
    oracle = PKCSOracle(num_bits=384, message=message)
    # Test that the oracle is working
    # assert oracle.decrypt_pkcs(oracle.get_ciphertext())
    # assert not oracle.decrypt_pkcs(oracle.get_ciphertext() + 1)
    padded_plaintext = pkcs_padding_oracle(oracle)
    plaintext = pkcs_unpad_encryption(padded_plaintext, oracle.block_length)
    print(f"Challenge 48 plaintext: {plaintext}")


if __name__ == "__main__":
    # challenge47()
    challenge48()
