from __future__ import annotations

import base64
import string
import zlib
from secrets import randbits

from Crypto.Random import get_random_bytes

from set2.challenge1 import pkcs7_pad
from set2.challenge2 import encrypt_AES_CBC
from set3.challenge2 import encrypt_AES_CTR

BASE64_ALPHABET = string.ascii_letters + string.digits + "-_" + "="

SESSION_ID = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

EXTRA_PADDING = "!\"#$%&'()*+,;<>?"


class Oracle:
    """docstring for Oracle."""

    def __init__(self, cbc: bool):
        """If `cbc` is True, then CBC is used instead of CTR"""
        self.cbc = cbc

    def compression_oracle(self, plaintext: str) -> int:
        """Takes `plaintext` without newline

        Returns the length of the compressed encrypted http request"""
        http_request = "POST / HTTP/1.1\n"
        http_request += "Host: hapless.com\n"
        http_request += f"Cookie: sessionid={SESSION_ID}\n"
        http_request += f"Content-Length: {len(plaintext)}\n"
        http_request += plaintext + "\r\n"

        compressed = zlib.compress(http_request.encode("utf-8"))
        key = get_random_bytes(16)
        if self.cbc:
            padded = pkcs7_pad(compressed, 16)
            encrypted = encrypt_AES_CBC(padded, key, get_random_bytes(16))
        else:
            encrypted = encrypt_AES_CTR(compressed, key, randbits(64))
        return len(encrypted)

    def guess_session_id(self, id: str) -> int:
        return self.compression_oracle(f"sessionid={id}")

    def is_cbc(self) -> bool:
        return self.cbc


def find_session_id(oracle: Oracle) -> str:
    prefixes: list[str] = [""]
    while True:
        current_guesses: dict[str, tuple[int, list[str]]] = {}
        for prefix in prefixes:
            guess = guess_char_with_prefix(oracle, prefix)

            current_guesses[prefix] = guess

        new_prefixes = []
        # min will sort this by the first element of the tuple, which is the length
        min_length = min(current_guesses.values())[0]
        with_min_length = {
            k: (l, chars)
            for k, (l, chars) in current_guesses.items()
            if l == min_length
        }
        for current_prefix, (length, chars) in with_min_length.items():
            # len(chars) can be 64 or 65 because = is included in BASE64_ALPHABET
            if len(chars) >= 64 and current_prefix.endswith("="):
                # All guesses compress the message equally - means that we've probably
                # reached the end of the message
                # If the current prefix also ends with an equal sign, we can be fairly
                # sure that we've reached the end of the message (because equal signs
                # are always at the end)
                return current_prefix
            for c in chars:
                joined = current_prefix + c
                if c == "=":
                    print(f"GUESS WITH EQUAL SIGN: {joined}")
                else:
                    print(joined)
                new_prefixes.append(current_prefix + c)
        prefixes = new_prefixes


def get_uncompressible_padding(length: int) -> str:
    """Return `length` characters of padding that shouldn't be compressible"""
    # EXTRA_PADDING should be uncompressible because those characters don't show up anywhere else
    # that should mean the compressed length increases linearly
    padding = EXTRA_PADDING[:length]
    assert (
        len(padding) == length
    ), f"not enough uncompressible data: {length - len(padding)} more needed"
    return padding


def find_amount_padding(oracle: Oracle, prefix: str) -> int:
    """Find the amount of padding bytes in the oracle needed to have PKCS#7 only have one byte of padding

    `prefix` is the prefix inserted before any padding"""
    prev_len = oracle.guess_session_id(prefix + get_uncompressible_padding(1))
    for length in range(2, 16 + 1):
        enc_len = oracle.guess_session_id(prefix + get_uncompressible_padding(length))
        if enc_len != prev_len:
            # encrypted length changed, meaning that we added the last byte of
            # the block - one less should give exactly one byte of PKCS#7 padding
            return length - 1
        prev_len = enc_len
    raise RuntimeError("couldn't find amount of padding")


def guess_char_with_prefix(oracle: Oracle, prefix: str) -> tuple[int, list[str]]:
    """Returns a list of all session ids with one character added to `prefix`
    that have the minimum compressed length

    Returns the tuple (length, chars) where `chars` is a list of characters
    that return the minimum compressed length and `length` is the compressed
    length"""
    if oracle.is_cbc():
        padding_needed = find_amount_padding(oracle, prefix)
        padding = get_uncompressible_padding(padding_needed)

    lengths = {}
    for c in BASE64_ALPHABET:
        if oracle.is_cbc():
            to_guess = prefix + c + padding
        else:
            to_guess = prefix + c

        lengths[c] = oracle.guess_session_id(to_guess)
    chars = get_key_with_minval(lengths)
    length = lengths[chars[0]]

    return length, chars


def get_key_with_minval(d: dict[str, int]) -> list[str]:
    """Get the list of keys corresponding to the minimum value of `d`"""
    minval = min(d.values())
    return [k for k, v in d.items() if v == minval]


def challenge51():

    print("CTR mode:")
    oracle = Oracle(False)
    guessed = find_session_id(oracle)
    print_results(guessed)
    print("CBC mode:")
    oracle_cbc = Oracle(True)
    guessed = find_session_id(oracle_cbc)
    print_results(guessed)


def print_results(guessed):
    decoded = base64.urlsafe_b64decode(guessed).decode("utf-8")
    print(f"Matches session id?: {guessed == SESSION_ID}")
    print(f"Final guess: {guessed}")
    print(f"Decoded: {decoded}")


if __name__ == "__main__":
    challenge51()
