import time

import requests

from ...conversions import bytes_to_hex
from .helper_functions import hmac_sha1

HMAC_SIZE = 20


def check_signature(filename, signature_bytes):
    signature_hex = bytes_to_hex(signature_bytes)
    data = {"file": filename, "signature": signature_hex}
    response = requests.get("http://localhost:9000/test", params=data)
    if response.status_code == 200:
        return True
    elif response.status_code == 500:
        return False
    else:
        raise ValueError("Invalid status code")


def find_hmac_file(filename, delay_ms):
    prefix = bytearray()
    for index in range(HMAC_SIZE):
        byte_guess = find_hmac_byte(filename, prefix, delay_ms)
        prefix.append(byte_guess)
        print(f"Found byte {index}: {byte_guess}")
    return prefix


def find_hmac_byte(filename, prefix, delay_ms_per_byte):
    # dictionary of byte possibilities with their times -
    # highest means the signature was reported correct
    guesses = {}
    padding_amount = HMAC_SIZE - 1 - len(prefix)
    padding = b"\0" * padding_amount
    expected_time_correct = (len(prefix) + 1) * delay_ms_per_byte
    for byte_guess in range(0, 0xFF + 1):
        # copy to prevent modification of prefix
        guess = bytearray(prefix)
        guess.append(byte_guess)
        guess.extend(padding)
        # assert len(guess) == 20
        start = time.time()
        correct = check_signature(filename, guess)
        end = time.time()
        if correct:
            return byte_guess
        else:
            elapsed = end - start
            if elapsed > expected_time_correct:
                return byte_guess

            guesses[byte_guess] = end - start
    sorted_guesses = sorted(guesses, key=lambda key: guesses[key], reverse=True)
    # returns best byte guess, either the byte that returned the correct value
    # or the guess that took the most time
    return sorted_guesses[0]


def challenge31():
    # Expects the server to already be running to work
    expected_hmac = hmac_sha1(b"\0" * 16, open("hmac_test.txt", "rb").read())
    print(bytes_to_hex(expected_hmac))
    hmac = find_hmac_file("hmac_test.txt", 50)
    print(f"Found HMAC: {bytes_to_hex(hmac)}")


if __name__ == "__main__":
    challenge31()
