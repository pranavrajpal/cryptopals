import statistics
import time

import requests
from challenge31 import check_signature, find_hmac_file
from helper_functions import hmac_sha1

from conversions import bytes_to_hex

# constants
ROUNDS = 10
HMAC_SIZE = 20


def challenge32():
    filename = "hmac_test.txt"
    expected_hash = bytes_to_hex(hmac_sha1(b"\0" * 16, open(filename, "rb").read()))
    print(f"Expected hash: {expected_hash}")
    start_time = time.time()
    # TODO: try to get this to work - currently fails relatively often (never succeeded yet)
    # sometimes works but very unreliable
    # TODO: also takes a long amount of time, especially as number of rounds increases
    # took 10 minutes with 5 rounds, 30 minutes with 10 rounds
    # FIXME: keeps breaking on the 3rd byte - got 0xb0 today when it should have
    # gotten 0xdf
    calculated_hmac = find_hmac_file_v2(filename)
    end_time = time.time()
    print(f"Calculated HMAC: {calculated_hmac}")
    print(f"Took {end_time - start_time} seconds")
    correct = check_signature(filename, calculated_hmac)
    print(f"Correct? {correct}")


def find_hmac_file_v2(filename):
    prefix = bytearray()
    for index in range(HMAC_SIZE):
        byte_guess = find_hmac_byte_v2(filename, prefix)
        prefix.append(byte_guess)
        print(f"Found byte {index}: {byte_guess}")
    return prefix


def find_hmac_byte_v2(filename, prefix):
    # dictionary of byte possibilities with their times -
    # highest means the signature was reported correct
    guesses = {}
    correct_signature = None
    padding_amount = HMAC_SIZE - 1 - len(prefix)
    padding = b"\0" * padding_amount
    for byte_guess in range(0, 0xFF + 1):
        # copy to prevent modification of prefix
        guess = bytearray(prefix)
        guess.append(byte_guess)
        guess.extend(padding)
        # assert len(guess) == 20
        # move check for correctness to here so we don't have to check again for every round
        correct, elapsed = check_signature_time(filename, guess)
        if correct:
            return byte_guess
        times = [elapsed]
        for round in range(ROUNDS):
            correct, elapsed = check_signature_time(filename, guess)
            times.append(elapsed)
        # use the median to avoid outliers - possibly due to network connection
        # guesses[byte_guess] = statistics.median(times)
        # try smallest value - ignores outliers that took longer due to network delay
        guesses[byte_guess] = min(times)
    sorted_guesses = sorted(guesses, key=lambda key: guesses[key], reverse=True)
    # returns best byte guess, either the byte that returned the correct value
    # or the guess that took the most time
    return sorted_guesses[0]


def check_signature_time(filename, signature_bytes):
    signature_hex = bytes_to_hex(signature_bytes)
    data = {"file": filename, "signature": signature_hex}
    start_time = time.perf_counter()
    response = requests.get("http://localhost:9000/test", params=data)
    end_time = time.perf_counter()
    elapsed = end_time - start_time
    if response.status_code == 200:
        return True, elapsed
    elif response.status_code == 500:
        return False, elapsed
    else:
        raise ValueError("Invalid status code")


if __name__ == "__main__":
    challenge32()
