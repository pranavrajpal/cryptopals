import itertools
from typing import Dict, Union

from ..set5.challenge39 import inverse_mod

from .challenge43 import (
    get_dsa_constants,
    get_private_dsa_key_message_val,
    get_sha1_fingerprint,
)


def parse_text_file():
    lines = []
    with open("44.txt") as file_handle:
        lines = file_handle.read().splitlines()
    current: Dict[str, Union[str, int]] = {}
    messages = []
    for index, line in enumerate(lines):
        if index != 0 and index % 4 == 0:
            messages.append(current)
            current = {}
        value: Union[str, int]
        key, value = line.split(": ")
        if key == "r" or key == "s":
            value = int(value)
        elif key == "m":
            value = int(value, 16)
        current[key] = value
    return messages


def repeated_nonce_find_private(messages):
    message_pairs = itertools.combinations(messages, 2)
    p, q, g = get_dsa_constants()
    for message1, message2 in message_pairs:
        if message1["r"] == message2["r"]:
            # if k is the same, then r is the same because it only depends on the parameters
            # (which are public and never change) and k
            denominator = inverse_mod(message1["s"] - message2["s"], q)
            numerator = message1["m"] - message2["m"]
            k = (numerator * denominator) % q
            signature = (message1["r"], message1["s"])
            private = get_private_dsa_key_message_val(message1["m"], k, signature)
            return private


def challenge44():
    messages = parse_text_file()
    private = repeated_nonce_find_private(messages)
    fingerprint = get_sha1_fingerprint(private)
    print(f"Private key fingerprint: {fingerprint}")


if __name__ == "__main__":
    challenge44()
