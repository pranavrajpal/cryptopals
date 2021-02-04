from conversions import base64_to_bytes
from set1.challenge6 import get_repeating_xor_key, repeating_key_xor
from challenge3 import Encryption
from set1.challenge8 import get_blocks
from challenge3 import guess_keystream
from set1.challenge1_2 import xor_bytes


def break_CTR_repeated_key_xor(bytestring_list):
    sorted_lines = sorted(bytestring_list, key=lambda line: len(line))
    lowest_len = len(sorted_lines[0])
    truncated = [line[:lowest_len] for line in bytestring_list]
    bytestring = b''.join(truncated)
    xor_key = get_repeating_xor_key(bytestring, lowest_len)
    plaintext_combined = repeating_key_xor(bytestring, xor_key)
    plaintext = get_blocks(plaintext_combined, lowest_len)
    return plaintext


def xor_shortened(bytestring, keystream):
    if len(keystream) > len(bytestring):
        shortened_keystream = keystream[:len(bytestring)]
    else:
        shortened_keystream = keystream
    return xor_bytes(bytestring, shortened_keystream)


def challenge4():
    with open('20.txt') as handle:
        contents_base64 = handle.read().splitlines()
    cipher = Encryption()
    encrypted_lines = cipher.encrypt(contents_base64)
    plaintext_bytes_list = break_CTR_repeated_key_xor(encrypted_lines)
    plaintext = [line.decode('utf-8') for line in plaintext_bytes_list]
    print('\n'.join(plaintext))
    print('-' * 90)
    # other approach
    keystream = guess_keystream(encrypted_lines)
    plaintext_lines = []
    for line in encrypted_lines:
        plaintext_lines.append(xor_shortened(line, keystream).decode('utf-8'))
    print('\n'.join(plaintext_lines))


if __name__ == "__main__":
    challenge4()
