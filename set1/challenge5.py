from itertools import cycle

from ..conversions import bytes_to_hex, hex_to_bytes


def repeating_key_xor(plaintext, key):
    # plaintext is a bytestring, key is a bytestring
    to_return = bytearray()
    for text_char, key_char in zip(plaintext, cycle(key)):
        to_return.append(text_char ^ key_char)
    return to_return


def challenge5():
    plaintext = (
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )
    ciphertext = repeating_key_xor(plaintext, b"ICE")
    ciphertext_hex = bytes_to_hex(ciphertext)
    expected = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""
    print(f"Calculated: {ciphertext_hex}")
    print(f"Expected  : {expected}")
    print(f"Correct? {ciphertext == hex_to_bytes(expected)}")


if __name__ == "__main__":
    challenge5()
