from ...conversions import hex_to_bytes
from ...set1.challenge1_2 import xor_bytes
from ...set4.challenge28 import sha1_hash


def hmac_sha1(key, message):
    block_size = 64
    if len(key) > block_size:
        key = sha1_hash(message)
    # have to modify key because key might be too short after hashing

    if len(key) < block_size:
        padding_amount = block_size - len(key)
        key = key + b"\0" * padding_amount
    outer_key = xor_single_byte(key, 0x5C)
    inner_key = xor_single_byte(key, 0x36)
    return sha1_hash(outer_key + sha1_hash(inner_key + message))


def xor_single_byte(message, byte_value):
    """Xor all bytes in message with the byte number byte_value"""
    as_bytestring = bytes([byte_value] * len(message))
    return xor_bytes(as_bytestring, message)


def test_hmac_sha1():
    # HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   = de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
    key = b"key"
    message = b"The quick brown fox jumps over the lazy dog"
    expected_hash = hex_to_bytes("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
    calculated_hash = hmac_sha1(key, message)
    correct = expected_hash == calculated_hash
    print(f"Expected: {expected_hash!r}")
    print(f"Calculated: {calculated_hash}")
    print(f"Correct? {correct}")
    assert correct


if __name__ == "__main__":
    test_hmac_sha1()
