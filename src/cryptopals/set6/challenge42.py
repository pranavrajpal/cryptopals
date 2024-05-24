from ..conversions import hex_to_bytes
from ..set5.challenge36 import bytes_to_num, num_to_bytes, sha256_hash
from ..set5.challenge39 import rsa_decrypt, rsa_encrypt, rsa_generate_keys
from ..set5.challenge40 import integer_cube_root

# taken from https://tools.ietf.org/html/rfc3447#section-9.2
ASN1_IDENTIFIER_SHA256 = hex_to_bytes(
    "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"
)
# length of SHA256 hash output in bytes
HASH_LENGTH = 32


def sign_pkcs1_5(message, d, modulus):
    """Computes the PKCS1.5 signature of the message, given as a bytestring,
    using the given RSA private key and the given modulus"""
    # maximum number of bytes that is definitely less than the modulus (first byte is always a 0 so don't need to subtract one byte)
    block_length = modulus.bit_length() // 8
    input_block = encode_pkcs1_5(message, block_length)
    return num_to_bytes(rsa_encrypt(input_block, d, modulus))


def encode_pkcs1_5(message, block_length):
    """Encodes the message, given as a bytestring, padding it to the specified block_length,
    so that it can be used as input to PKCS1.5 signing using a SHA256 hash"""
    message_hash = sha256_hash(message)
    # number of 0xff bytes needed to pad out message
    padding_needed = block_length - len(ASN1_IDENTIFIER_SHA256) - len(message_hash) - 3
    # according to https://tools.ietf.org/html/rfc3447#section-9.2, there needs to be at least 8 bytes of padding
    if padding_needed < 8:
        raise ValueError("block length too small")
    return (
        b"\x00\x01"
        + (b"\xff" * padding_needed)
        + b"\x00"
        + ASN1_IDENTIFIER_SHA256
        + message_hash
    )


def unencode_pkcs1_5_incorrect(block):
    """Returns the hash inside the signature or None if the signature is incorrect.
    This function does not check the padding correctly to make sure the hash reaches the end of the signature"""
    unparsed_signature = block
    # don't check for leading null byte because it would have been stripped off by repeated conversions between numbers and bytes
    if unparsed_signature.startswith(b"\x01"):
        unparsed_signature = unparsed_signature[1:]
    elif unparsed_signature.startswith(b"\x00\x01"):
        unparsed_signature = unparsed_signature[2:]
    else:
        return None
    byte = unparsed_signature[0]
    if byte != 0xFF:
        # make sure there's at least one 0xff byte
        return None
    while byte == 0xFF:
        unparsed_signature = unparsed_signature[1:]
        byte = unparsed_signature[0]
    if not unparsed_signature.startswith(b"\x00" + ASN1_IDENTIFIER_SHA256):
        return None
    unparsed_signature = unparsed_signature[len(ASN1_IDENTIFIER_SHA256) + 1 :]

    signature_hash = unparsed_signature[:HASH_LENGTH]
    return signature_hash


def verify_pkcs1_5_incorrect(message, signature, e, modulus):
    """Takes the message as a bytestring, the PKCS1.5 signature, and e and the modulus, and verifies if the signature is correct
    This function does not check the padding correctly because it does not make sure the hash reaches the end of the signature."""
    pkcs_block = rsa_decrypt(bytes_to_num(signature), e, modulus)
    signature_hash = unencode_pkcs1_5_incorrect(pkcs_block)
    calculated_hash = sha256_hash(message)
    return signature_hash == calculated_hash


def test_pkcs1_5():
    message = 0xE567A39AE4E5EF9B6801EA0561B72A5D4B5F385F0532FC9FE10A7570F869AE05C0BDEDD6E0E22D4542E9CE826A188CAC0731AE39C8F87F9771EF02132E64E2FB27ADA8FF54B330DD93AD5E3EF82E0DDA646248E35994BDA10CF46E5ABC98AA7443C03CDDEB5EE2AB82D60100B1029631897970275F119D05DAA2220A4A0DEFBA
    S = 0x0E7CDD121E40323CA6115D1EC6D1F9561738455F0E9E1CD858E8B566AE2DA5E8EE63D8F15C3CDD88027E13406DB609369C88CA99B34FA156C7EE62BC5A3923BB5A1EDABD45C1A422AAFCBB47E0947F35CFEF87970B4B713162B21916CAFB8C864A3E5B9FFC989401D4EAE992312A32C5BC88ABBB45F99AC885B54D6B8E61B6EC
    n = 0xC8A2069182394A2AB7C3F4190C15589C56A2D4BC42DCA675B34CC950E24663048441E8AA593B2BC59E198B8C257E882120C62336E5CC745012C7FFB063EEBE53F3C6504CBA6CFE51BAA3B6D1074B2F398171F4B1982F4D65CAF882EA4D56F32AB57D0C44E6AD4E9CF57A4339EB6962406E350C1B15397183FBF1F0353C9FC991
    e = 0x10001
    d = 0x5DFCB111072D29565BA1DB3EC48F57645D9D8804ED598A4D470268A89067A2C921DFF24BA2E37A3CE834555000DC868EE6588B7493303528B1B3A94F0B71730CF1E86FCA5AEEDC3AFA16F65C0189D810DDCD81049EBBD0391868C50EDEC958B3A2AAEFF6A575897E2F20A3AB5455C1BFA55010AC51A7799B1FF8483644A3D425
    signed = sign_pkcs1_5(num_to_bytes(message), d, n)
    correct = bytes_to_num(signed) == S
    print(f"Correct: {correct}")
    assert correct
    verified = verify_pkcs1_5_incorrect(num_to_bytes(message), num_to_bytes(S), e, n)
    print(f"Verified: {verified}")
    assert verified
    message = 0x467E8EA634F7995DC46C11B8AB0B7508894681E81C3502C3B335E897E6D69DF885F49557CE232784E3519B727BA6843BD7AF5063F8BC1D610F86CE5B35155E325CE175BE8538395B34DF67A421FCA27E31330B59A41011B290A58BDC8E740401B38F5564C2FD7AE89F609ED607D578DB7F1CDA508AF987BE1FD946A25AB9346D
    S = 0x2B1FFB370D518A82646D86828DB1FC7E8BFE73EE878DA120FA92737C9174688995F2255B29E83B28C244CC563C9B33EFD3F9F9E1638E2C16E24F2EAE19435696B2F4D1CF73064FC1CFCCB2278C01F0979E7DE7463BF8417BD6986FBF1D34D382A978CE799582442AFCC92B4FE743216B6F151F6A561D979CF683CAB6AF2FF4C5
    signed = sign_pkcs1_5(num_to_bytes(message), d, n)
    correct = bytes_to_num(signed) == S
    print(f"Correct: {correct}")
    assert correct
    verified = verify_pkcs1_5_incorrect(num_to_bytes(message), num_to_bytes(S), e, n)
    print(f"Verified: {verified}")
    assert verified


def forge_pkcs1_5_signature(message, modulus):
    """Forges a PKCS1.5 signature for the message assuming a public exponent of 3 (e = 3)"""
    message_hash = sha256_hash(message)
    pkcs_block_beginning = (
        b"\x00\x01" + b"\xff" * 8 + b"\x00" + ASN1_IDENTIFIER_SHA256 + message_hash
    )
    block_length = modulus.bit_length() // 8
    garbage_length = block_length - len(pkcs_block_beginning)
    # need to find a number S such that when cubed:
    # - doesn't go over the modulus (meaning that we don't need the private key)
    # - creates a valid PKCS1.5 block B with the correct hash
    # turns the block into a number, leaving all zeroes for the data at the end
    guess_block_num = bytes_to_num(pkcs_block_beginning) << (garbage_length * 8)
    guess_signature = integer_cube_root(guess_block_num)
    # same as pkcs_block_beginning but without the leading zero byte
    expected_prefix_block = (
        b"\x01" + b"\xff" * 8 + b"\x00" + ASN1_IDENTIFIER_SHA256 + message_hash
    )
    # TODO: find a valid signature using math instead of starting at the integer cube root,
    # incrementing and using guess and check - try just taking the cube root of the number
    # and rounding it up?
    while True:
        block_num = guess_signature ** 3
        # make sure block isn't too big
        assert block_num < modulus
        block = num_to_bytes(block_num)
        if block.startswith(pkcs_block_beginning) or block.startswith(
            expected_prefix_block
        ):
            break
        guess_signature += 1
    signature = num_to_bytes(guess_signature)
    return signature


def challenge42():
    e, d, n = rsa_generate_keys(num_bits=1024)
    print("Done generating keys")
    message = b"hi mom"
    signature = forge_pkcs1_5_signature(message, n)
    correct = verify_pkcs1_5_incorrect(message, signature, e, n)
    print(f"Correct: {correct}")
    assert correct


if __name__ == "__main__":
    challenge42()
    # test_pkcs1_5()
