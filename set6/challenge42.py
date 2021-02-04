from set5.challenge36 import sha256_hash, num_to_bytes, bytes_to_num
from set5.challenge39 import rsa_decrypt, rsa_encrypt, rsa_generate_keys
from conversions import hex_to_bytes
from set5.challenge40 import integer_cube_root

# taken from https://tools.ietf.org/html/rfc3447#section-9.2
ASN1_IDENTIFIER_SHA256 = hex_to_bytes(
    '30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20')
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
    padding_needed = block_length - \
        len(ASN1_IDENTIFIER_SHA256) - len(message_hash) - 3
    # according to https://tools.ietf.org/html/rfc3447#section-9.2, there needs to be at least 8 bytes of padding
    if padding_needed < 8:
        raise ValueError('block length too small')
    return b'\x00\x01' + (b'\xff' * padding_needed) + b'\x00' + ASN1_IDENTIFIER_SHA256 + message_hash


def unencode_pkcs1_5_incorrect(block):
    """Returns the hash inside the signature or None if the signature is incorrect.
    This function does not check the padding correctly to make sure the hash reaches the end of the signature"""
    unparsed_signature = block
    # don't check for leading null byte because it would have been stripped off by repeated conversions between numbers and bytes
    if unparsed_signature.startswith(b'\x01'):
        unparsed_signature = unparsed_signature[1:]
    elif unparsed_signature.startswith(b'\x00\x01'):
        unparsed_signature = unparsed_signature[2:]
    else:
        return None
    byte = unparsed_signature[0]
    if byte != 0xff:
        # make sure there's at least one 0xff byte
        return None
    while byte == 0xff:
        unparsed_signature = unparsed_signature[1:]
        byte = unparsed_signature[0]
    if not unparsed_signature.startswith(b'\x00' + ASN1_IDENTIFIER_SHA256):
        return None
    unparsed_signature = unparsed_signature[len(ASN1_IDENTIFIER_SHA256) + 1:]

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
    message = 0xe567a39ae4e5ef9b6801ea0561b72a5d4b5f385f0532fc9fe10a7570f869ae05c0bdedd6e0e22d4542e9ce826a188cac0731ae39c8f87f9771ef02132e64e2fb27ada8ff54b330dd93ad5e3ef82e0dda646248e35994bda10cf46e5abc98aa7443c03cddeb5ee2ab82d60100b1029631897970275f119d05daa2220a4a0defba
    S = 0x0e7cdd121e40323ca6115d1ec6d1f9561738455f0e9e1cd858e8b566ae2da5e8ee63d8f15c3cdd88027e13406db609369c88ca99b34fa156c7ee62bc5a3923bb5a1edabd45c1a422aafcbb47e0947f35cfef87970b4b713162b21916cafb8c864a3e5b9ffc989401d4eae992312a32c5bc88abbb45f99ac885b54d6b8e61b6ec
    n = 0xc8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991
    e = 0x10001
    d = 0x5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425
    signed = sign_pkcs1_5(num_to_bytes(message), d, n)
    correct = bytes_to_num(signed) == S
    print(f'Correct: {correct}')
    assert correct
    verified = verify_pkcs1_5_incorrect(
        num_to_bytes(message), num_to_bytes(S), e, n)
    print(f'Verified: {verified}')
    assert verified
    message = 0x467e8ea634f7995dc46c11b8ab0b7508894681e81c3502c3b335e897e6d69df885f49557ce232784e3519b727ba6843bd7af5063f8bc1d610f86ce5b35155e325ce175be8538395b34df67a421fca27e31330b59a41011b290a58bdc8e740401b38f5564c2fd7ae89f609ed607d578db7f1cda508af987be1fd946a25ab9346d
    S = 0x2b1ffb370d518a82646d86828db1fc7e8bfe73ee878da120fa92737c9174688995f2255b29e83b28c244cc563c9b33efd3f9f9e1638e2c16e24f2eae19435696b2f4d1cf73064fc1cfccb2278c01f0979e7de7463bf8417bd6986fbf1d34d382a978ce799582442afcc92b4fe743216b6f151f6a561d979cf683cab6af2ff4c5
    signed = sign_pkcs1_5(num_to_bytes(message), d, n)
    correct = bytes_to_num(signed) == S
    print(f'Correct: {correct}')
    assert correct
    verified = verify_pkcs1_5_incorrect(
        num_to_bytes(message), num_to_bytes(S), e, n)
    print(f'Verified: {verified}')
    assert verified


def forge_pkcs1_5_signature(message, modulus):
    """Forges a PKCS1.5 signature for the message assuming a public exponent of 3 (e = 3)"""
    message_hash = sha256_hash(message)
    pkcs_block_beginning = b'\x00\x01' + b'\xff' * \
        8 + b'\x00' + ASN1_IDENTIFIER_SHA256 + message_hash
    block_length = modulus.bit_length() // 8
    garbage_length = block_length - len(pkcs_block_beginning)
    # need to find a number S such that when cubed:
    # - doesn't go over the modulus (meaning that we don't need the private key)
    # - creates a valid PKCS1.5 block B with the correct hash
    # turns the block into a number, leaving all zeroes for the data at the end
    guess_block_num = (bytes_to_num(pkcs_block_beginning)
                       << (garbage_length * 8))
    guess_signature = integer_cube_root(guess_block_num)
    # same as pkcs_block_beginning but without the leading zero byte
    expected_prefix_block = b'\x01' + b'\xff' * 8 + \
        b'\x00' + ASN1_IDENTIFIER_SHA256 + message_hash
    # TODO: find a valid signature using math instead of starting at the integer cube root,
    # incrementing and using guess and check - try just taking the cube root of the number
    # and rounding it up?
    while True:
        block_num = guess_signature ** 3
        # make sure block isn't too big
        assert block_num < modulus
        block = num_to_bytes(block_num)
        if block.startswith(pkcs_block_beginning) or block.startswith(expected_prefix_block):
            break
        guess_signature += 1
    signature = num_to_bytes(guess_signature)
    return signature


def challenge42():
    e, d, n = rsa_generate_keys(num_bits=1024)
    print('Done generating keys')
    message = b'hi mom'
    signature = forge_pkcs1_5_signature(message, n)
    correct = verify_pkcs1_5_incorrect(message, signature, e, n)
    print(f'Correct: {correct}')
    assert correct


if __name__ == "__main__":
    challenge42()
    # test_pkcs1_5()
