from Crypto.Random import random
# from set4.challenge29 import sha1_hash
from set5.challenge36 import bytes_to_num, num_to_bytes
from set5.challenge39 import inverse_mod
from Crypto.Hash import SHA1
from conversions import hex_to_bytes, bytes_to_hex


def sha1_hash(message):
    """Returns the SHA1 hash of the bytestring `message`. Meant to replace custom SHA1 implementation from earlier challenge"""
    return SHA1.new(message).digest()


def get_dsa_constants(constants=None):
    """Returns (p, q, g) if constants is None, and constants otherwise.

    This allows you to write:
    ```
    def function(constants=None):
        p, q, g = get_dsa_constants(constants) 
    ```
    instead of:
    ```
    def function(constants=None):
        if constants is None:
            p, q, g = get_dsa_constants() 
        else:
            p, q, g = constants
    ```
    """
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    if constants is None:
        return p, q, g
    else:
        return constants


def dsa_generate_keys(constants=None):
    """Returns the key pair (private, public)"""
    p, q, g = get_dsa_constants(constants)
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return x, y


def dsa_sign(message, private, constants=None):
    """DSA signs the bytestring `message` with the given private key and returns the signature (r, s)
    using the hash SHA1"""
    p, q, g = get_dsa_constants(constants)
    while True:
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        if r == 0:
            continue
        h = bytes_to_num(sha1_hash(message))
        k_inverse = inverse_mod(k, q)
        s = ((h + private * r) * k_inverse) % q
        if s == 0:
            continue
        # will only get here if r and s were both not zero
        break
    return r, s


def dsa_verify(message, public, signature, constants=None):
    """Checks if the signature (r, s) is correct"""
    r, s = signature
    p, q, g = get_dsa_constants(constants)

    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = inverse_mod(s, q)
    u1 = (bytes_to_num(sha1_hash(message)) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(public, u2, p)) % p) % q
    return v == r


def test_dsa():
    message = b'This is a test message'
    private, public = dsa_generate_keys()
    signature = dsa_sign(message, private)
    correct = dsa_verify(message, public, signature)
    print(f'Correct: {correct}')
    altered_correct = dsa_verify(message + b'a', public, signature)
    print(f'Altered message correct: {altered_correct}')


def get_private_dsa_key(message, k, signature=None, constants=None):
    """Determines private DSA key value given bytestring `message`, the value of k, and the signature (r, s).

    If signature is None, r and s will be calculated from k and the message"""
    h = bytes_to_num(sha1_hash(message))
    return get_private_dsa_key_message_val(h, k, signature, constants)


def get_private_dsa_key_message_val(message_val, k, signature=None, constants=None):
    """Determines private DSA key value given integer `message`, the value of k, and the signature (r, s).

    If signature is None, r and s will be calculated from k and the message"""
    p, q, g = get_dsa_constants(constants)
    if signature is None:
        r = pow(g, k, p) % q
        k_inverse = inverse_mod(k, q)
        s = (k_inverse * (message_val + x * r)) % q
    else:
        r, s = signature
    # determine x
    r_inverse = inverse_mod(r, q)
    x = ((s * k - message_val) * r_inverse) % q
    return x


def brute_force_private_key(message, public, signature, constants=None):
    """Determines the private key given the bytestring `message`, the signature (r, s), and the public key"""
    p, q, g = get_dsa_constants(constants)
    expected_hash = hex_to_bytes(
        '0954edd5e0afe5542a4adf012611a91912a3ec16')
    for k in range(0, 2 ** 16 + 1):
        print(f'\rK = {k}', end='')
        private = get_private_dsa_key(message, k, signature=signature)
        # this code is faster but relies on knowing the SHA1 hash of the key, which isn't realistic
        # ------------------------------------------------
        # private_as_hex_bytes = hex(private)[2:].encode('utf-8')
        # private_hash = sha1_hash(private_as_hex_bytes)
        # if private_hash == expected_hash:
        # ------------------------------------
        if pow(g, private, p) == public:
            k_inverse = inverse_mod(k, q)
            h = bytes_to_num(sha1_hash(message))
            r = pow(g, k, p) % q
            s = (k_inverse * (h + private * r)) % q
            # make sure we get the same signature
            assert (r, s) == signature
            print()
            return private


def challenge43():
    message = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
    public = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    correct = dsa_verify(message, public, (r, s))
    print(f'Correct: {correct}')
    # get private key
    private = brute_force_private_key(message, public, (r, s))
    fingerprint = get_sha1_fingerprint(private)
    print(f'Private key SHA1 fingerprint: {fingerprint}')


def get_sha1_fingerprint(value):
    """Finds the SHA1 fingerprint of the int `value` by converting it to hex and then taking the SHA1 hash of the resulting string"""
    as_hex = hex(value)[2:].encode("utf-8")
    fingerprint = sha1_hash(as_hex)
    return fingerprint.hex()


if __name__ == "__main__":
    # test_dsa()
    challenge43()
