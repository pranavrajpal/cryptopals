from Crypto.Hash import SHA1
from Crypto.Random import random

from conversions import bytes_to_hex, hex_to_bytes

# from set4.challenge29 import sha1_hash
from set5.challenge36 import bytes_to_num, num_to_bytes
from set5.challenge39 import inverse_mod


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
    p = 0x800000000000000089E1855218A0E7DAC38136FFAFA72EDA7859F2171E25E65EAC698C1702578B07DC2A1076DA241C76C62D374D8389EA5AEFFD3226A0530CC565F3BF6B50929139EBEAC04F48C3C84AFB796D61E5A4F9A8FDA812AB59494232C7D2B4DEB50AA18EE9E132BFA85AC4374D7F9091ABC3D015EFC871A584471BB1
    q = 0xF4F47F05794B256174BBA6E9B396A7707E563C5B
    g = 0x5958C9D3898B224B12672C0B98E06C60DF923CB8BC999D119458FEF538B8FA4046C8DB53039DB620C094C9FA077EF389B5322A559946A71903F990F1F7E0E025E2D7F7CF494AFF1A0470F5B64C36B625A097F1651FE775323556FE00B3608C887892878480E99041BE601A62166CA6894BDD41A7054EC89F756BA9FC95302291
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
    message = b"This is a test message"
    private, public = dsa_generate_keys()
    signature = dsa_sign(message, private)
    correct = dsa_verify(message, public, signature)
    print(f"Correct: {correct}")
    altered_correct = dsa_verify(message + b"a", public, signature)
    print(f"Altered message correct: {altered_correct}")


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
    expected_hash = hex_to_bytes("0954edd5e0afe5542a4adf012611a91912a3ec16")
    for k in range(0, 2 ** 16 + 1):
        print(f"\rK = {k}", end="")
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
    message = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    public = 0x84AD4719D044495496A3201C8FF484FEB45B962E7302E56A392AEE4ABAB3E4BDEBF2955B4736012F21A08084056B19BCD7FEE56048E004E44984E2F411788EFDC837A0D2E5ABB7B555039FD243AC01F0FB2ED1DEC568280CE678E931868D23EB095FDE9D3779191B8C0299D6E07BBB283E6633451E535C45513B2D33C99EA17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    correct = dsa_verify(message, public, (r, s))
    print(f"Correct: {correct}")
    # get private key
    private = brute_force_private_key(message, public, (r, s))
    fingerprint = get_sha1_fingerprint(private)
    print(f"Private key SHA1 fingerprint: {fingerprint}")


def get_sha1_fingerprint(value):
    """Finds the SHA1 fingerprint of the int `value` by converting it to hex and then taking the SHA1 hash of the resulting string"""
    as_hex = hex(value)[2:].encode("utf-8")
    fingerprint = sha1_hash(as_hex)
    return fingerprint.hex()


if __name__ == "__main__":
    # test_dsa()
    challenge43()
