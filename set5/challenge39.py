from Crypto.Util.number import getPrime

from set5.challenge36 import bytes_to_num, num_to_bytes


def rsa_generate_keys(num_bits=1024):
    """Returns the tuple (e, d, n)"""
    while True:
        p = getPrime(num_bits)
        q = getPrime(num_bits)
        e = 3
        et = (p - 1) * (q - 1)
        x, y, gcd_val = egcd(e, et)
        if p != q and gcd_val == 1:
            break
    n = p * q
    d = inverse_mod(e, et)
    return e, d, n


def rsa_encrypt(message, e, modulus):
    """Encrypts the bytestring `message` using the exponent `e` and the modulus `modulus` and returns the ciphertext"""
    message_int = bytes_to_num(message)
    if message_int >= modulus:
        raise ValueError("Message is too large to be encrypted with given modulus")
    return pow(message_int, e, modulus)


def rsa_decrypt(ciphertext, d, modulus):
    """Decrypts the integer `ciphertext` using the exponent `d` and returns the bytestring `plaintext`"""
    return num_to_bytes(pow(ciphertext, d, modulus))


def challenge39():
    message = b"Hello"
    e, d, n = rsa_generate_keys()
    ciphertext = rsa_encrypt(message, e, n)
    plaintext = rsa_decrypt(ciphertext, d, n)
    print(f"Plaintext: {plaintext}")
    long_message = b"A" * 100000
    e, d, n = rsa_generate_keys()
    ciphertext = rsa_encrypt(long_message, e, n)
    plaintext = rsa_decrypt(ciphertext, d, n)
    print(f"Long plaintext: {plaintext}")


def gcd(a, b):
    """Returns the gcd of a and b"""
    x, y, gcd_val = egcd(a, b)
    return gcd_val


def egcd(a, b):
    """Computes (x, y, gcd) given a and b where x * a + y * b = gcd(a, b)"""
    # based on pseudocode found on wikipedia
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = (r, old_r - quotient * r)
        old_s, s = (s, old_s - quotient * s)
        old_t, t = (t, old_t - quotient * t)
    return old_s, old_t, old_r


def inverse_mod(number, modulus):
    """Returns the inverse of `number` mod `modulus`"""
    x, y, gcd_val = egcd(number, modulus)
    if gcd_val != 1:
        # algorithm only works if number and modulus are coprime
        raise ValueError("Can't find multiplicative inverse")
    return x % modulus


def test_egcd():
    # 3 * 102 - 8 * 38 = gcd(38, 102) = 2
    a, b, gcd_val = egcd(102, 38)
    print(f"A: {a}, B: {b}, gcd: {gcd_val}")
    inverse = inverse_mod(3, 26)
    print(f"Inverse: {inverse}")
    inverse = inverse_mod(3, 79)
    print(f"Inverse: {inverse}")
    print(f"Inverse: {inverse_mod(17, 3120)}")


if __name__ == "__main__":
    challenge39()
    # test_egcd()
