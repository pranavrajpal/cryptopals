from set5.challenge39 import rsa_decrypt, rsa_encrypt, rsa_generate_keys, inverse_mod, gcd
from set5.challenge36 import num_to_bytes
from functools import reduce
from operator import mul
import math
from gmpy2 import iroot, mpz


def encrypt_3_times(message):
    ciphertexts = []
    for i in range(3):
        e, d, n = rsa_generate_keys(num_bits=1024)
        to_append = rsa_encrypt(message, e, n), n
        ciphertexts.append(to_append)
    return ciphertexts


def all_coprime(num_list):
    """Checks if none of the numbers in the list share any common factors"""
    for i, num1 in enumerate(num_list):
        for j, num2 in enumerate(num_list):
            if i == j:
                continue
            if gcd(num1, num2) != 1:
                # 2 numbers share a common factor
                return False
    return True


def crt_recover_plaintext(ciphertext_list):
    ciphertexts, moduli = zip(*ciphertext_list)
    assert all_coprime(moduli)
    modulus_product = 1
    for mod in moduli:
        modulus_product *= mod

    result_so_far = 0
    for ciphertext, modulus in ciphertext_list:
        # int division to make sure m_s is an integer
        assert modulus_product % modulus == 0
        m_s = modulus_product // modulus
        result_so_far += (ciphertext * m_s * inverse_mod(m_s, modulus))
    # find the cube root of the result
    # // we have result_so_far = (m**3) % modulus_product which means m ** 3 = result_so_far + n * modulus_product
    # // m = cube_root(result_so_far + n * modulus_product) - need to find the n value that makes this equation true
    # m < n1, m < n2, and m < n3 based on the requirements of RSA, so m ** 3 < n1 * n2 * n3
    # modulus_product = n1 * n2 * n3, so m**3 < modulus_product, so cubing won't wrap around the modulus
    # If cubing doesn't wrap, that means that cube root mod modulus_product = regular cube root

    # use gmpy for extra precision
    result_mpz = mpz(result_so_far % modulus_product)
    root_mpz, exact = iroot(result_mpz, 3)
    # root should always be exact for reasoning explained in above comment (message cubed should never wrap)
    assert exact
    root = int(root_mpz)
    return num_to_bytes(root)


def cube_root_mod_n(num, modulus):
    """Computes the cube root of num mod the modulus"""
    # TODO: use a faster algorithm for calculating this (like the Tonelli-Shanks method?)
    guess = num % modulus
    while not is_perfect_cube(guess):
        guess += modulus
    return round(guess ** (1/3))


def test_cube_root_mod_n():
    root = cube_root_mod_n(3 ** 3, 11)
    print(f'Root: {root}')
    assert root == 3
    assert cube_root_mod_n(3 ** 3, 17) == 3


def is_perfect_cube(num):
    root = round(num ** (1/3))
    return root ** 3 == num


def test_perfect_cube():
    for i in range(1000):
        if is_perfect_cube(i):
            print(i)


def integer_cube_root_binary_search(n):
    """Returns the largest number n such that n ** 3 <= num"""
    high = (n // 2) + 1
    low = 0
    while low < high:
        mid = (low + high) // 2
        if mid ** 3 < n:
            # mid works, but higher option might work too
            low = mid + 1
        else:
            # don't rule out this option, because mid ** 3 could be equal to n
            high = mid
    return low


def integer_cube_root(num):
    """Returns the largest number n such that n ** 3 <= num - returns floor(cube_root(num))"""
    # algorithm based on https://www.akalin.com/computing-iroot
    if num == 0:
        return 0
    if num.bit_length() <= 3:
        return 1
    previous = 1 << math.ceil(num.bit_length() / 3)
    current = 0
    while True:
        numerator = 2*previous + num//(previous ** 2)
        current = (numerator // 3)
        if current >= previous:
            return previous
        else:
            previous = current


def challenge40():
    # message = b'passwordlakfjlajsdljslddj'
    # FIXME: algorithm breaks when the message is too large for the specified number of bits - only works when adding more bits
    # or making the message shorter
    message = b"Hello, I'm a Javascript programmer."
    ciphertexts = encrypt_3_times(message)
    plaintext = crt_recover_plaintext(ciphertexts)
    print(f'Plaintext: {plaintext}')


def test_integer_cube_root():
    test_nums = [1, 2, 5, 10, 100, (3 ** 3)]
    for num in test_nums:
        root = integer_cube_root(num)
        print(
            f'Number: {num}, Cube root: {root}, cubed: {root ** 3}, next cubed: {(root + 1) ** 3}')


if __name__ == "__main__":
    # test_integer_cube_root()
    # test_perfect_cube()
    # test_cube_root_mod_n()
    challenge40()
