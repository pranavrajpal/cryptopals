import secrets
from collections import namedtuple


def diffie_hellman(generator, modulus):
    """Generates a new Diffie Hellman public and private key pair and returns the tuple (private, public)"""

    private = generate_private(modulus)
    public = generate_public(private, generator, modulus)
    return private, public


def generate_public(private, generator, modulus):
    """Calculates the public Diffie-Hellman key given g, p, and the private key"""
    return pow(generator, private, modulus)


def generate_private(modulus):
    """Returns a random private key given the modulus being used"""
    return secrets.randbelow(modulus)


def generate_session(public, private, modulus):
    """Calculates the session key given the received public key, the receiver's 
    private key, and the modulus"""
    return pow(public, private, modulus)


def test_small_nums():
    # small number version
    p = 37
    g = 5
    a = generate_private(p)
    assert a < p and a >= 0
    A = generate_public(a, g, p)
    b = generate_private(p)
    assert b < p and b >= 0
    B = generate_public(b, g, p)
    sA = generate_session(B, a, p)
    sB = generate_session(A, b, p)
    assert sA == sB
    print(sA)


def test_big_nums():
    constants = get_constants()
    p, g = constants.p, constants.g
    a = generate_private(p)
    assert a < p and a >= 0
    A = generate_public(a, g, p)
    b = generate_private(p)
    assert b < p and b >= 0
    B = generate_public(b, g, p)
    sA = generate_session(B, a, p)
    sB = generate_session(A, b, p)
    assert sA == sB
    print(sA)


def get_constants():
    """Returns common set of constants used in Diffie Hellman"""
    DiffieHellmanConstants = namedtuple('DiffieHellmanConstants', 'p g')
    constants = DiffieHellmanConstants(p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,
                                       g=2)
    return constants


def challenge33():
    test_small_nums()
    test_big_nums()


if __name__ == "__main__":
    challenge33()
