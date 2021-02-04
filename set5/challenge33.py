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
    DiffieHellmanConstants = namedtuple("DiffieHellmanConstants", "p g")
    constants = DiffieHellmanConstants(
        p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
        g=2,
    )
    return constants


def challenge33():
    test_small_nums()
    test_big_nums()


if __name__ == "__main__":
    challenge33()
