from ..set5.challenge39 import inverse_mod

from .challenge43 import dsa_generate_keys, dsa_sign, dsa_verify, get_dsa_constants


def dsa_substitute_g0():
    # This attack will only work if the implementation of DSA forgets to make sure that:
    # 1) the value of r generated while signing isn't 0
    # 2) the value of r in the signature while signing isn't 0
    # The implementation makes sure of both of these things, so this attack won't work
    # (It will send dsa_sign into an infinite loop as it keeps trying k values hoping to get an r that isn't 0)

    p, q, g = get_dsa_constants()
    constants = (p, q, 0)
    private, public = dsa_generate_keys(constants)
    message = b"Hello"
    signature = dsa_sign(message, private, constants)
    correct = dsa_verify(message, public, signature, constants)
    print(f"Original signature: {signature}")
    print(f"Original message verified: {correct}")
    forged_correct = dsa_verify(b"Forged message", public, signature, constants)
    print(f"Forged message verified: {forged_correct}")


def dsa_substitute_g1():
    p, q, g = get_dsa_constants()
    constants = (p, q, p + 1)
    private, public = dsa_generate_keys(constants)
    message = b"Hello, world"
    message2 = b"Goodbye, world"
    # try using the same signature to verify any message
    original_signature = dsa_sign(message, private, constants)
    original_correct = dsa_verify(message, public, original_signature, constants)
    modified_correct = dsa_verify(message2, public, original_signature, constants)
    print(f"Original correct: {original_correct}")
    print(f"Modified correct: {modified_correct}")
    # use method in description to create a valid signature
    # set z = 1 to make the math easier
    z = 1
    r = pow(public, z, p) % q
    s = (r * inverse_mod(z, q)) % q
    created_signature = (r, s)
    message1_correct = dsa_verify(message, public, created_signature, constants)
    message2_correct = dsa_verify(message2, public, created_signature, constants)
    print(f"Message 1 correct: {message1_correct}")
    print(f"Message 2 correct: {message2_correct}")


def challenge45():
    # see comment in dsa_subsitute_g0 for why this is commented out
    # dsa_substitute_g0()
    dsa_substitute_g1()


if __name__ == "__main__":
    challenge45()
