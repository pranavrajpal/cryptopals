from challenge36 import (
    create_connection,
    sha256_hash,
    bytes_to_num,
    num_to_bytes,
    hmac_sha256,
)
from challenge33 import diffie_hellman, get_constants, generate_public
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from threading import Thread


def simplified_srp_server(channel, password):
    constants = get_constants()
    g, n = constants.g, constants.p
    salt = get_random_bytes(192)
    x = bytes_to_num(sha256_hash(salt + password))
    v = pow(g, x, n)
    b, B = diffie_hellman(g, n)
    u = getrandbits(128)
    channel.send((salt, B, u))
    email, A = channel.receive()
    S = pow(A * pow(v, u, n), b, n)
    K = sha256_hash(num_to_bytes(S))
    received_hmac = channel.receive()
    expected_hmac = hmac_sha256(K, salt)
    if expected_hmac == received_hmac:
        channel.send("OK")
    else:
        channel.send("Not OK")


def simplified_srp_client(channel, email, password):
    constants = get_constants()
    g, n = constants.g, constants.p
    a, A = diffie_hellman(g, n)
    channel.send((email, A))
    salt, B, u = channel.receive()
    x = bytes_to_num(sha256_hash(salt + password))
    S = pow(B, a + u * x, n)
    K = sha256_hash(num_to_bytes(S))
    hmac = hmac_sha256(K, salt)
    channel.send(hmac)
    message = channel.receive()
    print(message)


ROCKYOU_PATH = "/mnt/e/Tools/Cybersecurity/Password_Cracking/hashcat/hashcat-5.1.0/hashcat-5.1.0/dictionaries/rockyou.txt"


def mitm_simplified_srp_server(channel):
    constants = get_constants()
    g, n = constants.g, constants.p
    salt = b""
    # B can't be 1, or S would always be 1, so HMAC would always match regardless of guessed password
    # if b = 1 then no need for outer exponentiation in computation for S
    b = 1
    B = generate_public(b, g, n)
    # u can't be 0, or the exponent of S would be B**a % n, removing the dependence on the password and
    # set u to 1 to remove need for inner exponentiation
    u = 1
    email, A = channel.receive()
    channel.send((salt, B, u))
    expected_hmac = channel.receive()
    # print(f'Expected hmac: {expected_hmac}')
    # send OK to let the client shut down
    channel.send("OK")
    with open(ROCKYOU_PATH, "rb") as rockyou_handle:
        lines = rockyou_handle.read().splitlines()
        for line in lines:
            # don't need to include salt because salt was b''
            x = bytes_to_num(sha256_hash(line))
            v = pow(g, x, n)
            S = (A * v) % n
            K = sha256_hash(num_to_bytes(S))
            hmac = hmac_sha256(K, salt)
            if hmac == expected_hmac:
                print(f"Found password: {line}")
                return line


def challenge38():
    endpoint1, endpoint2 = create_connection()
    email = b"email@email.com"
    password = b"password"
    client = Thread(target=simplified_srp_client, args=(endpoint1, email, password))
    # server = Thread(target=simplified_srp_server, args=(endpoint2, password))
    mitm_server = Thread(target=mitm_simplified_srp_server, args=[endpoint2])
    client.start()
    mitm_server.start()
    client.join()
    mitm_server.join()


if __name__ == "__main__":
    challenge38()
