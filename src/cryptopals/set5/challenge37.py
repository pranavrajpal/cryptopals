from threading import Thread

from .challenge36 import (
    create_connection,
    get_srp_constants,
    hmac_sha256,
    num_to_bytes,
    sha256_hash,
    srp_server,
)


def fake_srp_client(channel, A_val):
    email = b"realemail@definitelynotfake.net"
    N, g, k = get_srp_constants()
    channel.send((email, A_val))
    salt, B = channel.receive()

    S = 0
    K = sha256_hash(num_to_bytes(S))
    hmac = hmac_sha256(K, salt)
    channel.send(hmac)


def challenge37():
    actual_password = b"actual password"
    N, g, k = get_srp_constants()
    for i in range(10):
        print(f"I = {i}")
        A_val = i * N
        endpoint1, endpoint2 = create_connection()
        server = Thread(target=srp_server, args=(endpoint1, actual_password))
        server.start()
        fake_srp_client(endpoint2, A_val)
        server.join()


if __name__ == "__main__":
    challenge37()
