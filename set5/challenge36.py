from __future__ import annotations

import socket
import sys
from queue import Queue
from threading import Thread
from typing import Any

from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

from .challenge33 import get_constants
from .challenge34 import diffie_hellman, generate_private


class ConnectionEndpoint:
    def __init__(self, send_queue: Queue[Any], receive_queue: Queue[Any]):
        self.send_queue = send_queue
        self.receive_queue = receive_queue

    def send(self, message: Any):
        self.send_queue.put(message)

    def receive(self):
        # get will block until it receives a message
        return self.receive_queue.get()

    def empty(self):
        """Returns True if the receive queue is empty (there are no messages available)"""
        return self.receive_queue.empty()


def create_connection():
    """Returns the tuple (endpoint1, endpoint2), where both endpoints can send data to and receive data from the other"""
    queue1: Queue[Any] = Queue(0)
    queue2: Queue[Any] = Queue(0)
    # messages sent from endpoint 1 are received by endpoint 2 and vice versa
    endpoint1 = ConnectionEndpoint(queue1, queue2)
    endpoint2 = ConnectionEndpoint(queue2, queue1)
    return endpoint1, endpoint2


def get_srp_constants():
    """Get constants related to the Secure Remote Password (SRP) protocol - returns the tuple (N, g, k)
    where N is the prime modulus, g is the generator, and k = 3"""

    constants = get_constants()
    return constants.p, constants.g, 3


def bytes_to_num(bytestring):
    return int.from_bytes(bytestring, "big")


def num_to_bytes(num):
    """Converts the number to a bytestring"""
    length = (num.bit_length() + 7) // 8
    return num.to_bytes(length, "big")


def sha256_hash(bytestring):
    """Computes the SHA256 hash of the bytestring"""
    return SHA256.new(bytestring).digest()


def hmac_sha256(key, bytestring):
    """Computes the HMAC-SHA256 of the bytestring using the given key"""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(bytestring)
    return h.digest()


def srp_server(channel, password):
    N, g, k = get_srp_constants()
    salt = get_random_bytes(192)
    xH = sha256_hash(salt + password)
    x = bytes_to_num(xH)
    v = pow(g, x, N)
    # make sure x and xH aren't used again
    del x
    del xH
    b = generate_private(N)
    B = k * v + pow(g, b, N)
    channel.send((salt, B))
    email, A = channel.receive()
    uH = sha256_hash(num_to_bytes(A) + num_to_bytes(B))
    u = bytes_to_num(uH)
    # v ** u is the same as v ** u % N or pow(v, u, N) because entire expression is mod N
    S = pow(A * pow(v, u, N), b, N)
    K = sha256_hash(num_to_bytes(S))
    computed_hmac = hmac_sha256(K, salt)
    received_hmac = channel.receive()
    if computed_hmac == received_hmac:
        print("OK")
        channel.send("OK")


def srp_client(channel, email, password):
    """Returns True if the connection was made successfully, False otherwise"""
    N, g, k = get_srp_constants()
    a, A = diffie_hellman(g, N)
    channel.send((email, A))
    salt, B = channel.receive()
    uH = sha256_hash(num_to_bytes(A) + num_to_bytes(B))
    u = bytes_to_num(uH)
    xH = sha256_hash(salt + password)
    x = bytes_to_num(xH)
    # g ** x == pow(g, x, N) when modulo N either way
    S = pow(B - k * pow(g, x, N), a + u * x, N)
    K = sha256_hash(num_to_bytes(S))
    hmac = hmac_sha256(K, salt)
    channel.send(hmac)


def test_connection():
    endpoint1, endpoint2 = create_connection()
    # endpoint 1 to 2
    endpoint1.send("Hello")
    endpoint1.send("Goodbye")
    endpoint1.send((1, 2, "a"))
    received = endpoint2.receive()
    print(f"Received: {received}")
    received = endpoint2.receive()
    print(f"Received: {received}")
    received = endpoint2.receive()
    print(f"Received: {received}")
    # endpoint 2 to 1
    endpoint2.send("Hello")
    endpoint2.send("Goodbye")
    endpoint2.send((1, 2, "a"))
    received = endpoint1.receive()
    print(f"Received: {received}")
    received = endpoint1.receive()
    print(f"Received: {received}")
    received = endpoint1.receive()
    print(f"Received: {received}")


def challenge36():
    endpoint1, endpoint2 = create_connection()
    email = b"email@email.com"
    password = b"password"
    client = Thread(target=srp_client, args=(endpoint1, email, password))
    server = Thread(target=srp_server, args=(endpoint2, password))
    client.start()
    server.start()
    client.join()
    server.join()


if __name__ == "__main__":
    # test_connection()
    challenge36()
