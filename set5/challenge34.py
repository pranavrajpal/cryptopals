from Crypto.Random import get_random_bytes

from set2.challenge1 import pkcs7_pad, pkcs7_unpad
from set2.challenge2 import decrypt_AES_CBC, encrypt_AES_CBC
from set4.challenge28 import sha1_hash

from .challenge33 import diffie_hellman, generate_session, get_constants

CONSTANTS = get_constants()
p, g = CONSTANTS.p, CONSTANTS.g


class Sender:
    def __init__(self):
        self.private, self.public = diffie_hellman(g, p)

    def initial_request(self):
        return self.public

    def create_connection(self, other_public):
        self.session = generate_session(other_public, self.private, p)

    def send_message(self, message):
        return encrypt(message, self.session)


def num_to_bytes(num):
    # value of p is 192 bytes, so 192 bytes should be enough to hold the whole number
    return num.to_bytes(192, "big")


class Receiver:
    def __init__(self):
        self.private, self.public = diffie_hellman(g, p)

    def initial_response(self, other_public):
        self.session = generate_session(other_public, self.private, p)
        return self.public

    def respond_to_message(self, received):
        message = decrypt(received, self.session)
        print(f"Received message: {message}")
        return encrypt(message, self.session)


def encrypt(message, session):
    """Encrypts the message using the Diffie Hellman created session key"""
    aes_key = sha1_hash(num_to_bytes(session))[:16]
    iv = get_random_bytes(16)
    padded = pkcs7_pad(message, 16)
    encrypted = encrypt_AES_CBC(padded, aes_key, iv)
    return encrypted + iv


def decrypt(received, session):
    """Decrypts the message using the Diffie Hellman created session key"""
    aes_key = sha1_hash(num_to_bytes(session))[:16]
    ciphertext, iv = received[:-16], received[-16:]
    padded_message = decrypt_AES_CBC(ciphertext, aes_key, iv)
    message = pkcs7_unpad(padded_message)
    return message


def diffie_hellman_mitm(sender, receiver):
    A = sender.initial_request()  # noqa
    B = receiver.initial_response(p)  # noqa
    # sets both public keys to p, so that s = (B ** a) % p turns into (p ** a) % p = 0 because (p ** a) is always a multiple of p
    sender.create_connection(p)
    intercept_messages(sender, receiver, 0)


def intercept_messages(sender, receiver, session_val, message_to_send=b"Hello"):
    """Send `message_to_send` between the sender and the receiver and decrypt them using the fixed session key given"""
    encrypted = sender.send_message(message_to_send)
    message = decrypt(encrypted, session_val)
    print(f"Intercepted message sent: {message}")
    returned = receiver.respond_to_message(encrypted)
    returned_message = decrypt(returned, session_val)
    print(f"Intercepted message received: {returned_message}")


def test_connection():
    sender = Sender()
    receiver = Receiver()
    A = sender.initial_request()
    B = receiver.initial_response(A)
    sender.create_connection(B)
    encrypted = sender.send_message(b"Hello")
    returned = receiver.respond_to_message(encrypted)  # noqa


def challenge34():
    test_connection()

    sender = Sender()
    receiver = Receiver()
    diffie_hellman_mitm(sender, receiver)


if __name__ == "__main__":
    challenge34()
