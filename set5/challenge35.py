from challenge34 import (
    intercept_messages,
    Sender,
    Receiver,
    get_constants,
    encrypt,
    decrypt,
)
from challenge33 import diffie_hellman, generate_session


class Sender2:
    def request1(self):
        constants = get_constants()
        self.p, self.g = constants.p, constants.g
        return self.p, self.g

    def request2(self):
        self.private, self.public = diffie_hellman(self.g, self.p)
        return self.public

    def response2(self, other_public):
        self.session = generate_session(other_public, self.private, self.p)

    def send_message(self, message):
        return encrypt(message, self.session)


class Receiver2:
    def response1(self, p, g):
        self.p, self.g = p, g

    def response2(self, other_public):
        self.private, self.public = diffie_hellman(self.g, self.p)
        self.session = generate_session(other_public, self.private, self.p)
        return self.public

    def receive_message(self, received):
        message = decrypt(received, self.session)
        print(f"Received message: {message}")
        encrypted = encrypt(message, self.session)
        return encrypted


def intercept_messages2(sender, receiver, session_val, message_to_send=b"Hello"):
    """Send `message_to_send` between the sender and the receiver and decrypt them using the fixed session key given"""
    encrypted = sender.send_message(message_to_send)
    message = decrypt(encrypted, session_val)
    print(f"Intercepted message sent: {message}")
    returned = receiver.receive_message(encrypted)
    returned_message = decrypt(returned, session_val)
    print(f"Intercepted message received: {returned_message}")


def change_g_value(g_value, session_value, sender_public):
    sender = Sender2()
    receiver = Receiver2()
    p, g = sender.request1()
    receiver.response1(p, g_value)
    A = sender.request2()
    B = receiver.response2(sender_public)
    sender.response2(B)
    intercept_messages2(sender, receiver, session_value)


def challenge35():
    constants = get_constants()
    p, g = constants.p, constants.g
    change_g_value(1, 1, 1)
    change_g_value(p, 0, 0)
    change_g_value(p - 1, 1, 1)


if __name__ == "__main__":
    challenge35()
