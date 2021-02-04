from set3.challenge2 import encrypt_AES_CTR
from Crypto.Random import get_random_bytes
from secrets import randbits
import zlib
import string


def compression_oracle(plaintext):
    """Takes `plaintext` without newline"""
    http_request = "POST / HTTP/1.1\n"
    http_request += "Host: hapless.com\n"
    http_request += "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
    http_request += f"Content-Length: {len(plaintext)}\n"
    http_request += plaintext + "\r\n"

    compressed = zlib.compress(http_request.encode("utf-8"))
    encrypted = encrypt_AES_CTR(compressed, get_random_bytes(16), randbits(64))
    return len(encrypted)


base64_alphabet = string.ascii_letters + string.digits + "-_"


def challenge51():
    compression_oracle("hello")


if __name__ == "__main__":
    challenge51()
