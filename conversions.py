import base64
from typing import Union


def hex_to_bytes(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


def bytes_to_hex(bytestring: bytes) -> str:
    return bytestring.hex()


def bytes_to_base64(bytestring: bytes) -> str:
    return base64.b64encode(bytestring).decode("utf-8")


def base64_to_bytes(base64_string: Union[str, bytes]) -> bytes:
    return base64.b64decode(base64_string)


def hex_to_base64(hex_string: str) -> str:
    return bytes_to_base64(hex_to_bytes(hex_string))
