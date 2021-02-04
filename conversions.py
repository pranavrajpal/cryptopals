import base64


def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)


def bytes_to_hex(bytestring):
    return bytestring.hex()


def bytes_to_base64(bytestring):
    return base64.b64encode(bytestring).decode("utf-8")


def base64_to_bytes(base64_string):
    return base64.b64decode(base64_string)


def hex_to_base64(hex_string):
    return bytes_to_base64(hex_to_bytes(hex_string))
