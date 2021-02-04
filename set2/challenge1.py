from conversions import base64_to_bytes


def pkcs7_pad(unpadded, block_size):
    length = len(unpadded)
    last_block_amount = length % block_size
    needed_padding = block_size - last_block_amount
    # if already aligned, add another block of padding so it can be removed
    if needed_padding == 0:
        needed_padding += block_size
    padding = bytes([needed_padding] * needed_padding)
    return unpadded + padding


def pkcs7_unpad(padded):
    padding_length = padded[-1]
    expected_padding = bytes([padding_length] * padding_length)
    if padded[-padding_length:] != expected_padding:
        raise ValueError("invalid PKCS#7 padding")
    unpadded = padded[:-padding_length]
    return unpadded


def challenge1():
    padded = pkcs7_pad(b"YELLOW SUBMARINE", 20)
    print(f"Padded: {padded}")


if __name__ == "__main__":
    challenge1()
