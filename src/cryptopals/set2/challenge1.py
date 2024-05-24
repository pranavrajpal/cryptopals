def pkcs7_pad(unpadded: bytes, block_size: int) -> bytes:
    length = len(unpadded)
    last_block_amount = length % block_size
    needed_padding = block_size - last_block_amount
    # if already aligned, add another block of padding so it can be removed
    if needed_padding == 0:
        needed_padding += block_size
    padding = bytes([needed_padding] * needed_padding)
    return unpadded + padding


def pkcs7_unpad(padded: bytes) -> bytes:
    padding_length = padded[-1]
    expected_padding = bytes([padding_length] * padding_length)
    if padded[-padding_length:] != expected_padding:
        raise ValueError("invalid PKCS#7 padding")
    unpadded = padded[:-padding_length]
    return unpadded


def challenge1():
    padded = pkcs7_pad(b"YELLOW SUBMARINE", 20).decode('utf-8')
    print(f"Padded: {padded}")


if __name__ == "__main__":
    challenge1()
