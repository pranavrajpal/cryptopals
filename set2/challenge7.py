from .challenge1 import pkcs7_unpad


def challenge7():
    input1 = b"ICE ICE BABY\x04\x04\x04\x04"
    output1 = pkcs7_unpad(input1).decode("utf-8")
    print(f"Output 1: {output1}")
    try:
        input2 = b"ICE ICE BABY\x05\x05\x05\x05"
        output2 = pkcs7_unpad(input2).decode("utf-8")
        print(f"Output 2: {output2}")
    except ValueError as e:
        print(f"Received error: {e}")
    try:
        input3 = b"ICE ICE BABY\x01\x02\x03\x04"
        output3 = pkcs7_unpad(input3).decode("utf-8")
        print(f"Output 2: {output3}")
    except ValueError as e:
        print(f"Received error: {e}")


if __name__ == "__main__":
    challenge7()
