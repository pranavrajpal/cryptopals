from conversions import hex_to_base64, bytes_to_hex, hex_to_bytes


def challenge1():
    hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base64_string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    converted = hex_to_base64(hex_string)
    print(f'Converted to Base 64: {converted}')
    print(f'Expected:             {base64_string}')
    print(f'Correct? {converted == base64_string}')


def xor_bytes(bytes1, bytes2):
    output = bytearray()
    if len(bytes1) != len(bytes2):
        # print('invalid length')
        raise ValueError("byte sequences aren't the same length",
                         bytes_to_hex(bytes1), bytes_to_hex(bytes2))
    for c1, c2 in zip(bytes1, bytes2):
        output.append(c1 ^ c2)
    return output


def challenge2():
    input1 = hex_to_bytes('1c0111001f010100061a024b53535009181c')
    input2 = hex_to_bytes('686974207468652062756c6c277320657965')
    expected_output = '746865206b696420646f6e277420706c6179'
    expected_bytes = hex_to_bytes(expected_output)
    xored = xor_bytes(input1, input2)
    print(f'Output:   {bytes_to_hex(xored)}')
    print(f'Expected: {expected_output}')
    print(f'Correct?: {expected_bytes == xored}')


if __name__ == '__main__':
    challenge2()
