from challenge3 import brute_force_single_byte_xor
from conversions import hex_to_bytes


def challenge4():
    lines = []
    with open('4.txt') as textfile:
        lines = textfile.read().splitlines()
    decrypted_list = []
    for index, line in enumerate(lines):
        bytestring = hex_to_bytes(line)
        # returns [(input_byte, score, decrypted)]
        current_decrypted = brute_force_single_byte_xor(bytestring)
        # decrypted_list is [(encrypted, input_byte, score, decrypted)]
        decrypted_list += [(index, input_byte, score, decrypted)
                           for (input_byte, score, decrypted) in current_decrypted]
    sorted_list = sorted(decrypted_list, key=get_score, reverse=True)
    for (index, input_byte, score, decrypted) in sorted_list[:5]:
        print(f'Index: {index}, Input: {lines[index]}')
        print(f'Score: {score:.2f}')
        print(f'Decrypted: {decrypted.decode("utf-8")}')


def get_score(tuple_with_score):
    line, input_byte, score, decrypted = tuple_with_score
    return score


if __name__ == "__main__":
    challenge4()
