from conversions import hex_to_bytes
from set1.challenge1_2 import xor_bytes
import string


def get_english_freq(character):
    english_text_frequencies = {'a': 08.497, 'b': 01.492, 'c': 02.202, 'd': 04.253, 'e': 11.162, 'f': 02.228, 'g': 02.015,
                                'h': 06.094, 'i': 07.546, 'j': 00.153, 'k': 01.292, 'l': 04.025, 'm': 02.406, 'n': 06.749,
                                'o': 07.507, 'p': 01.929, 'q': 00.095, 'r': 07.587, 's': 06.327, 't': 09.356, 'u': 02.758,
                                'v': 00.978, 'w': 02.560, 'x': 00.150, 'y': 01.994, 'z': 00.077, ' ': 11.3}
    # make space slightly higher than the letter e according to
    # https://en.wikipedia.org/wiki/Letter_frequency
    return english_text_frequencies.get(chr(character), 0)


def is_valid_ascii(bytestring):
    try:
        input_string = bytestring.decode('utf-8')
        return set(input_string).issubset(string.printable)
    except UnicodeDecodeError as e:
        return False


def get_freq_dict(string):
    frequencies = {}
    for c in string:
        if c not in frequencies:
            frequencies[c] = 1
        else:
            frequencies[c] += 1
    return frequencies


def check_english(string):
    # uses frequency analysis to determine ranking for whether string is english text
    # higher score means worse
    english_text_frequencies = 'ETAOINSRHDLUCMFYWGPBVKXQJZ'
    if not is_valid_ascii(string):
        return 500
    # get frequencies and convert it to a list
    frequencies_dict = get_freq_dict(string)
    sorted_dict = sorted(
        frequencies_dict, key=lambda key: frequencies_dict[key], reverse=True)
    # if condition at end removes all characters not in the alphabet
    frequencies_string = ''.join(
        [chr(c) for c in sorted_dict]).upper()
    # compare 2 frequency lists by determining distance between corresponding elements in both lists -
    # should have a bigger impact if closer to beginning of list
    score = 0
    for index, c in enumerate(frequencies_string):
        english_index = english_text_frequencies.find(c)
        if english_index == -1:
            score += 30
        else:
            difference = abs(index - english_index)
            score += difference
    return score


def check_english_v2(string):
    # uses frequency analysis to determine ranking for whether string is english text
    # higher score means better (more likely to be english)

    # returns None if string isn't valid ascii
    input_frequencies = get_freq_dict(string)
    if not is_valid_ascii(string):
        return None
    # multiply frequencies for regular english and input string for each character together -
    # if both are high, score will be higher (more common letters should have greater impact on score)
    # if one is high and one is low, score will be slightly lower but not much (difference lowers score)
    # if both are low, score is low (less common letters have less impact on final score)
    score = 0
    for character in string:
        # use 0 as default if character isn't valid english - makes current letter have no effect on score
        english_freq = get_english_freq(character)
        input_freq = input_frequencies[character]
        score += english_freq * input_freq
    return score


def brute_force_single_byte_xor(bytestring):
    decryption_keys = {}
    for c in range(0, 0xFF + 1):
        # construct bytestring of correct length
        to_xor = bytes([c] * len(bytestring))
        decrypted = xor_bytes(bytestring, to_xor)
        score = check_english_v2(decrypted)
        if score != None:
            decryption_keys[c] = (score, decrypted)
    # sort keys by score
    sorted_inputs = sorted(
        decryption_keys, key=lambda key: decryption_keys[key][0], reverse=True)
    # returns [(decryption_key, score, decrypted)]
    return [(k, decryption_keys[k][0], decryption_keys[k][1]) for k in sorted_inputs]


def challenge3():
    encrypted = hex_to_bytes(
        '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    decrypted_list = brute_force_single_byte_xor(encrypted)
    for input_byte, score, decrypted in decrypted_list[:5]:
        print(f'Input Byte: {hex(input_byte)}')
        print(f'Score: {score}')
        print(f'Decrypted: {decrypted}')


if __name__ == '__main__':
    challenge3()
