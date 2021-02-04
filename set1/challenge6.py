from conversions import base64_to_bytes
from challenge3 import brute_force_single_byte_xor
from set1.challenge5 import repeating_key_xor


def hamming_dist(bytestring1, bytestring2):
    # if len(bytestring1) != len(bytestring2):
    #     # raise ValueError(
    #     print(
    #         f"Bytestrings don't have same length: {bytestring1}, {bytestring2}")
    sum_so_far = 0
    for c1, c2 in zip(bytestring1, bytestring2):
        # xoring bytes makes all differences 1s and all same bits 0s
        differing = c1 ^ c2
        # count number of ones and add it to sum
        sum_so_far += bin(differing).count("1")
    return sum_so_far


def test_hamming():
    distance = hamming_dist(b"this is a test", b"wokka wokka!!!")
    print(distance)


def get_hamming_keysize(ciphertext, keysize):
    blocks = get_blocks(ciphertext, keysize)
    # distance = hamming_dist(blocks[0], blocks[1])
    # find hamming distance between every 2 consecutive blocks
    second_blocks = blocks[1:]
    first_blocks = blocks[:-1]

    distance_so_far = 0
    num_compares = 0
    for first_block, second_block in zip(first_blocks, second_blocks):
        num_compares += 1
        distance_so_far += hamming_dist(first_block, second_block)
    # divide by number of blocks compared to average out distances - prevents lower distance just because of fewer blocks with differences
    # divide by keysize also in order to correct for fact that longer keysize means more chances to be wrong -> higher hamming distance
    return distance_so_far / (num_compares * keysize)


def get_blocks(text, block_size):
    blocks = [text[i : i + block_size] for i in range(0, len(text), block_size)]
    return blocks


def brute_force_keysize(ciphertext):
    distances = {}
    for keysize in range(2, 40):
        distance = get_hamming_keysize(ciphertext, keysize)
        distances[keysize] = distance
    # returns [(keysize, distance)] with shortest distance at beginning
    sorted_distances = sorted(distances.items(), key=lambda item: item[1])
    return sorted_distances


def solve_repeating_key(ciphertext):
    keysizes = brute_force_keysize(ciphertext)
    keysize, distance = keysizes[0]
    xor_key = get_repeating_xor_key(ciphertext, keysize)
    # encryption and decryption is the same for xor because anything xored with itself is 0
    plaintext = repeating_key_xor(ciphertext, xor_key)
    return plaintext


def get_nth_byte(ciphertext, index, keysize):
    blocks = get_blocks(ciphertext, keysize)
    byte_list = []
    for block in blocks:
        if index >= len(block):
            break
        byte_list.append(block[index])
    return bytes(byte_list)


def get_repeating_xor_key(ciphertext, keysize):
    final_key = bytearray()
    for index in range(keysize):
        bytes_at_index = get_nth_byte(ciphertext, index, keysize)
        keys_at_index = brute_force_single_byte_xor(bytes_at_index)
        key_at_index, score, decrypted = keys_at_index[0]
        final_key.append(key_at_index)
    return final_key


def challenge6():
    with open("6.txt") as encrypted_file:
        base64_encoded = encrypted_file.read().replace("\n", "")
    as_bytes = base64_to_bytes(base64_encoded)
    plaintext = solve_repeating_key(as_bytes)
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    challenge6()
    # test_hamming()
