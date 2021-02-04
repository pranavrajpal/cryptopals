from conversions import hex_to_bytes


def get_blocks(bytestring, blocksize):
    blocks = [bytestring[i:i + blocksize]
              for i in range(0, len(bytestring), blocksize)]
    return blocks


def get_num_duplicates(bytestring, blocksize):
    blocks = get_blocks(bytestring, blocksize)
    duplicates = 0
    found_blocks = {}
    for block in blocks:
        if block not in found_blocks:
            found_blocks[block] = True
        else:
            duplicates += 1
    return duplicates


def find_most_duplicates(bytestring_list):
    num_duplicates = {}
    for bytestring in bytestring_list:
        duplicates = get_num_duplicates(bytestring, 16)
        num_duplicates[bytestring] = duplicates
    sorted_duplicates = sorted(
        num_duplicates, key=lambda key: num_duplicates[key], reverse=True)
    return [(k, num_duplicates[k]) for k in sorted_duplicates]


def challenge8():
    with open('8.txt') as file_handle:
        contents = [hex_to_bytes(line.strip())
                    for line in file_handle.read().splitlines()]
        num_duplicates_list = find_most_duplicates(contents)
        most_duplicates_bytestring, duplicates = num_duplicates_list[0]
        print(f'Bytestring: {most_duplicates_bytestring}')
        print(f'Number of duplicates: {duplicates}')
        print(f'Line Number: {1+contents.index(most_duplicates_bytestring)}')


if __name__ == "__main__":
    challenge8()
