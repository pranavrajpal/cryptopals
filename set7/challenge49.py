from set2.challenge2 import encrypt_AES_CBC
from Crypto.Random import get_random_bytes
from set2.challenge1 import pkcs7_pad, pkcs7_unpad
from set1.challenge8 import get_blocks
from set2.challenge5 import url_decode, url_encode
from set1.challenge1_2 import xor_bytes
from set5.challenge36 import create_connection

# ID numbers for API server
CLIENT_ID = 2
ATTACKER_ID = 1


def cbc_mac(message, key, iv):
    """Calculates the CBC-MAC of the bytestring `message` with the bytestring `key`"""
    padded_message = pkcs7_pad(message, 16)
    encrypted = encrypt_AES_CBC(padded_message, key, iv)
    blocks = get_blocks(encrypted, 16)
    return blocks[-1]


class ServerWithIV:
    def __init__(self):
        self.key = get_random_bytes(16)

    def send_message(self, to, amount):
        assert to != ATTACKER_ID
        message = {
            'from': CLIENT_ID,
            'to': to,
            'amount': amount
        }
        iv = get_random_bytes(16)
        url_encoded = url_encode(message).encode('utf-8')
        mac = cbc_mac(url_encoded, self.key, iv)
        return url_encoded + iv + mac

    def receive_message(self, bytestring):
        """Receives a message of the form message || IV || MAC, where MAC is the CBC-MAC of the message,
        and decodes the MAC if it's valid"""
        message = bytestring[:-32]
        iv, mac = bytestring[-32:-16], bytestring[-16:]
        calculated_mac = cbc_mac(message, self.key, iv)
        if calculated_mac != mac:
            return None
        try:
            return url_decode(message.decode('utf-8'), separator='&')
        except UnicodeDecodeError:
            return None


def transactions_list_to_string(transactions):
    transactions_string = ''
    for to, amount in transactions:
        transactions_string += f'{to}:{amount};'
    # remove final semicolon
    return transactions_string[:-1]


def string_to_transactions(string):
    transactions = []
    for transaction in string.split(';'):
        to, amount = transaction.split(':')
        transactions.append((to, amount))
    return transactions


def bytestring_to_transactions(bytestring):
    transactions = []
    for transaction in bytestring.split(b';'):
        to, amount = transaction.split(b':')
        transactions.append((to, amount))
    return transactions


fixed_iv_key = get_random_bytes(16)


class ClientFixedIV:
    def __init__(self, client_id):
        self.key = fixed_iv_key
        self.id = client_id

    def send_messages(self, transactions):
        """Takes a list of (to, amount) tuples and creates a message with all of the transactions
        from the current id"""
        transactions_string = transactions_list_to_string(transactions)

        message = {
            'from': self.id,
            'tx_list': transactions_string
        }
        url_encoded = url_encode(message).encode('utf-8')
        mac = cbc_mac(url_encoded, self.key, b'\x00' * 16)
        return url_encoded + mac


def create_server_client(client_id):
    """Returns the tuple (client, server)"""
    client = ClientFixedIV(client_id)
    server = ServerFixedIV()
    return client, server


class ServerFixedIV:
    """Same as other server, but fixes IV at 0 and allows for multiple transactions at a time"""

    def __init__(self):
        self.key = fixed_iv_key

    def receive_messages(self, bytestring):
        """Receives a message of the form messages || MAC, where MAC is the CBC-MAC of the message,
        and the IV is fixed at 0. The decoded message will be returned if the MAC is valid"""
        message, mac = bytestring[:-16], bytestring[-16:]
        calculated_mac = cbc_mac(message, self.key, b'\x00' * 16)
        if calculated_mac != mac:
            print('invalid mac')
            return None
        try:
            decoded = bytes_url_decode(message, separator=b'&')
            decoded[b'tx_list'] = bytestring_to_transactions(
                decoded[b'tx_list'])
            return decoded
        except UnicodeDecodeError:
            print('invalid unicode')
            return None


def bytes_url_decode(bytestring, separator=b'&'):
    pairs = bytestring.split(separator)
    output = {}
    for pair in pairs:
        try:
            key, val = pair.split(b'=')
        except ValueError:
            print(f'Pair: {pair}')
            raise
        output[key] = val
    return output


def test_cbc_mac():
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    mac = cbc_mac(b'abcd', key, iv)
    print(mac)
    # taken from challenge 50 description
    key = b'YELLOW SUBMARINE'
    iv = b'\0' * 16
    message = b"alert('MZA who was that?');\n"
    mac = cbc_mac(message, key, iv)
    print(mac.hex())


def cbc_iv_controlled_forge_message(server, encrypted):
    # Note: this breaks on any id that is more than one digit long
    message = encrypted[:-32]
    iv, mac = encrypted[-32:-16], encrypted[-16:]
    prefix_len = len(f'from={CLIENT_ID}&to=')
    modified_message = bytearray(message)
    current_id = 3

    difference = current_id ^ ATTACKER_ID
    modified_message[prefix_len] ^= difference
    modified_iv = bytearray(iv)
    modified_iv[prefix_len] ^= difference
    # assert xor_bytes(modified_iv, modified_message[:16]) == xor_bytes(iv, message[:16])
    modified_encoded = modified_message + modified_iv + mac
    return server.receive_message(modified_encoded)


def cbc_length_extension(attacker_client, server, captured_bytestring):
    captured_message = captured_bytestring[:-16]
    captured_mac = captured_bytestring[-16:]
    # [original message] [first block append xor original mac] [rest of append]
    padded_message = pkcs7_pad(captured_message, 16)

    attacker_message_with_mac = attacker_client.send_messages(
        [(ATTACKER_ID, 10), (ATTACKER_ID, 1_000_000)])
    attacker_message = attacker_message_with_mac[:-16]
    attacker_mac = attacker_message_with_mac[-16:]
    # attacker message first 16 bytes is from field and beginning of tx_list
    # (we don't want that in the final thing anyway)
    # FIXME: find a way to avoid having colon in final section of attacker message -
    # current attack bypasses MAC check but fails when parsing the final message because of
    # colon in final message
    modified_message = padded_message + \
        xor_bytes(attacker_message[:16],
                  captured_mac) + attacker_message[16:]
    modified_mac = cbc_mac(modified_message, fixed_iv_key, b'\0' * 16)
    assert modified_mac == attacker_mac
    print(server.receive_messages(modified_message + attacker_mac))


def challenge49():
    print('IV in message attack')
    server = ServerWithIV()
    message = server.send_message(3, 1000000)
    response = cbc_iv_controlled_forge_message(server, message)
    print(response)
    print('Fixed IV length extension attack')
    attacker_client, _ = create_server_client(ATTACKER_ID)
    normal_client, server = create_server_client(CLIENT_ID)
    captured_message = normal_client.send_messages([(3, 10)])

    response2 = cbc_length_extension(
        attacker_client, server, captured_message)


if __name__ == "__main__":
    challenge49()
    # test_cbc_mac()
