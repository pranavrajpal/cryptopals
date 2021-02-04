from flask import Flask, request, make_response
from Crypto.Random import get_random_bytes
from helper_functions import hmac_sha1
import random
from conversions import hex_to_bytes, bytes_to_hex
from enum import Enum
import time
import sys

app = Flask(__name__)

# status codes
FILE_NOT_FOUND = 400
INVALID_MAC = 500
CORRECT_MAC = 200


def start_app(delay_ms):
    # set delay time after each byte comparison in milliseconds
    app.config['delay_ms'] = delay_ms
    app.run(port=9000)


key = None
@app.before_first_request
def generate_key():
    global key
    key_size = random.randint(5, 100)
    # key = get_random_bytes(key_size)
    # print(bytes_to_hex(key))
    # TODO: change this back to random key
    key = b'\0' * 16


@app.route('/test')
def receive_request():
    filename = request.args['file']
    signature = request.args['signature']
    try:
        with open(filename, 'rb') as file_handle:
            contents = file_handle.read()
            correct = insecure_compare(contents, signature)
            # return bytes_to_hex(hmac_sha1(key, contents))
            if correct:
                expected_hmac = hmac_sha1(key, contents)
                print('Expected hmac: ', bytes_to_hex(expected_hmac))
                return make_response('Correct signature', CORRECT_MAC)
            else:
                return make_response('Incorrect signature', INVALID_MAC)
    except FileNotFoundError:
        return make_response('File not found', FILE_NOT_FOUND)
    # return f'Filename: {filename}, Signature: {signature}'


def insecure_compare(contents, received_hmac_hex):
    global key
    delay_ms = app.config['delay_ms']
    expected_hmac = hmac_sha1(key, contents)
    received_hmac = hex_to_bytes(received_hmac_hex)
    # break if received isn't the correct length
    if len(received_hmac) != len(expected_hmac):
        return False
    for expected, received in zip(expected_hmac, received_hmac):
        if expected != received:
            return False
        time.sleep(delay_ms / 1000)

    print('Expected hmac: ', bytes_to_hex(expected_hmac))
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Please specify the number of milliseconds for delay')
        exit(1)
    delay_ms = int(sys.argv[1])
    start_app(delay_ms)
