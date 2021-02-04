from Crypto.Random import get_random_bytes

from set1.challenge8 import get_blocks
from set2.challenge1 import pkcs7_pad, pkcs7_unpad
from set2.challenge2 import decrypt_AES_ECB, encrypt_AES_ECB


class Encryption:
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, email):
        dict_string = profile_for(email)
        dict_bytes = dict_string.encode("utf-8")
        padded = pkcs7_pad(dict_bytes, 16)
        encrypted = encrypt_AES_ECB(padded, self.key)
        return encrypted

    def decrypt(self, encrypted):
        decrypted = decrypt_AES_ECB(encrypted, self.key)
        padding_removed_bytes = pkcs7_unpad(decrypted)
        padding_removed_string = padding_removed_bytes.decode("utf-8")
        dictionary = url_decode(padding_removed_string)
        return dictionary


def url_decode(string, separator="&"):
    pairs = string.split(separator)
    output = {}
    for pair in pairs:
        key, val = pair.split("=")
        output[key] = val
    return output


def url_encode(dictionary):
    string = ""
    for key, val in dictionary.items():
        string += f"{key}={val}&"
    # remove last & sign
    string = string[:-1]
    return string


def test_url_decode():
    test_string = "foo=bar&baz=qux&zap=zazzle"
    print(url_decode(test_string))


def test_url_encode():
    dictionary = {"email": "foo@bar.com", "uid": 10, "role": "user"}
    print(url_encode(dictionary))


def profile_for(email):
    safe_email = email.replace("&", "").replace("=", "")
    dictionary = {"email": safe_email, "uid": 10, "role": "user"}
    return url_encode(dictionary)


def cut_and_paste_ECB(cipher):
    email_beginning = "foo@bar.com"
    block_to_encrypt = pkcs7_pad(b"admin", 16)
    # use the cipher to encrypt the admin block
    email_padding_encryption = 16 - (len(f"email={email_beginning}") % 16)
    encryption_block_prefix = "A" * email_padding_encryption + email_beginning
    prefix_num_blocks = len(f"email={encryption_block_prefix}") // 16
    encryption_input = encryption_block_prefix + block_to_encrypt.decode("utf-8")

    encrypted = cipher.encrypt(encryption_input)
    blocks = get_blocks(encrypted, 16)
    encrypted_block = blocks[prefix_num_blocks]

    input_string_no_padding = f"email={email_beginning}&uid=10&role="
    # padding added to email to make role= the end of its block
    email_padding_role = 16 - (len(input_string_no_padding) % 16)
    email = email_padding_role * "A" + email_beginning
    final_encrypted_user = cipher.encrypt(email)
    blocks = get_blocks(final_encrypted_user, 16)
    blocks[-1] = encrypted_block
    final_encrypted_admin = b"".join(blocks)
    results = cipher.decrypt(final_encrypted_admin)
    return results


def challenge5():
    cipher = Encryption()
    results = cut_and_paste_ECB(cipher)
    print(results)


if __name__ == "__main__":
    challenge5()
