# TODO: figure out all of the import problems
from set1.challenge1_2 import xor_bytes
from set1.challenge8 import get_blocks
from set2.challenge2 import encrypt_AES_CBC

from ..challenge49 import cbc_mac


def forge_message(
    goal_message: bytes, original_message: bytes, key: bytes, iv: bytes
) -> bytes:

    goal_message_with_comment = goal_message + b"//"
    padding_amount = (16 - (len(goal_message_with_comment) % 16)) % 16
    padded_message = goal_message_with_comment + b"A" * padding_amount

    # using encrypt_AES_CBC directly instead of cbc_mac to avoid adding padding
    # (message is already the correct length)
    goal_message_hash = encrypt_AES_CBC(padded_message, key, iv)
    last_block = get_blocks(goal_message_hash, 16)[-1]

    original_blocks = get_blocks(original_message, 16)
    original_blocks[0] = xor_bytes(original_blocks[0], last_block)
    modified_original = b"".join(original_blocks)

    modified_message = padded_message + modified_original
    return modified_message


def challenge50():
    original_message = b"alert('MZA who was that?');\n"
    key = b"YELLOW SUBMARINE"
    iv = b"\0" * 16
    goal_message = b"alert('Ayo, the Wu is back!');"
    forged_message = forge_message(goal_message, original_message, key, iv)
    assert cbc_mac(forged_message, key, iv) == cbc_mac(original_message, key, iv)
    # with open("fake.js", "wb") as f:
    #     f.write(forged_message)
    HTML = (
        b"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBC-MAC Forgery Test</title>
</head>
<script>%s</script>
<body>
    
</body>
</html>
    """
        % forged_message
    )
    # Chrome alerts "Ayo, the Wu is back!" successfully
    with open("forged.html", "wb") as f:
        f.write(HTML)


if __name__ == "__main__":
    challenge50()
