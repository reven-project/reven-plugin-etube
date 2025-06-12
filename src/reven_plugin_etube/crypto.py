import typer
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Annotated
from enum import Enum
import base64

app = typer.Typer()


class KeyFormat(str, Enum):
    HEX = "hex"
    B64 = "base64"


def parse_key(key_format: KeyFormat, key: str):
    match key_format:
        case KeyFormat.HEX:
            return bytes.fromhex(key)
        case KeyFormat.B64:
            return base64.b64decode(key, validate=True)


@app.command(help="Decrypt E-Tube file using AES.")
def decrypt(
    key_format: KeyFormat,
    key: str,
    input: typer.FileText = sys.stdin,
    output: typer.FileTextWrite = sys.stdout,
    codec: Annotated[
        str,
        typer.Argument(
            help="The text codec to use for reading / writing the plaintext."
        ),
    ] = "utf-16-le",
):
    iv = input.buffer.read(16)
    cipher = AES.new(parse_key(key_format, key), AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(input.buffer.read())
    # remove PKCS#7 padding
    plaintext = plaintext[: -plaintext[-1]]
    plaintext = plaintext.decode(codec).encode("utf-8")
    output.buffer.write(plaintext)


@app.command(help="Encrypt an E-Tube file using AES.")
def encrypt(
    key_format: KeyFormat,
    key: str,
    input: typer.FileText = sys.stdin,
    output: typer.FileTextWrite = sys.stdout,
    codec: Annotated[
        str,
        typer.Argument(
            help="The text codec to use for reading / writing the plaintext."
        ),
    ] = "utf-16-le",
):
    iv = get_random_bytes(16)
    cipher = AES.new(parse_key(key_format, key), AES.MODE_CBC, iv)
    plaintext = input.read().encode(codec)
    if len(plaintext) % 16 != 0:
        pad_bytes = 16 - (len(plaintext) % 16)
        plaintext += bytes((pad_bytes,) * pad_bytes)
    ciphertext = iv + cipher.encrypt(plaintext)
    output.buffer.write(ciphertext)
