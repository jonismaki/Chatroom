import socket
import subprocess
import threading
import sys
import base64
from Crypto.Cipher import AES
import Crypto.Util.Padding
import Crypto.Random

class Cryptor:

    def encode(message):
        message = message.encode('UTF-8')
        message = encypt(message)
        message = base64.b64encode(message)
        return message

    def decode(message):
        message = base64.b64decode(message)
        message = decrypt(message)
        message = message.decode('UTF-8')
        return message

    def encypt(message):
        # FUNCTION ONLY CALLED FROM ENCODE
        iv = Crypto.Random.get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        message = Crypto.Util.Padding.pad(message, AES.block_size)
        message = iv + cipher.encrypt(message)
        return message

    def decrypt(message):
        # FUNCTION ONLY CALLED FROM DECODE
        iv = message[:AES.block_size]
        cipher_dec = AES.new(key, AES.MODE_CBC, iv)
        message = cipher_dec.decrypt(message[AES.block_size:])
        message = Crypto.Util.Padding.unpad(message, AES.block_size)
        return message


def main():
    print("TBA")


if __name__ == "__main__":
    main()