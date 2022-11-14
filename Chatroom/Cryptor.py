import hashlib
import base64
from Crypto.Cipher import AES
import Crypto.Util.Padding
import Crypto.Random

class Cryptor:

    def __init__(self, init_key):
        self.key = hashlib.sha256(init_key.encode("utf-8")).digest()


    def encode(self, message):
        message = message.encode('UTF-8')
        message = self.encypt(message)
        message = base64.b64encode(message)
        return message

    def decode(self, message):
        message = base64.b64decode(message)
        message = self.decrypt(message)
        message = message.decode('UTF-8')
        return message

    def encypt(self, message):
        # FUNCTION ONLY CALLED FROM ENCODE
        iv = Crypto.Random.get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        message = Crypto.Util.Padding.pad(message, AES.block_size)
        message = iv + cipher.encrypt(message)
        return message

    def decrypt(self, message):
        # FUNCTION ONLY CALLED FROM DECODE
        iv = message[:AES.block_size]
        cipher_dec = AES.new(self.key, AES.MODE_CBC, iv)
        message = cipher_dec.decrypt(message[AES.block_size:])
        message = Crypto.Util.Padding.unpad(message, AES.block_size)
        return message


def main():
    test_key = "abcdefghijklmnop"
    test_text = "Testi tekstiä, testataan tänään tekstiä. Toivottavasti toimii"
    print(f"Testing functions with key: {test_key}")
    cryptor = Cryptor(test_key)

    encoded_test_text = cryptor.encode(test_text)
    print("Printing encoded and Encrypted test_message")
    print(encoded_test_text)

    decoded_test_text = cryptor.decode((encoded_test_text))
    print("Printing, decoded and decrypted, encoded and encrypted test_message")
    print(decoded_test_text)

if __name__ == "__main__":
    main()