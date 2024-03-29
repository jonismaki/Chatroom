import threading
import socket
import sys


############################### FUNKTIOT #####################################

def broadcast(message, sender):
    for client in clients:
        if sender != client:
            try:
                client.send(message)
            except Exception as e:
                print(e)


def client_handle(client):
    while True:
        try:
            message = client.recv(1024)
            broadcast(message, client)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f'{nickname} left the chat!'.encode('UTF-8'), client)
            nicknames.remove(nickname)
            break

def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        client.send("NICK".encode('UTF-8'))
        nickname = client.recv(1024).decode('UTF-8')
        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname of the client is {nickname}!")
        broadcast(f"{nickname} joined the chat.".encode('UTF-8'), client)
        client.send("Connected to the server!".encode('UTF-8'))

        thread = threading.Thread(target=client_handle, args=(client,))
        thread.start()


################################## MAIN ######################################


if len(sys.argv) != 3:
    print("Correct usage: script, IP address, port number")
    exit()

host = str(sys.argv[1])
port = int(sys.argv[2])

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen() # Has backlog parameter, when empty uses default

clients = []
nicknames = []

print("Server is listening...")
receive()