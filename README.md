"# Chatroom" 
Chatroom is a simple socket based chat application, that has the function to
execute commandline commands on Windows and Linux. 
Data that travels between clients through the server is encrypted using AES.

Some of the modules are not yet finished, but do function. 
Cryptor has two added functions which are used to send and read data in chunks, in the
case data exeeds the set size. These functions are to be moved to their own module.
Some of the modules also cannot yet be ran on their own for testing.


Project has the following modules:
- Server.py which sets up a server for clients to connect to 
- Client.py which sets up client that connects to server
- Cryptor.py handles encoding, decoding, encrypting and decrypting
- Commander.py handles the running of the cmd calls.

Project uses pycryptodome
