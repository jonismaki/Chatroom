def agent(message, key):
    msg = []
    msgNum = []
    for i in message:
        msg.append(i)

    index = 0
    keyIndex = 0
    while(index < len(msg)):
        msgNum.append(ord(msg[index]) + key[keyIndex])
        index = index + 1
        keyIndex = keyIndex + 1
        if keyIndex >= len(key):
            keyIndex = 0

    index = 0
    for i in msgNum:
        msg[index] = chr(i)
        index = index + 1

    viesti = ''.join([str(elem) for elem in msg])
    return viesti

def revert(message, key):
    msg = []
    msgNum = []
    for i in message:
        msg.append(i)

    index = 0
    keyIndex = 0
    while(index < len(msg)):
        msgNum.append(ord(msg[index]) - key[keyIndex])
        index = index + 1
        keyIndex = keyIndex + 1
        if keyIndex >= len(key):
            keyIndex = 0

    index = 0
    for i in msgNum:
        msg[index] = chr(i)
        index = index + 1

    viesti = ''.join([str(elem) for elem in msg])
    return viesti