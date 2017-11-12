"""
CPSC 526 Assignment #4
Steven Leong 10129668 T01
Josh Quines 10138118 T03
"""
import socket
import socketserver
import sys
import os
import time
import traceback
import select
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import random
import hashlib

#GLOBAL VARIABLES
BUFFER_SIZE = 4096
CIPHER = 0
BLOCK_SIZE = 128


# Authentication
    # server → client: random challenge
    # client → server: compute and send back a reply that can only be computed if secret key is known
    # server → client: verify the reply, send success/failure message to client
# The key received from the client is encrypted using cipher<x>
def authentication(client, key):
    # https://codereview.stackexchange.com/questions/47529/creating-a-string-of-random-characters
    message = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    logging("Message = " + message)
    sendEncrypted(client, message)
    # random challenge is for the client to send back SHA1(msg|key)
    hashMsg = message + key
    answer = hashlib.sha1(hashMsg.encode()).hexdigest()
    logging("H(msg|key) = " + answer)
    clientAnswer = recvEncrypted(client)
    logging("Client's Answer = " + clientAnswer)
    if answer != clientAnswer: 
        return False
    else:
        return True


def sendEncrypted(client, msg):
    byteMsg = msg.encode("utf -8")
    if CIPHER == 0:
        client.sendall(byteMsg)
    else:
        # https://cryptography.io/en/latest/hazmat/primitives/padding/?highlight=padding
        padder = padding.PKCS7(BLOCK_SIZE).padder()
        padded_data = padder.update(byteMsg) + padder.finalize()
        # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=cbc%20mode
        encryptor = CIPHER.encryptor()
        toSend = encryptor.update(padded_data) + encryptor.finalize()
        client.sendall(toSend)


def recvEncrypted(client):
    if CIPHER != 0:
        logging("cipher not equal to 0")
        message = client.recv(BUFFER_SIZE)
        decryptor = CIPHER.decryptor()
        dataRecvd = decryptor.update(message) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        data = unpadder.update(dataRecvd) + unpadder.finalize()
        return data
    else:
        message = client.recv(BUFFER_SIZE).decode("utf-8")
        return message
        


def read(client, filename):
    # Check if filename is a file
    if not os.path.isfile(filename):
        logging("File does not exist")
        sendEncrypted(client, "Error: " + filename + " could not be read by server")
        client.close()
        return
    logging("Reading from file: " + filename)

    # Open the file and read the correct size and send to the client
    try:
        with open(filename, 'rb') as rfile:
            while 1:
                content = rfile.read(BLOCK_SIZE)
                if not content:
                    break
                sendEncrypted(client, content)
            logging("File successfully read")
            sendEncrypted(client, "") # something to tell the client the file has ended
            sendEncrypted(client, "OK")
        rfile.close()
    except:
        logging("Could not open file to read")
        sendEncrypted(client, "Error: File could not be opened")


def write(client, filename):
    try:
        with open(filename, 'wb') as wfile:
            while 1:
                content = recvEncrypted(client)
                if not content:
                    break
                if content == 'OK': # Something to tell the server the file has ended
                    break
                wfile.write(content)
            logging("File successfully written")
            sendEncrypted(client, "OK")
        wfile.close()
    except:
        sendEncrypted(client, "Error: File could not be opened")
        logging("Could not opne file to write")
        client.close()
        return


def setCipher(cCipher, key, nonce):
    IVMsg = key + nonce + "IV"
    SKMsg = key + nonce + "SK"
    backend = default_backend()
    IV = hashlib.sha256(IVMsg.encode()).hexdigest()
    SK = hashlib.sha256(SKMsg.encode()).hexdigest()
    logging("IV = " + str(IV))
    logging("SK = " + str(SK))
    global BLOCK_SIZE, CIPHER
    if cCipher == 'aes128':
        # Encrypt using aes128
        BLOCK_SIZE = 128
        CIPHER = Cipher(algorithms.AES(SK[:16].encode()), modes.CBC(IV[:16].encode()), backend=backend)

    elif cCipher == 'aes256':
        # Encrypt using aes256
        BLOCK_SIZE = 256
        CIPHER = Cipher(algorithms.AES(SK), modes.CBC(IV), backend=backend)
    else:
        CIPHER = 0
        logging("Null cipher being used, IV and SK not needed")


"""Log client activity to standard output"""
def logging(msg):
    # get local time
    print(time.strftime("%a %b %d %H:%M:%S") + ": " + msg)
        

# Request
    # client → server: operation, filename
    # server → client: response indicating whether operation can proceed

# Data Exchange
    # client → server: data chunk
    # server → client: data chunk
    # In case of any errors, the server should indicate so to the client and then disconnect.
        # server → client: optional error message


def clientHandler(client, key):
    # Authenticate Client's key
    if not authentication(client, key):
        logging("Error: wrong key")
        sendEncrypted(client, "Server: Incorrect Key Used")
        client.close()
        return
    else:
        logging("Correct key used")
        sendEncrypted(client, "Server: Correct Key! Send me your request")

    # Client will send as operation;filename
    request = recvEncrypted(client).split(";")

    operation = request[0]
    filename = request[1]

    logging("Command: " + operation + " Filename: " + filename)

    # Verify the reply
    if operation == "read":
        sendEncrypted(client, "Server: Valid Operation")
        read(client, filename)
    elif operation == "write":
        sendEncrypted(client, "Server: Valid Operation")
        write(client, filename)
    else:
        sendEncrypted(client, "Server: Unknown Operation. I can only read and write.")
        client.close()



if __name__ == "__main__":

    # Arg check
    if len(sys.argv) == 3:
        PORT = int(sys.argv[1])
        KEY = sys.argv[2]
    else:
        print("\nIncorrect number of parameters: ")
        print("Usage: server.py <port> <key>")
        sys.exit()

    print("Listening on port " + str(PORT))
    print("Using secret key: " + str(KEY))

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind(('', PORT))
    serverSocket.listen(5)

    while 1:
        client, addr = serverSocket.accept()
        # First message in the clear
        # client → server: cipher, nonce
        cipherNonceMsg = client.recv(BUFFER_SIZE).decode("utf-8").split(";")
        logging("cipher = " + cipherNonceMsg[0])
        logging("nonce = " + cipherNonceMsg[1] )
        cCipher = cipherNonceMsg[0]
        nonce = cipherNonceMsg[1]

        logging("new connection from " + str(addr[0]) + " cipher = " + cCipher)
        logging("nonce = " + nonce)
        sendEncrypted(client, "Server: Cipher and nonce received.")
        
        logging("setting Cipher")
        setCipher(cCipher, KEY, nonce)

        logging("handling client")
        clientHandler(client, KEY) 
        # Final Success
        # server → client: final success
        logging("End of main")

        client.close()

