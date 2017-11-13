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

# https://gist.github.com/crmccreary/5610068
padder = lambda s: s + (BL0CK_SIZE - len(s) % BL0CK_SIZE) * chr(BL0CK_SIZE - len(s) % BL0CK_SIZE) 
unpad = lambda s : s[0:-ord(s[-1])]


# Authentication
    # server → client: random challenge
    # client → server: compute and send back a reply that can only be computed if secret key is known
    # server → client: verify the reply, send success/failure message to client
# The key received from the client is encrypted using cipher<x>
def authentication(client, key):
    # https://codereview.stackexchange.com/questions/47529/creating-a-string-of-random-characters
    message = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    #logging("Message = " + message)
    sendEncrypted(client, message)
    # random challenge is for the client to send back SHA1(msg|key)
    hashMsg = message + key
    answer = hashlib.sha1(hashMsg.encode()).hexdigest()
    #logging("H(msg|key) = " + answer)
    clientAnswer = recvEncrypted(client)
    #logging("Client's Answer = " + str(clientAnswer))
    if answer != clientAnswer: 
        return False
    else:
        return True


def sendEncrypted(client, msg):
    try:
        byteMsg = msg.encode("utf-8")
    except:
        byteMsg = msg
    #logging("byteMsg = " + str(byteMsg))
    #logging("byteMsg length = " + str(len(byteMsg)))
    #logging("CIPHER = " + str(CIPHER))
    if CIPHER == 0:
        client.sendall(byteMsg)
    else:
        # https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes
        # https://cryptography.io/en/latest/hazmat/primitives/padding/?highlight=padding
        #old padder = padding.PKCS7(BLOCK_SIZE).padder()
        #old padded_data = padder.update(byteMsg) + padder.finalize()
        #padded_data = pad(msg)
        length = (BLOCK_SIZE//8) - (len(byteMsg) % (BLOCK_SIZE//8))
        #logging("length = " + str(length))
        byteMsg += bytes([length])*length
        #byteMsg =byteMsg
        #logging("new byteMsg = " + byteMsg.decode())
        #logging("new byteMsg length  = " + str(len(byteMsg)))
        # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=cbc%20mode
        encryptor = CIPHER.encryptor()
        toSend = encryptor.update(byteMsg) + encryptor.finalize()
        client.sendall(toSend)
        #print("Encryption = " + str(toSend))
        #print(len(toSend))
    #print("debug")


def recvEncrypted(client):
    if CIPHER == 0:
        data = client.recv(BLOCK_SIZE).decode("utf-8")
        return data
    else:
        data = client.recv(BLOCK_SIZE)
        #print("data length = " + str(len(data)))
        decryptor = CIPHER.decryptor()
        dataRecvd = decryptor.update(data) + decryptor.finalize()
        #unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        dataRecvd = dataRecvd[:-dataRecvd[-1]]
        #data = unpadder.update(dataRecvd) + unpadder.finalize()
        dataRecvd = dataRecvd.decode("utf-8")
        #print("dataRecvd = " + dataRecvd)
        #data = unpad(cipher.decrypt(dataRecvd))
        return dataRecvd
        

# Server reads the file contents and sends it to the Client encrypted
def read(client, filename):
    # Check if filename is a file
    if not os.path.isfile(filename):
        logging("File does not exist")
        sendEncrypted(client, "Error: " + filename + " could not be read by server")
        client.close()
        return
    #logging("Reading from file: " + filename)

    # Open the file and read the correct size and send to the client
    try:
        #logging("Trying to read " + filename)
        with open(filename, 'rb') as rfile:
            while 1:
                content = rfile.read(BLOCK_SIZE).decode("utf-8")
                #logging("CONTENT: " + content)
                if not content:
                    #logging("not sending content")
                    sendEncrypted(client, content)
                    break
                #logging("Sending content")
                sendEncrypted(client, content)
            #sendEncrypted(serverSocket, "") # something to tell the server the file has ended
        rfile.close()
    except:
        sendEncrypted(client, "Error: File could not be read by server")
        logging("Error: File could not be read by server")
        client.close()
        return

def write(client, filename):
    try:
        with open(filename, 'wb') as wfile:
            #logging("trying to write to " + filename)
            while 1:
                content = recvEncrypted(client)
                #logging("CONTENT: " + str(content))
                if not content:
                    logging("file has ended")
                    break
                #logging("Writing content")
                wfile.write(content)
            #logging("File successfully written")
        wfile.close()
        client.close()
    except:
        sendEncrypted(client, "Error: File could not be written by server")
        logging("Error: File could not be written by server")
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
    try:
        if cCipher == 'aes128':
            # Encrypt using aes128
            BLOCK_SIZE = 128
            CIPHER = Cipher(algorithms.AES(SK[:16].encode()), modes.CBC(IV[:16].encode()), backend=backend)

        elif cCipher == 'aes256':
            # Encrypt using aes256
            BLOCK_SIZE = 256
            CIPHER = Cipher(algorithms.AES(SK[:32].encode()), modes.CBC(IV[:16].encode()), backend=backend)
        else:
            CIPHER = 0
            logging("Null cipher being used, IV and SK not needed")
    except:
        tb = traceback.format_exc()
        print (tb)



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
        sendEncrypted(client, "Error: Incorrect Key Used")
        client.close()
        return
    else:
        logging("Correct key used")
        sendEncrypted(client, "Server: Correct Key")

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
        logging("Error: wrong command line arguments")
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
        #logging("cipher = " + cipherNonceMsg[0])
        #logging("nonce = " + cipherNonceMsg[1] )
        cCipher = cipherNonceMsg[0]
        nonce = cipherNonceMsg[1]

        logging("new connection from " + str(addr[0]) + " cipher = " + cCipher)
        #logging("nonce = " + nonce)
        
        #logging("setting Cipher")
        setCipher(cCipher, KEY, nonce)
        #logging("Block Size = " + str(BLOCK_SIZE))
        sendEncrypted(client, "Server: Cipher and nonce received.")

        #logging("handling client")
        clientHandler(client, KEY) 
        # Final Success
        # server → client: final success
        logging("status: Success")

        client.close()

