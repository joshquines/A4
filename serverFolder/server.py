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
import binascii

#GLOBAL VARIABLES
BUFFER_SIZE = 1024
CIPHER = 0
CIPHER_FILE = 0
BLOCK_SIZE = 128
IVMsg = None 
SKMsg = None 

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
    clientAnswer = recvEncrypted(client).decode("utf-8")
    logging("Client's Answer = " + str(clientAnswer))
    if answer != clientAnswer: 
        return False
    else:
        return True


def sendEncrypted(client, msg):
    # try changing the type of msg to bytes
    try:
        byteMsg = msg.encode()
    except:
        byteMsg = msg

    if CIPHER == 0:
        client.sendall(byteMsg)
    else:
        # https://stackoverflow.com/questions/14179784/python-encrypting-with-pycrypto-aes#
        # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=cbc%20mode
        #print("byteMsg length = " + str(len(byteMsg)))
        length = BLOCK_SIZE//8 - (len(byteMsg) % (BLOCK_SIZE//8))
        # if byteMsg is BLOCK_SIZE length would add BLOCK_SIZE//8 padding
        if length == BLOCK_SIZE//8:
            # Instead add BLOCK_SIZE of padding
            length = 0
        #else:
            # Add BLOCK_SIZE of padding
        #    length += BLOCK_SIZE
        #print("pad length = " + str(length))
        pad = bytes([length])*length
        #print("byteMsg = " + str(byteMsg))
        #print("pad = " + str(pad))
        byteMsg = byteMsg + pad
        #print("padded msg = " + str(byteMsg))
        #print("padded msg len = " + str(len(byteMsg)))

        encryptor = CIPHER.encryptor()
        toSend = encryptor.update(byteMsg) + encryptor.finalize()
        #print("encrypted = " + str(toSend))
        client.sendall(toSend)



def recvEncrypted(client):
    if CIPHER != 0:
        #logging("cipher not equal to 0")
        message = client.recv(BLOCK_SIZE*2)
        #logging("received msg = " + str(message))
        decryptor = CIPHER.decryptor()
        dataRecvd = decryptor.update(message) + decryptor.finalize()
        #unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        #data = unpadder.update(dataRecvd) + unpadder.finalize()
        #data = unpad(cipher.decrypt(dataRecvd))
        #logging("decrypted = " + str(dataRecvd))
        if  len(dataRecvd) != 0 and dataRecvd[len(dataRecvd)-1] == dataRecvd[len(dataRecvd)-2]:
            dataRecvd = dataRecvd[:-dataRecvd[-1]]
        #logging("padding removed = " + str(dataRecvd))
        #logging("Data received = " + str(dataRecvd)+ " of type " + str(type(dataRecvd)))
        return dataRecvd
    else:
        message = client.recv(BUFFER_SIZE)
        return message
        

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
                content = rfile.read(BLOCK_SIZE)
                #logging("CONTENT: " + str(content) + " of type " + str(type(content)))
                if not content:
                    #logging("not sending content")
                    sendEncrypted(client, content)
                    break
                #logging("Sending content")
                sendEncrypted(client, content)
            logging("File successfully read")
        rfile.close()
    except:
        sendEncrypted(client, "Error: File could not be read by server")
        logging("Error: File could not be read by server")
        client.close()
        tb = traceback.format_exc()
        print (tb)
        return

def write(client, filename):
    try:
        with open(filename, 'wb') as wfile:
            #logging("trying to write to " + filename)
            content = recvEncrypted(client)
            while 1:
                #logging("CONTENT: " + str(content))
                #print("GETTING BITS N SHIT " + str(content))
                if not content:
                    #print("BREAK CONTENT LOOP")
                    #logging("file has ended")
                    break
                #logging("Writing content in " + str(type(content)))
                #if ".txt" not in filename:
                #    wfile.write(content)
                #else:
                wfile.write(content)
                content = recvEncrypted(client)

            logging("File successfully written")
        #print("AYYYY BISSHHH")
        wfile.close()
        #client.close()
    except:
        sendEncrypted(client, "Error: File could not be written by server")
        logging("Error: File could not be written by server")
        client.close()
        tb = traceback.format_exc()
        print (tb)
        return


def setCipher(cCipher, key, nonce):
    global IVMsg, SKMsg, CIPHER_FILE
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
            #CIPHER_FILE = Cipher(algorithms.AES(SK[:16], modes.CBC(IV[:16], backend=backend)))

        elif cCipher == 'aes256':
            # Encrypt using aes256
            BLOCK_SIZE = 256
            CIPHER = Cipher(algorithms.AES(SK[:32].encode()), modes.CBC(IV[:16].encode()), backend=backend)
            #CIPHER_FILE = Cipher(algorithms.AES(SK[:32], modes.CBC(IV[:16], backend=backend)))
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
    request = recvEncrypted(client).decode("utf-8").split(";")

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
        sendEncrypted(client, "Error: Invalid Operation")
        logging("Error: Invalid Operation")
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
        
        logging("setting Cipher")
        setCipher(cCipher, KEY, nonce)
        #logging("Block Size = " + str(BLOCK_SIZE))
        sendEncrypted(client, "Server: Cipher and nonce received.")

        logging("handling client")
        clientHandler(client, KEY) 
        # Final Success
        # server → client: final success
        logging("status: Success")

        client.close()

