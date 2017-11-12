"""
CPSC 526 Assignment #4
Steven Leong 10129668 T01
Josh Quines 10138118 T03
"""

#I'M JUST PUTTING THIS COMMENT HERE TO TEST THE CODEANYWHERE THING SO I CAN DO THIS IN SCHOOL WITHOUT A LAPTOP LOL
#Check #2

import socket
import socketserver
import sys
import threading
import time
import traceback
import select
import string
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import random

#GLOBAL VARIABLES
BUFFER_SIZE = 4096
BLOCK_SIZE = 0
NONCE = None 
CIPHER = 0
HOST = None 
KEY = None 
FILENAME = None
cipherType = ['aes256','aes128','null']


def read(serverSocket):
    f = open(FILENAME, 'r')
    fileData = f.read()
    sendEncrypted(serverSocket, fileData)
    f.close()

def write(serverSocket):
    fileData = recvEncrypted(serverSocket)
    f = open(FILENAME, 'w')
    f.write(fileData)
    f.close()

# FOR CHALLENGE
def authentication(msg):
    clientHash = msg + KEY
    response = hashlib.sha1(clientHash.encode()).hexdigest()
    return response
    

# SEND MESSAGE TO SERVER

def sendEncrypted(serverSocket, msg):
    """
    byteMsg = msg.encode("utf-8")
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(byteMsg) + padder.finalize()
    if CIPHER == 0:
        serverSocket.sendall(msg).encode()
    else:
        encrypt = CIPHER.encryptor()
        toSend = encrypt.update(byteMsg) + encrypt.finalize()
        serverSocket.sendall(toSend).encode()
    """
    byteMsg = msg.encode("utf -8")
    # https://cryptography.io/en/latest/hazmat/primitives/padding/?highlight=padding
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(byteMsg) + padder.finalize()
    if CIPHER == 0:
        serverSocket.sendall(byteMsg)
    else:
        # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=cbc%20mode
        encryptor = CIPHER.encryptor()
        toSend = encryptor.update(padded_data) + encryptor.finalize()
        serverSocket.sendall(toSend)

def recvEncrypted(serverSocket):
    """
    if CIPHER == 0:
        msg = serverSocket.recv(BLOCK_SIZE).decode('utf-8')
        return msg
    else:
        msg = serverSocket.recv(BLOCK_SIZE).decode()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        data = unpadder.update(msg)
        encryptedMsg = data + unpadder.finalize()
        decrypt = CIPHER.decryptor()
        msg = decryptor.update(encryptedMsg) + decryptor.finalize()
        return msg
    """
    if CIPHER == 0:
        challenge = serverSocket.recv(BUFFER_SIZE).decode("utf-8")
        return challenge
    else:
        challenge = serverSocket.recv(BUFFER_SIZE)
        decryptor = CIPHER.decryptor()
        dataRecvd = decryptor.update(challenge) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        data = unpadder.update(dataRecvd) + unpadder.finalize()
        return data

def setCipher(cCipher, key, nonce):
    IVMsg = key + nonce + "IV"
    SKMsg = key + nonce + "SK"
    backend = default_backend()
    IV = hashlib.sha256(IVMsg.encode()).hexdigest()
    SK = hashlib.sha256(SKMsg.encode()).hexdigest()
    print("IV = " + str(IV))
    print("SK = " + str(SK))
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
        print("Null cipher being used, IV and SK not needed")





# COMMAND, SEND KEY, FILENAME, CIPHER TO SERVER
def serverConnect(command, filename, hostname, port, cipher, key):

    # Connect to server
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    x = hostname, int(port)
    serverSocket.connect(x)
   
    global NONCE
    NONCE = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    print("nonce = " + NONCE)
    # FIRST MESSAGE -----------------------------------------------------------------
    # Send to server for authentication. Only send CIPHER and NONCE
    setCipher(cipher, key, NONCE)
    initMessage = CIPHER + ';' + NONCE
    serverSocket.sendall(initMessage.encode("utf-8"))

    # Get challenge from server 
    serverChallenge = recvEncrypted(serverSocket)
    # Authenticate key 
    toSend = authentication(serverChallenge)
    # Send challenge response to serverSocket
    sendEncrypted(serverSocket, toSend)
    # Get challenge result from server 
    keyResult = recvEncrypted(serverSocket)
    # Key check
    if keyResult == "Incorrect Key Used":
        print("Wrong key used.\nTerminating connection")
        serverSocket.close()
        sys.close()
    else:
        print("Key used was valid")

    # REQUEST ------------------------------------------------------------------------
    # Start sending stuff
    requestAction = COMMAND + ";" + FILENAME
    sendEncrypted(serverSocket, requestAction)

    # Get server response True/False (Server: I can do this action/I cannot do this action)
    serverResponse = recvEncrypted(serverSocket)

    # DATA EXCHANGE ------------------------------------------------------------------
    if serverResponse == "Server: Valid Operation":
        # Start doing stuff with filename aka upload the file to the server
        if COMMAND == 'read':
            read(serverSocket)
        elif COMMAND == 'write':
            write(serverSocket)
    else:
        print("Server unable to do operation")
        sys.close()

    # FINAL RESULT -------------------------------------------------------------------
    print("SUCCESS MOTHAFUCKAAAAAAAAAA WOOOOOOOO")
                  




    


if __name__ == "__main__":

    # CHECK ARGS
    if len(sys.argv) == 6:
        COMMAND = sys.argv[1]
        FILENAME = sys.argv[2]
        CIPHER = sys.argv[4]
        KEY = sys.argv[5]
        
        # CHECK IF HOSTNAME:PORT IS CORRECT
        try:
            HOST = sys.argv[3].split(":")[0]
            prePortCheck = sys.argv[3].split(":")[1] 
            if int(prePortCheck) >= 0 or int(prePortCheck) <= 65535:
                PORT = prePortCheck
            else:
                print("Invalid port number. Must be in range 0 - 65535")
            print("DEBUG \nHOSTNAME: " + HOST + "\nPORT: " + PORT)
        except:
            print("Incorrect hosname:port syntax")
            sys.exit()

        # CHECK IF CIPHERTYPE IS VALID
        if CIPHER not in cipherType:
            print("Cipher not available. Please use aes256, aes128 or null")
            sys.exit()

        # CHECK IF FILENAME EXISTS
        fileCheck = os.path.isfile(FILENAME)
        if fileCheck == False:
            print("File: \'" + str(FILENAME) + "\'does not exist")
            sys.exit()

        # START
        serverConnect(COMMAND, FILENAME, HOST, PORT, CIPHER, KEY)

    else:
        print("\nIncorrect number of parameters: ")
        print("Usage: client.py command filename hostname:port cipher key")
        sys.exit()