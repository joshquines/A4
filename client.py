"""
CPSC 526 Assignment #4
Steven Leong 10129668 T01
Josh Quines 10138118 T03
"""

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
import binascii

#GLOBAL VARIABLES
BUFFER_SIZE = 1024
BLOCK_SIZE = 128
CIPHER = 0
cipherType = ['aes256','aes128','null']

def read(serverSocket, filename):
    wErrorMsg = "Error: File could not be read by server"
    try:
        # Open a file to write in bytes
        with open(filename, 'wb') as wfile:
            content = recvEncrypted(serverSocket)
            #print("Content = " + str(content))
            # First msg could be error msg
            """
            try:
                errorCheck = content.decode("utf-8")
                if errorCheck == wErrorMsg:
                    print("ERROR")
                    print(errorCheck)
                    rfile.close()
                    serverSocket.close()
                    sys.exit()
            except:
                pass
            """
            while 1:
                if not content:
                    # EOF is indicated by an empty byte string
                    break
                wfile.write(content)
                content = recvEncrypted(serverSocket)
        wfile.close()
    except:
        print("Error: File could not be read by server")
        serverSocket.close()
        tb = traceback.format_exc()
        print (tb)
        return

# To write the file content to the Server the Client must read the file and pass it through the socket encrypted
def write(serverSocket, filename):
    # Open the file and read the correct size and send to the server
    wErrorMsg = "Error: File could not be written by server"
    try:
        with open(filename, 'rb') as rfile:
            while 1:
                content = rfile.read(BLOCK_SIZE)
                if not content:
                    #print("not sending content")
                    sendEncrypted(serverSocket, content)
                    break
                try:
                    errorCheck = content.decode("utf-8")
                    if errorCheck == wErrorMsg:
                        #print(wErrorMsg)
                        rfile.close()
                        serverSocket.close()
                        sys.exit()
                except:
                    pass
                #print("Sending content")
                sendEncrypted(serverSocket, content)
        rfile.close()
    except:
        tb = traceback.format_exc()
        print (tb)


# FOR CHALLENGE
def authentication(msg, key):
    clientHash = msg + key
    response = hashlib.sha1(clientHash.encode()).hexdigest()
    #print("My Answer = " + response)
    return response
    

# SEND MESSAGE TO SERVER
def sendEncrypted(serverSocket, msg):
    # try changing the type of msg to bytes
    try:
        byteMsg = msg.encode()
    except:
        byteMsg = msg

    if CIPHER == 0:
        serverSocket.sendall(byteMsg)
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
        #extraLen = BLOCK_SIZE + length
        #print("pad length = " + str(length))
        pad = bytes([length])*length
        #pad += bytes([extraLen])*BLOCK_SIZE
        #print("byteMsg = " + str(byteMsg))
        #print("pad = " + str(pad))
        byteMsg = byteMsg + pad
        #print("padded msg = " + str(byteMsg))
        #print("padded msg len = " + str(len(byteMsg)))

        encryptor = CIPHER.encryptor()
        toSend = encryptor.update(byteMsg) + encryptor.finalize()
        #print("encrypted = " + str(toSend))
        serverSocket.sendall(toSend)
        #print("Sent")

def recvEncrypted(serverSocket):
    if CIPHER != 0:
        #print("cipher not equal to 0")
        message = serverSocket.recv(BLOCK_SIZE)
        #print("received msg = " + str(message))
        decryptor = CIPHER.decryptor()
        dataRecvd = decryptor.update(message) + decryptor.finalize()
        #print("decrypted = " + str(dataRecvd))
        if  len(dataRecvd) != 0 and dataRecvd[len(dataRecvd)-1] == dataRecvd[len(dataRecvd)-2]:
            dataRecvd = dataRecvd[:-dataRecvd[-1]]
        #print("padding removed = " + str(dataRecvd))
        #print("Data received = " + str(dataRecvd)+ " of type " + str(type(dataRecvd)))
        return dataRecvd
    else:
        message = serverSocket.recv(BUFFER_SIZE)
        return message

def setCipher(cCipher, key, nonce):
    IVMsg = key + nonce + "IV"
    SKMsg = key + nonce + "SK"
    backend = default_backend()
    IV = hashlib.sha256(IVMsg.encode()).hexdigest()
    SK = hashlib.sha256(SKMsg.encode()).hexdigest()
    #print("IV = " + str(IV))
    #print("SK = " + str(SK))
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
            #print("Null cipher being used, IV and SK not needed")
    except:
        tb = traceback.format_exc()
        print (tb)




# COMMAND, SEND KEY, FILENAME, CIPHER TO SERVER
def serverConnect(command, filename, hostname, port, cipher, key):

    # Connect to server
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    x = hostname, int(port)
    serverSocket.connect(x)
   
    global NONCE
    NONCE = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    #print("nonce = " + NONCE)

    # FIRST MESSAGE -----------------------------------------------------------------
    # Send to server for authentication. Only send CIPHER and NONCE
    setCipher(cipher, key, NONCE)
    initMessage = cipher + ';' + NONCE
    serverSocket.sendall(initMessage.encode("utf-8"))

    # Server should response with ack when cipher and nonce are received
    ack = recvEncrypted(serverSocket).decode("utf-8")
    #print(ack)

    # CHALLENGE ---------------------------------------------------------------------
    serverChallenge = recvEncrypted(serverSocket).decode("utf-8")
    #print("Server's Challenge = " + str(serverChallenge))
    # Authenticate key 
    toSend = authentication(serverChallenge, key)
    # Send challenge response to serverSocket
    sendEncrypted(serverSocket, toSend)
    # Get challenge result from server 
    keyResult = recvEncrypted(serverSocket).decode("utf-8")
    # Print error if one occurred
    if keyResult != "Server: Correct Key":
        print(keyResult)

    # REQUEST ------------------------------------------------------------------------
    # Start sending stuff
    requestAction = command + ";" + filename
    sendEncrypted(serverSocket, requestAction)

    # Get server response (Server: Valid/Invalid)
    serverResponse = recvEncrypted(serverSocket).decode("utf-8")

    # DATA EXCHANGE ------------------------------------------------------------------
    #print(serverResponse)
    if serverResponse == "Server: Valid Operation":
        # Start doing stuff with filename aka upload the file to the server
        if command == 'read':
            #print("Starting read")
            read(serverSocket, filename)
        elif command == 'write':
            #print("Starting write")
            write(serverSocket, filename)
    else:
        print(serverResponse)


    # FINAL RESULT -------------------------------------------------------------------
    print("OK")
    sys.exit()

if __name__ == "__main__":

    # CHECK ARGS
    if len(sys.argv) == 6:
        command = sys.argv[1]
        filename = sys.argv[2]
        cipher = sys.argv[4]
        key = sys.argv[5]
        
        # CHECK IF HOSTNAME:PORT IS CORRECT
        try:
            HOST = sys.argv[3].split(":")[0]
            prePortCheck = sys.argv[3].split(":")[1] 
            if int(prePortCheck) >= 0 or int(prePortCheck) <= 65535:
                PORT = prePortCheck
            else:
                print("Invalid port number. Must be in range 0 - 65535")
        except:
            print("Incorrect hosname:port syntax")
            sys.exit()

        # CHECK IF CIPHERTYPE IS VALID
        if cipher not in cipherType:
            print("Cipher not available. Please use aes256, aes128 or null")
            sys.exit()

        # CHECK IF FILENAME EXISTS
        if command == 'write':
            fileCheck = os.path.isfile(filename)
            if fileCheck == False:
                print("File: \'" + str(filename) + "\'does not exist")
                sys.exit()

        # START
        serverConnect(command, filename, HOST, PORT, cipher, key)

    else:
        print("\nIncorrect number of parameters: ")
        print("Usage: client.py command filename hostname:port cipher key")
        sys.exit()
