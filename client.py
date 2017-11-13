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
import binascii

#GLOBAL VARIABLES
BUFFER_SIZE = 4096
BLOCK_SIZE = 128
CIPHER = 0
cipherType = ['aes256','aes128','null']

# https://gist.github.com/crmccreary/5610068
padder = lambda s: s + (BL0CK_SIZE - len(s) % BL0CK_SIZE) * chr(BL0CK_SIZE - len(s) % BL0CK_SIZE) 
unpad = lambda s : s[0:-ord(s[-1])]

def read(serverSocket, filename):
    try:
        with open(filename, 'wb') as wfile:
            print("trying to write to " + filename)
            content = recvEncrypted(serverSocket)
            while 1:
                print("CONTENT: " + str(content))
                #print("GETTING BITS N SHIT " + str(content))
                if not content:
                    print("file has ended")
                    break
                print("Writing content in " + str(type(content)))
                #if ".txt" not in filename:
                #    wfile.write(content)
                #else:
                wfile.write(content)
                content = recvEncrypted(serverSocket)

            print("File successfully written")
        #print("AYYYY BISSHHH")
        wfile.close()
        serverSocket.close()
    except:
        sendEncrypted(serverSocket, "Error: File could not be written by server")
        print("Error: File could not be written by server")
        serverSocket.close()
        tb = traceback.format_exc()
        print (tb)
        return

# To write the file content to the Server the Client must read the file and pass it through the socket encrypted
def write(serverSocket, filename):
    # Open the file and read the correct size and send to the server
    wErrorMsg = "Error: File could not be written by server"
    print("Starting write operation")
    try:
        with open(filename, 'rb') as rfile:
            while 1:
                content = rfile.read(BLOCK_SIZE) #.decode().strip()
                print("CONTENT: " + str(content) + " of type " + str(type(content)))
                print("content length = " + str(len(content)))
                if not content:
                    print("not sending content")
                    #sendEncryptedFile(serverSocket, content)
                    sendEncrypted(serverSocket, content)
                    break
                try:
                    errorCheck = content.decode("utf-8")
                    if errorCheck == wErrorMsg:
                        print(wErrorMsg)
                        rfile.close()
                        serverSocket.close()
                        sys.exit()
                except:
                    pass
                print("Sending content")
                #print("FUKING CONTENT " + str(content))
                sendEncrypted(serverSocket, content)
                #sendEncrypted(serverSocket, "STILL SENDING")
            #sendEncrypted(serverSocket, "") # something to tell the server the file has ended
        rfile.close()
    except:
        tb = traceback.format_exc()
        print (tb)


# FOR CHALLENGE
def authentication(msg, key):
    clientHash = msg + key
    response = hashlib.sha1(clientHash.encode()).hexdigest()
    print("My Answer = " + response)
    return response
    

# SEND MESSAGE TO SERVER
def sendEncrypted(serverSocket, msg):
    print("msg to send type = " + str(type(msg)))
    try:
        byteMsg = msg.encode()
    except:
        byteMsg = msg

    print("new msg to send type = " + str(type(msg)))

    if CIPHER == 0:
        serverSocket.sendall(byteMsg)
    else:
         # https://cryptography.io/en/latest/hazmat/primitives/padding/?highlight=padding
        #old padder = padding.PKCS7(BLOCK_SIZE).padder()
        #old padded_data = padder.update(byteMsg) + padder.finalize()
        #padded_data = pad(byteMsg)
        # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=cbc%20mode
        length = BLOCK_SIZE//8 - (len(byteMsg) % (BLOCK_SIZE//8))
        #if length == BLOCK_SIZE//8:
        #    length = 0
        print("pad length = " + str(length))
        pad = bytes([length])*length
        print("byteMsg = " + str(byteMsg))
        print("pad = " + str(pad))
        byteMsg = byteMsg + pad
        print("padded msg = " + str(byteMsg))
        encryptor = CIPHER.encryptor()
        toSend = encryptor.update(byteMsg) + encryptor.finalize()
        print("encrypted = " + str(toSend))
        serverSocket.sendall(toSend)
        print("Sent")

def recvEncrypted(serverSocket):
    if CIPHER != 0:
        print("cipher not equal to 0")
        message = serverSocket.recv(BUFFER_SIZE)
        print("received msg = " + str(message))
        decryptor = CIPHER.decryptor()
        dataRecvd = decryptor.update(message) + decryptor.finalize()
        #unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        #data = unpadder.update(dataRecvd) + unpadder.finalize()
        #data = unpad(cipher.decrypt(dataRecvd))
        print("decrypted = " + str(dataRecvd))
        dataRecvd = dataRecvd[:-dataRecvd[-1]]
        print("padding removed = " + str(dataRecvd))
        print("Data received = " + str(dataRecvd)+ " of type " + str(type(dataRecvd)))
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
    print("IV = " + str(IV))
    print("SK = " + str(SK))
    global BLOCK_SIZE, CIPHER
    try:
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
            print("Null cipher being used, IV and SK not needed")
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
    print(ack)

    # Get challenge from server 
    serverChallenge = recvEncrypted(serverSocket).decode("utf-8")
    print("Server's Challenge = " + str(serverChallenge))
    # Authenticate key 
    toSend = authentication(serverChallenge, key)
    # Send challenge response to serverSocket
    sendEncrypted(serverSocket, toSend)
    # Get challenge result from server 
    keyResult = recvEncrypted(serverSocket).decode("utf-8")
    if keyResult != "Server: Correct Key":
        print(keyResult)

    # REQUEST ------------------------------------------------------------------------
    # Start sending stuff
    #print("Sending request")
    requestAction = command + ";" + filename
    sendEncrypted(serverSocket, requestAction)

    # Get server response True/False (Server: I can do this action/I cannot do this action)
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
    #print("SUCCESS MOTHAFUCKAAAAAAAAAA WOOOOOOOO")
    print("OK")

if __name__ == "__main__":

    # CHECK ARGS
    if len(sys.argv) == 6:
        command = sys.argv[1]
        filename = sys.argv[2]
        cipher = sys.argv[4]
        key = sys.argv[5]
        #print("Key = " + key)
        
        # CHECK IF HOSTNAME:PORT IS CORRECT
        try:
            HOST = sys.argv[3].split(":")[0]
            prePortCheck = sys.argv[3].split(":")[1] 
            if int(prePortCheck) >= 0 or int(prePortCheck) <= 65535:
                PORT = prePortCheck
            else:
                print("Invalid port number. Must be in range 0 - 65535")
            #print("DEBUG \nHOSTNAME: " + HOST + "\nPORT: " + PORT)
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
