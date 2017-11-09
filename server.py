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
BLOCK_SIZE = 0


# Authentication
	# server → client: random challenge
	# client → server: compute and send back a reply that can only be computed if secret key is known
	# server → client: verify the reply, send success/failure message to client
# The key received from the client is encrypted using cipher<x>
def authentication(client, key, nonce):
    # https://codereview.stackexchange.com/questions/47529/creating-a-string-of-random-characters
    message = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))
	sendEncrypted(client, message)
	hashMsg = bytearray(msg + key)
	answer = hashlib.sha1(hashMsg).hexdigest()
	clientAnswer = recvEncrypted(client)

	if answer != clientAnswer : 
		return False
	else:
    	return True


def sendEncrypted(client, msg):
    # https://cryptography.io/en/latest/hazmat/primitives/padding/?highlight=padding
    padder = padding.PKCS7(BLOCK_SIZE).padder()
	padded_data = padder.update(msg) + padder.finalize()
	if CIPHER == 0:
    	client.sendall(msg).encode()
	else:
    	# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=cbc%20mode
		encryptor = CIPHER.encryptor()
		toSend = encrypt.update(padded_data) + encrypt.finalize()
		client.sendall(toSend).encode()


def recvEncrypted(client):
	if CIPHER = 0:
    	clientAns = client.recv(BUFFER_SIZE).decode("utf-8")
	else:
    	clientAns = client.recv(BUFFER_SIZE)
		decryptor = CIPHER.decryptor()
		dataRecvd = decryptor.update(clientAns) + decryptor.finalize()
		unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
		data = unpadder.update(dataRecvd) + decryptor.finalize()
	
	return data

def read(client, filename):

def write(client, filename):

def setCipher(cCipher, key, nonce):
	IVMsg = bytearray(key + nonce + "IV")
	SKMsg = bytearray(key + nonce + "SK")
	backend = default_backend()
	global BLOCK_SIZE, CIPHER
	if cipher == 'aes128':
		# Encrypt using aes128
		BLOCK_SIZE = 128
		IV = hashlib.sha128(IVMsg).hexdigest()
		SK = hashlib.sha128(SKMsg).hexdigest()
		logging("IV = " + IV)
		logging("SK = " + SK)
		CIPHER = Cipher(algorithms.AES(SK), modes.CBC(IV), backend=backend)

	elif cipher == 'aes256':
		# Encrypt using aes256
		BLOCK_SIZE = 256
		IV = hashlib.sha256(IVMsg).hexdigest()
		SK = hashlib.sha256(SKMsg).hexdigest()
		logging("IV = " + IV)
		logging("SK = " + SK)
		CIPHER = Cipher(algorithms.AES(SK), modes.CBC(IV), backend=backend)
	else:
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


def clientHandler(client, cipher, nonce, key):
	
	if not authentication(client, key):
		logging("Error: wrong key")
		sendEncrypted(client, "Server: Incorrect Key Used")
		client.close()
		return
	else:
    	sendEncrypted(client, "Server: Correct Key! Send me your request")

	request = recvEncrypted(client).decode("utf-8").split(";")

	operation = request[0]
	filename = request[1]

	logging("Command: " + operation + " Filename: " + filename)

	if operation == "read":
    	sendEncrypted(client, "Server: Valid Operation")
    	read(client, filename)
	elif operation == "write":
    	sendEncrypted(client, "Server: Valid Operation")
    	write(client, filename)
	else:
    	sendEncrypted(client, "Server: Invalid Operation. I can only read and write.")
    	

	"""
	# Get method + filename
	clientFileRequestEncrypted = client.recv(BUFFER_SIZE).decode("utf-8")
	clientFileRequest = decrypter(cipher, clientFileRequestEncrypted)
	command = clientFileRequest.split(';')[0]
	filename = clientFileRequest.split(';')[1]

	# Check if server can do action
	# Temporarily calling this function doAction, still gotta define it and find out how to do it
	# doAction will return either True or False

	canDo = doAction()
	canDoEncrypt = encrypter(cipher, canDo)
	client.sendall(canDoEncrypt)

	# If canDo was true, should be able to either download from client, or give file to client
	# If canDo was not true, client closes connection
	"""


if __name__ == "__main__":

	# Arg check
	if len(sys.argv) == 3:
		PORT = sys.argv[1]
		KEY = sys.argv[2]
	else:
		print("\nIncorrect number of parameters: ")
		print("Usage: server.py <port> <key>")
		sys.exit()

	print("Listening on port " + str(PORT))
	print("Using secret key: " + str(KEY))

	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	HOST = socket.gethostname
	serverSocket.bind((HOST, PORT))
	serverSocket.listen(5)

	while 1:
		client, addr = serverSocket.accept()
		# First message
		# client → server: cipher, nonce
		cipherNonceMsg = client.recv(BUFFER_SIZE).decode("utf-8").split(";")
		cCipher = cipherNonceMsg[0]
		nonce = cipherNonceMsg[1]

		logging("new connection from " + str(addr[0]) + " cipher = " + cCipher)
		logging("nonce = " + nonce)
		setCipher(cCipher, key, nonce)

		sendEncrypted(client, "Server: Cipher and nonce received.")

		clientHandler(client, key, nonce) 
		# Final Success
		# server → client: final success
		logging("status: SUCCESS")

		client.close()

