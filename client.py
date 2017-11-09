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

#GLOBAL VARIABLES
BUFFER_SIZE = 4096
NONCE = None 
CIPHER = None 
HOSTNAME = None 
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
	clientHash = bytearray(msg + KEY) 
	m = hashlib.sha1()
	m.update(clientHash)
	response = m.digest()
	return response
	

# SEND MESSAGE TO SERVER
padder = padding.PKCS7(BLOCK_SIZE).padder()
padded_data = padder.update(msg) + padder.finalize()
def sendEncrypted(serverSocket, msg):
	if CIPHER == 0:
		serverSocket.sendall(msg).encode()
	else:
		encrypt = CIPHER.encryptor()
		toSend = encrypt.update(msg) + encrypt.finalize()
		serverSocket.sendall(toSend).encode()

def recvEncrypted(serverSocket):
	msg = serverSocket.recv().decode('utf-8')
	if CIPHER == 0:
		return msg 
	else:
	    unpadder = padding.PKCS7(128).unpadder()
		data = unpadder.update(msg)
		encryptedMsg = data + unpadder.finalize()
		decrypt = CIPHER.decryptor()
		msg = decryptor.update(encryptedMsg) + decryptor.finalize()
		return msg

def setCipher(cCipher, key, nonce):
	IVMsg = bytearray(key + nonce + "IV")
	SKMsg = bytearray(key + nonce + "SK")
	backend = default_backend()

	if cipher == 'aes128':
		# Encrypt using aes128
		IV = hashlib.sha128(IVMsg).hexdigest()
		SK = hashlib.sha128(SKMsg).hexdigest()
		CIPHER = Cipher(algorithms.AES(SK), modes.CBC(IV), backend=backend)

	elif cipher == 'aes256':
		# Encrypt using aes256
		IV = hashlib.sha256(IVMsg).hexdigest()
		SK = hashlib.sha256(SKMsg).hexdigest()
		CIPHER = Cipher(algorithms.AES(SK), modes.CBC(IV), backend=backend)





# COMMAND, SEND KEY, FILENAME, CIPHER TO SERVER
def serverCOnnect(command, filename, hostname, port, cipher, key):

	# Connect to server
	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverSocket.connect(hostname, port)

	# FIRST MESSAGE -----------------------------------------------------------------
	# Send to server for authentication. Only send CIPHER and NONCE
	initMessage = CIPHER + ';' + NONCE
	serverSocket.sendall(initMessage).encode()

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
	if serverResponse == True:
		# Start doing stuff with filename aka upload the file to the server
		if COMMAND == 'read'
			read(serverSocket):
		elif COMMAND == 'write':
			write(serverSocket
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
			HOSTNAME = sys.argv[3].split(":")[0]
			prePortCheck = sys.argv[3].split(":")[1] 
			if int(prePortCheck) >= 0 or int(prePortCheck) =< 65535:
				PORT = prePortCheck
			else:
				print("Invalid port number. Must be in range 0 - 65535")
			print("DEBUG \nHOSTNAME: " + HOSTNAME + "\nPORT: " + PORT)
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