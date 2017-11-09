"""
CPSC 526 Assignment #4
Steven Leong 10129668 T01
Josh Quines 10138118 T03
"""

#I'M JUST PUTTING THIS COMMENT HERE TO TEST THE CODEANYWHERE THING SO I CAN DO THIS IN SCHOOL WITHOUT A LAPTOP LOL

import socket
import socketserver
import sys
import threading
import time
import traceback
import select
import string

#GLOBAL VARIABLES
BUFFER_SIZE = 4096
NONCE = None 
CIPHER = None 
HOSTNAME = None 
KEY = None 
FILENAME = None
cipherType = ['aes256','aes128','null']


def read(FILENAME):

def write(FILENAME):

def sendMessage(cipher, msg):
	if cipher == 'aes128':
		# Encrypt using aes128
		toSend = resultOfEncryption
		pass
	elif cipher == 'aes256':
		# Encrypt using aes256
		toSend = resultOfEncryption
		pass
	elif cipher == 'null':
		# Just send msg
		toSend = msg
		pass
	return toSend

def recvMessage(cipher,msg):
	if cipher == 'aes128':
		# Decrypt using aes128
		toReceive = resultOfEncryption
		pass
	elif cipher == 'aes256':
		# Decrypt using aes256
		toReceive = resultOfEncryption
		pass
	elif cipher == 'null':
		# Dest send msg
		toReceive = msg
		pass
	return toReceive




# COMMAND, SEND KEY, FILENAME, CIPHER TO SERVER
def serverCOnnect(command, filename, hostname, port, cipher, key):

	# Connect to server
	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverSocket.connect(hostname, port)

	# FIRST MESSAGE -----------------------------------------------------------------
	# Send to server for authentication. Only send CIPHER and NONCE
	initMessage = CIPHER + ';' + NONCE
	serverSocket.sendall(initMessage)

	# Get server response
	initMessage = serverSocket.recv()

	# AUTHENTICATION -----------------------------------------------------------------
	# Send key (encrypted)
	toServer = sendMessage(CIPHER, KEY)
	serverSocket.sendall(toServer)

	# Receive response
	fromServer = serverSocket.recv()
	serverResponse = recvMessage(CIPHER, fromServer)

	# AUTHENTICATION RESULT
	if serverResponse == False:
		print("Invalid key. Termination connection")
		sys.close()
	else:
		print("Key is valid")

	# REQUEST ------------------------------------------------------------------------
	# Start sending stuff
	requestAction = COMMAND + ";" + FILENAME
	serverSocket.send(requestAction)

	# Get server response (Server: I can do this action/I cannot do this action)
	serverResponse = serverSocket.recv()

	# DATA EXCHANGE ------------------------------------------------------------------
	if serverResponse == True:
		# Start doing stuff with filename aka upload the file to the server
		pass
	else:
		print("Server unable to do operation")

	# FINAL RESULT -------------------------------------------------------------------




	


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

	else:
		print("\nIncorrect number of parameters: ")
		print("Usage: client.py command filename hostname:port cipher key")
		sys.exit()