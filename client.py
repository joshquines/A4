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

"""
encrypter and decrypter can also be used in the server
"""

# TAKEN FROM 
# https://dzone.com/articles/interoperable-aes256-encryption-between-cryptojs-p
# TODO: Implement this into our encrypter and decrypter functions
# KEY is obvs the key
# IV I think the nonce  

"""
import binascii
from Crypto.Cipher import AES
KEY = 'This is a key123'
IV = 'This is an IV456'
MODE = AES.MODE_CFB
BLOCK_SIZE = 16
SEGMENT_SIZE = 128
def encrypt(key, iv, plaintext):
    aes = AES.new(key, MODE, iv, segment_size=SEGMENT_SIZE)
    plaintext = _pad_string(plaintext)
    encrypted_text = aes.encrypt(plaintext)
    return binascii.b2a_hex(encrypted_text).rstrip()
def decrypt(key, iv, encrypted_text):
    aes = AES.new(key, MODE, iv, segment_size=SEGMENT_SIZE)
    encrypted_text_bytes = binascii.a2b_hex(encrypted_text)
    decrypted_text = aes.decrypt(encrypted_text_bytes)
    decrypted_text = _unpad_string(decrypted_text)
    return decrypted_text
def _pad_string(value):
    length = len(value)
    pad_size = BLOCK_SIZE - (length % BLOCK_SIZE)
    return value.ljust(length + pad_size, '\x00')
def _unpad_string(value):
    while value[-1] == '\x00':
        value = value[:-1]
    return value
if __name__ == '__main__':
    input_plaintext = 'The answer is no'
    encrypted_text = encrypt(KEY, IV, input_plaintext)
    decrypted_text = decrypt(KEY, IV, encrypted_text)
    assert decrypted_text == input_plaintext
"""


# Use this to send msg to server
def encrypter(cipher, msg, NONCE):
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

# Use this to receive msg from server
def decrypter(cipher, msg, NONCE):
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
	serverSocket.sendall(initMessage).encode()

	# Get server response
	initMessage = serverSocket.recv(BUFFER_SIZE) # eg. Cipher method is: x ****This is encrypted
	initMessageDecrypted = decrypter(cipher, initMessage)

	# AUTHENTICATION -----------------------------------------------------------------
	# Send key (encrypted)
	toServer = encrypter(CIPHER, KEY)
	serverSocket.sendall(toServer).encode()

	# Receive response
	fromServer = serverSocket.recv(BUFFER_SIZE)
	serverResponse = decrypter(CIPHER, fromServer)

	# AUTHENTICATION RESULT
	if serverResponse == False:
		print("Invalid key. Termination connection")
		sys.close()
	else:
		print("Key is valid")

	# REQUEST ------------------------------------------------------------------------
	# Start sending stuff
	requestAction = COMMAND + ";" + FILENAME
	serverSocket.send(requestAction).encode()

	# Get server response True/False (Server: I can do this action/I cannot do this action)
	serverResponse = serverSocket.recv(BUFFER_SIZE)

	# DATA EXCHANGE ------------------------------------------------------------------
	if serverResponse == True:
		# Start doing stuff with filename aka upload the file to the server
		pass
	else:
		print("Server unable to do operation")
		sys.close()

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

		# START
		serverConnect(COMMAND, FILENAME, HOST, PORT, CIPHER, KEY)

	else:
		print("\nIncorrect number of parameters: ")
		print("Usage: client.py command filename hostname:port cipher key")
		sys.exit()