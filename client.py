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

#GLOBAL VARIABLES
BUFFER_SIZE = 4096
NONCE = None 
CIPHER = None 
HOSTNAME = None 
KEY = None 
FILENAME = None


def read(FILENAME):

def write(FILENAME):





# COMMAND, SEND KEY, FILENAME, CIPHER TO SERVER
def serverCOnnect(command, filename, hostname, port, cipher, key):

	# Connect to server
	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverSocket.connect(hostname, port)

	# Send to server for authentication
	authCheck = CIPHER + '\t' + NONCE
	serverSocket.send(authCheck.encode())

	# Get server response
	authResult = serverSocket.recv().decode()
	if authResult == False:
		print("Server denied this connection. Closing.")
		serverSocket.close()
	
	# I think this is where we send data?
	# Not 100% sure here
	serverSocket.send(command, filename)

	


if __name__ == "__main__":

	# CHECK ARGS
	if len(sys.argv) == 6:
		COMMAND = sys.argv[1]
		FILENAME = sys.argv[2]
		CIPHER = sys.argv[4]
		KEY = sys.argv[5]
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
	else:
		print("\nIncorrect number of parameters: ")
		print("Usage: client.py command filename hostname:port cipher key")