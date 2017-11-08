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
import cryptography

#GLOBAL VARIABLES
BUFFER_SIZE = 4096

def read(filename):

def write(filename):

def cipher(cipherType, key):

def logging(msg):
    # get local time
    print(time.strftime("%a %b %d %H:%M:%S") + ": " + msg)
		

# Authentication
	# server → client: random challenge
	# client → server: compute and send back a reply that can only be computed if secret key is known
	# server → client: verify the reply, send success/failure message to client

# Request
	# client → server: operation, filename
	# server → client: response indicating whether operation can proceed

# Data Exchange
	# client → server: data chunk
	# server → client: data chunk
	# In case of any errors, the server should indicate so to the client and then disconnect.
		# server → client: optional error message


def clientHandler(client, cipher, nonce, key):
	
	""" THIS WILL HAVE THE CRYPTO STUFF, INPUTS WILL BE DIFFERENT *********************************************************"""




	# CHECK IF CLIENT KEY = SERVER KEY. IT'S LIKE A PASSWORD THING GOING ON
	#if clientKey == KEY:
	#	do stuff 
	#else:
	#	close client

	# GET ARGS FROM CLIENT
	# COMMAND -> DETERMINES IF CALLS READ R WRITE
	# CIPHER -> CALLS FUNCTION CIPHER AND PASSES THE TYPE OF CIPHER
	# KEY -> DO CRYPTO SHIT, PROBABLY GETS PASSED INTO THE CIPHER FUNCTION TOO  

	# OR CIPHER GETS CALLED INSIDE READ/WRITE

	if COMMAND == read:
		read(filename)
	elif COMMAND == write:
		write(filename)





	""" THIS WHILE LOOP MAY NOT BE NEEDED *********************************************************"""
	while 1:
		readable, writeable, exceptional = select.select(inputs, [], [])
		for sock in readable:
			data = sock.recv(1024)
			logData = data
			# If no data, close the current connection socket.
			if not data:
				print("No data provided. Connection closed.")
				client.close()
				dstSocket.close()
				return

			# If socket sending data is the destination socket send the data to the client
			if sock == dstSocket:
				if REPLACE_FLAG == True:
					logData = replacer(data)

				if LOG_FLAG == True:
					logging(logData, INCOMING)

				client.sendall(data)
			# Otherwise send the data from client to the destination
			else:
				if REPLACE_FLAG == True:
					logData = replacer(data)

				if LOG_FLAG == True:
					logging(logData, OUTGOING)

				dstSocket.sendall(data)


if __name__ == "__main__":

	""" Making a new Arg Check"""
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


	""" THIS CAN PROBABLY STAY THE SAME *********************************************************"""
	while 1:
		client, addr = serverSocket.accept()
		# First message
		# client → server: cipher, nonce
		cipherNonceMsg = client.recv(BUFFER_SIZE).decode("utf-8").split(";")
		cipher = cipherNonceMsg[0]
		nonce = cipherNonceMsg[1]

		logging("new connection from " + str(addr[0]) + " cipher = " + cipher)
		logging("nonce = " + nonce)
		clientHandler(client,cipher, nonce, KEY)
		# Final Success
		# server → client: final success
		logging("status: SUCCESS")

		client.close()

