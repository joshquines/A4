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
OUTGOING = "---->"
INCOMING = "<----"
SRC_PORT = 0
HOST = ''
DST_PORT = 0

def read(filename):

def write(filename):

def cipher(cipherType, key):


		
def clientHandler(client, dstSocket):
	
	""" THIS WILL HAVE THE CRYPTO STUFF, INPUTS WILL BE DIFFERENT *********************************************************"""
	inputs = [client, dstSocket] #maybe this takes in the args?

	# GET ARGS FROM CLIENT
	# COMMAND -> DETERMINES IF CALLS READ R WRITE
	# CIPHER -> CALLS FUNCTION CIPHER AND PASSES THE TYPE OF CIPHER
	# KEY -> DO CRYPTO SHIT, PROBABLY GETS PASSED INTO THE CIPHER FUNCTION TOO  

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
		print("Usage: server.py port key")




	""" THIS CAN PROBABLY STAY THE SAME *********************************************************"""
	while 1:
		client, addr = sourceSocket.accept()
		# get local time
		timeNow = time.strftime("%a %b %d %H:%M:%S")
		print("New Connection: " + timeNow + ", from " + str(addr[0]))

		# Create  socket that will forward data
		dstSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		dstSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		# Connect to destination server
		dstSocket.connect((SERVER, DST_PORT))

		# Start a thread that will handle data between the sockets
		threading.Thread(target=clientHandler, args=(client, dstSocket)).start()
