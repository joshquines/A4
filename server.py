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
		
def clientHandler(client, dstSocket):
	
	""" THIS WILL HAVE THE CRYPTO STUFF, INPUTS WILL BE DIFFERENT *********************************************************"""
	inputs = [client, dstSocket]

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

	""" THE ARGUMENT CHECKS WILL BE DIFFERENT HERE *********************************************************"""
	"""# Parse arguments
	if len(sys.argv) < 4 or len(sys.argv) == 6 or len(sys.argv) > 8 : 	# Minimum number of arguments is 3, maximum is 7
																		#Impossible to have ./A2.py + 5 arguments
		print("\nIncorrect number of parameters: ")
		print("Usage: ./A3.py [logOptions] [replaceOptions] srcPort server dstPort")
		print("[logOptions] and [replaceOptions] are optional parameters")
		print("[replaceOptions] takes in 2 parameters\n")
		sys.exit(0)
	elif len(sys.argv) == 5: #logOptions is always first arg
		if sys.argv[1] in LOG_OPTIONS:
			LOG_FLAG = True
			LOG_COMMAND = sys.argv[1]
		elif sys.argv[1].startswith("-auto"):
			LOG_FLAG = True
			AUTONUM = int(sys.argv[1][5:])
			LOG_COMMAND = "-autoN"
		else: #user wrote something over than a logOption
			print("\nIncorrect Usage of Logging Program: ")
			print("Usage: ./A3.py [logOptions] [replaceOptions] srcPort server dstPort")
			print("[logOptions] and [replaceOptions] are optional parameters")
			print("[replaceOptions] takes in 2 parameters\n")
			sys.exit(0)
	else: # More than 4 arguments, logoPtion is always first arg
		if sys.argv[1] in LOG_OPTIONS:
			LOG_FLAG = True
			LOG_COMMAND = sys.argv[1]
		elif sys.argv[1].startswith("-auto"):
			LOG_FLAG = True
			AUTONUM = int(sys.argv[1][5:])
			LOG_COMMAND = "-autoN"

	HOST = "localhost"
	DST_PORT = int(sys.argv[len(sys.argv) - 1])
	SERVER = sys.argv[len(sys.argv) - 2]
	SRC_PORT = int(sys.argv[len(sys.argv) - 3])

	if '-replace' in sys.argv: # if -replace is an argument
		REPLACE_FLAG = True
		replaceIndex = sys.argv.index('-replace')
		ORIGINAL_T = sys.argv[replaceIndex + 1]
		REPLACE_T = sys.argv[replaceIndex + 2]
		if ORIGINAL_T == str(SRC_PORT) or REPLACE_T == str(SRC_PORT):
			print("\nIncorrect Usage of -replace  ")
			print("Usage: ./A3.py [logOptions] [replaceOptions] srcPort server dstPort")
			print("[logOptions] and [replaceOptions] are optional parameters")
			print("[replaceOptions] takes in 2 parameters\n")
			sys.exit(0)
	
	#print(ORIGINAL_T,REPLACE_T)

	print("Port logger running: srcPort=" + str(SRC_PORT) + " host=" + SERVER + " dstPort=" + str(DST_PORT))
	#print("Log command = " + LOG_COMMAND)
	"""

	# Create socket to accept clients
	sourceSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sourceSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sourceSocket.bind((HOST, SRC_PORT))
	sourceSocket.listen(5)

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
