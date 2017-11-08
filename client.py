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

if __name__ == "__main__":

	# CHECK ARGS
	if len(sys.argv) == 6:
		COMMAND = sys.argv[1]
		FILENAME = sys.argv[2]
		CIPHER = sys.argv[4]
		KEY = sys.argv[5]
		try:
			HOSTNAME = sys.argv[3].split(":")[0]
			PORT = sys.argv[3].split(":")[1] 
			print("DEBUG \nHOSTNAME: " + HOSTNAME + "\nPORT: " + PORT)
		except:
			print("Incorrect hosname:port syntax")
	else:
		print("\nIncorrect number of parameters: ")
		print("Usage: client.py command filename hostname:port cipher key")