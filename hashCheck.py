import hashlib
import sys
import os

fileName = sys.argv[1]
cwd = os.getcwd()
fClient = cwd + "/" +fileName
fServer = cwd + "/serverFolder/" + fileName
md5Client = hashlib.md5(open(fClient, 'rb').read()).hexdigest()
md5Server = hashlib.md5(open(fServer, 'rb').read()).hexdigest()
if md5Client == md5Server:
	result = "The files are the same"
else:
	result = "The files are different"

print("CLIENT MD5: " + md5Client + "\nSERVER MD5: " + md5Server + "\nRESULT: " + str(result))
