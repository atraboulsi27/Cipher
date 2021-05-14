import sys
import os
from encryption import *

filename = ""
for i in range(len(sys.argv)-1):
	filename = filename + " " + sys.argv[i+1]
filename = filename[1:]

if __name__ == "__main__":
	print("Decrypting File ...")
	decryptFile(filename)
