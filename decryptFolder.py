import sys
import os
from encryption import *

filename = ""
for i in range(len(sys.argv)-1):
	filename = filename + " " + sys.argv[i+1]
filename = filename[1:]

decryptFolder(filename)