import os
import base64
from auxFunctions import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def askPassword():
	password = "my great password" #u need to get password from gui

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt = password.encode(),
		iterations=100000,
	)
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

	password = os.urandom(132)

	return key

def encryptFile(fileName):

	if is_admin():

		key = askPassword()
		f = Fernet(key)
		key = os.urandom(333)

		with open(fileName, 'rb') as original_file:
			original = original_file.read()

		encrypted = f.encrypt(original)

		with open (fileName, 'wb') as encrypted_file:
			encrypted_file.write(encrypted)
	
	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
		
	return

def decryptFile(fileName):

	if is_admin():

		key = askPassword()
		f = Fernet(key)
		key = os.urandom(132)

		with open(fileName, 'rb') as encrypted_file:
			encrypted = encrypted_file.read()

		decrypted = f.decrypt(encrypted)

		with open(fileName, 'wb') as decrypted_file:
			decrypted_file.write(decrypted)
	
	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
		
	return


def encryptFolder(folderName, f = None):

	if is_admin():
		
		if f == None:
			key = askPassword()
			f = Fernet(key)
			key = os.urandom(99)
		
		for filename in os.listdir(folderName):

			filepath = os.path.join(folderName, filename)

			if os.path.isdir(filepath):
				encryptFolder(filepath, f)
			else:
				with open(filepath, 'rb') as original_file:
					original = original_file.read()

				encrypted = f.encrypt(original)

				with open (filepath, 'wb') as encrypted_file:
					encrypted_file.write(encrypted)
	
	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
		
	return

def decryptFolder(folderName, f = None):

	if is_admin():

		if f == None:
			key = askPassword()
			f = Fernet(key)
			key = os.urandom(99)
		
		for filename in os.listdir(folderName):

			filepath = os.path.join(folderName, filename)

			if os.path.isdir(filepath):
				decryptFolder(filepath, f)
			else:
				with open(filepath, 'rb') as encrypted_file:
					encrypted = encrypted_file.read()

				decrypted = f.decrypt(encrypted)

				with open(filepath, 'wb') as decrypted_file:
					decrypted_file.write(decrypted)
	
	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
		
	return
