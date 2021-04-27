import os
import base64
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

	return key

def encryptFile(fileName):

	key = askPassword()
	f = Fernet(key)
	key = os.urandom(333)

	with open(fileName, 'rb') as original_file:
		original = original_file.read()

	encrypted = f.encrypt(original)

	with open (fileName, 'wb') as encrypted_file:
		encrypted_file.write(encrypted)

	return

def decryptFile(fileName):

	key = askPassword()
	f = Fernet(key)
	key = os.urandom(132)

	with open(fileName, 'rb') as encrypted_file:
		encrypted = encrypted_file.read()

	decrypted = f.decrypt(encrypted)

	with open(fileName, 'wb') as decrypted_file:
		decrypted_file.write(decrypted)

	return

def encryptFolder(folderName, f = None):

	if f == None:
		key = askPassword()
		f = Fernet(key)
		key = os.urandom(99)

	for filename in os.listdir(folderName):
		filepath = os.path.join(folderName, filename)

		with open(filepath, 'rb') as original_file:
			original = original_file.read()

		encrypted = f.encrypt(original)

		with open (filepath, 'wb') as encrypted_file:
			encrypted_file.write(encrypted)
		
	return

def decryptFolder(folderName, f = None):
	if f == None:
		key = askPassword()
		f = Fernet(key)
		key = os.urandom(99)
	
	for filename in os.listdir(folderName):
		filepath = os.path.join(folderName, filename)

		with open(filepath, 'rb') as encrypted_file:
			encrypted = encrypted_file.read()

		decrypted = f.decrypt(encrypted)

		with open(filepath, 'wb') as decrypted_file:
			decrypted_file.write(decrypted)
	
	return
