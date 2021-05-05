import os
import sys
import winreg as reg
import ctypes
import base64
from auxFunctions import *


def setup():

	os.mkdir("MyKeys")
	os.mkdir("OtherKeys")
 
	return

def addToRegistry():

	if is_admin():

		# Code of your program here
		cwd = os.getcwd()

		python_exe = sys.executable

		#add to file Context Menu
		key_path = r"*\\shell\\CipherE"
		key = reg.CreateKeyEx(reg.HKEY_CLASSES_ROOT, key_path)
		reg.SetValue(key,'', reg.REG_SZ, '&Encrypt with Cipher')
		key1 = reg.CreateKeyEx(key, r'command')
		reg.SetValue(key1,'', reg.REG_SZ, python_exe + f' {cwd}\\encryptFile.py %1')
		
		key_path = r"*\\shell\\CipherD"
		key = reg.CreateKeyEx(reg.HKEY_CLASSES_ROOT, key_path)
		reg.SetValue(key,'', reg.REG_SZ, '&Decrypt with Cipher')
		key1 = reg.CreateKeyEx(key, r'command')
		reg.SetValue(key1,'', reg.REG_SZ, python_exe + f' {cwd}\\decryptFile.py %1')
		
		#add to folder Context Menu
		key_path = r"Directory\\shell\\CipherE"
		key = reg.CreateKeyEx(reg.HKEY_CLASSES_ROOT, key_path)
		reg.SetValue(key,'', reg.REG_SZ, '&Encrypt with Cipher')
		key1 = reg.CreateKeyEx(key, r'command')
		reg.SetValue(key1,'', reg.REG_SZ, python_exe + f' {cwd}\\encryptFolder.py %1')

		key_path = r"Directory\\shell\\CipherD"
		key = reg.CreateKeyEx(reg.HKEY_CLASSES_ROOT, key_path)
		reg.SetValue(key,'', reg.REG_SZ, '&Decrypt with Cipher')
		key1 = reg.CreateKeyEx(key, r'command')
		reg.SetValue(key1,'', reg.REG_SZ, python_exe + f' {cwd}\\decryptFolder.py %1')

	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

	return