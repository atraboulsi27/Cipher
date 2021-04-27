import os
import sys
import winreg as reg
import ctypes


def setup():

	os.mkdir("MyKeys")
	os.mkdir("OtherKeys")
 
	return

def is_admin():
		try:
			return ctypes.windll.shell32.IsUserAnAdmin()
		except:
			return False

def addToRegistry():

	if is_admin():

		# Code of your program here
		cwd = os.getcwd()

		python_exe = sys.executable

		key_path = r"*\\shell\\Cipher"

		key = reg.CreateKeyEx(reg.HKEY_CLASSES_ROOT, key_path)

		reg.SetValue(key,'', reg.REG_SZ, '&Encrypt with Cipher')

		key1 = reg.CreateKeyEx(key, r'command')

		reg.SetValue(key1,'', reg.REG_SZ, python_exe + f' {cwd}\\print.py %1')

	else:
		# Re-run the program with admin rights
		ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

	return

addToRegistry()