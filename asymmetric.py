from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Creates public and private key pair
def create_and_store(password,pair_name,directory):
    private_name=""+"private_"+pair_name+".pem"
    public_name=""+"public_"+pair_name+".pem"
    private_destination=os.path.join(directory, private_name)
    public_destination=os.path.join(directory, public_name)
    if (os.path.isfile(private_destination) or os.path.isfile(public_destination)):
        return "Failed to create Pair, Files with the same name already exist in destination directory"
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
    public_key = private_key.public_key()
    password=bytes(password.encode())
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password))
    with open(private_destination, 'wb') as f:
        f.write(pem)
    pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(public_destination, 'wb') as f:
        f.write(pem)
    return "Success"



#reads public key from public key file
def read_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend())
    return public_key


#read private key from private key file
def read_private_key(password,filename):
    password=bytes(password.encode())
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key


#function to encrypt using public key
def public_key_encrypt(key,message):
    encrypted = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

#function to decrypt using private key
def private_key_decrypt(key,encrypted_message):
    private_key=key
    encrypted=encrypted_message
    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message


def envelope_encryption(public_key_file, filename, envelope_name, directory,encrypted_filename):
    random_key = Fernet.generate_key()
    try:
        public_key=read_public_key(public_key_file)
    except:
        return "Failed to read public key"
    try:
        encrypted_key = public_key_encrypt(public_key,random_key)
    except:
        return "Failed to encrypt random key"
    envelope_destination=os.path.join(directory, envelope_name)
    if (os.path.isfile(envelope_destination)):
        return "Envelope name already exists in destination directory, enter another name"
    encrypted_file_destination=os.path.join(directory, encrypted_filename)
    if (os.path.isfile(encrypted_file_destination)):
        return "File name already exists in destination directory, enter another desired encrypted file name"
    try:
        with open(envelope_destination, 'wb') as f:
            f.write(encrypted_key)
    except:
         return "Failed to write Envelope"
    f = Fernet(random_key)
    try:
        with open(filename, 'rb') as original_file:
	        original = original_file.read()
    except:
        return "Failed to read the file " + filename
    try:
        encrypted = f.encrypt(original)
    except:
        return "Failed to encrypt the file " + filename
    try:
        with open (encrypted_file_destination, 'wb') as encrypted_file:
	        encrypted_file.write(encrypted)
    except:
        return "Failed to write encrypted file to " + encrypted_file_destination
    return "Success"


def envelope_decryption(private_key_file, password, filename, envelope_name,directory,decrypted_filename):
    try:
        private_key=read_private_key(password,private_key_file)
    except:
        return "Failed to read private Key, Password Incorrect or File Invalid"
    encrypted_destination=os.path.join(directory, decrypted_filename)
    try:
        with open(envelope_name, 'rb') as envelope_file:
	        encrypted_key = envelope_file.read()
    except:
        return "Failed to read Envelope"
    try:
        decrypted_key = private_key_decrypt(private_key,encrypted_key)
    except:
        return "Failed to decrypt Key"
    f = Fernet(decrypted_key)
    try:
        with open(filename, 'rb') as encrypted_file:
	        encrypted = encrypted_file.read()
    except:
        return "Failed to read encrypted file"
    try:
        decrypted = f.decrypt(encrypted)
    except:
        return "Failed to decrypt file " + filename
    try:
        with open(encrypted_destination, 'wb') as decrypted_file:
	        decrypted_file.write(decrypted)
    except:
        return "Failed to write decrypted file " + decrypted_filename
    return "Success"


