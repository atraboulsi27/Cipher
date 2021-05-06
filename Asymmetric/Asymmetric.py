from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Creates public and private key pair
def create_and_store(password,pair_name):
    private_name=""+"private_"+pair_name+".pem"
    public_name=""+"public_"+pair_name+".pem"
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
    public_key = private_key.public_key()
    password=bytes(password.encode())
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password))
    with open(private_name, 'wb') as f:
        f.write(pem)
    pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(public_name, 'wb') as f:
        f.write(pem)



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


def envelope_encryption(public_key, filename, envelope_name):
    random_key = Fernet.generate_key()
    encrypted_key = public_key_encrypt(public_key,random_key)
    with open(envelope_name, 'wb') as f:
        f.write(encrypted_key)
    f = Fernet(random_key)
    with open(filename, 'rb') as original_file:
	    original = original_file.read()
    encrypted = f.encrypt(original)
    with open (filename, 'wb') as encrypted_file:
	    encrypted_file.write(encrypted)


def envelope_decryption(private_key, filename, envelope_name):
    with open(envelope_name, 'rb') as envelope_file:
	    encrypted_key = envelope_file.read()
    decrypted_key = private_key_decrypt(private_key,encrypted_key)
    f = Fernet(decrypted_key)
    with open(filename, 'rb') as encrypted_file:
	    encrypted = encrypted_file.read()
    decrypted = f.decrypt(encrypted)
    with open(filename, 'wb') as decrypted_file:
	    decrypted_file.write(decrypted)
