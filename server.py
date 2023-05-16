import socket
import random
import string
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import threading


SERVER_IP = '172.20.10.2'
SERVER_PORT = 5678

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
def save_key(key, file_name='Key.key'):
    desktop_path = os.path.expanduser("~/Desktop")
    file_path = os.path.join(desktop_path, file_name)
    with open(file_path, 'wb') as f:
        f.write(key)
        
public_key, private_key = generate_RSA_keys()
#save_RSA_keys(public_key, private_key)


def handle_client(client_socket):
    # Generate RSA key pair
    public_key, private_key = generate_RSA_keys()
    # Send public key to client
    client_socket.send(public_key)

    # Receive message from client
    message = client_socket.recv(1024)
    print("The encrypted AES key:")
    print(message)
    AES_key = decrypt_using_private(private_key,message)
    client_socket.send(AES_key)
    print("The decrypted AES key has been successfully sent")
    client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print("Server is up and running.")

    while True:
        client_socket, address = server_socket.accept()
        print("New connection from:", address)
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()

#with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s:
#    s.bind((SERVER_IP, SERVER_PORT))
#    print('Server is listening')
#    s.listen(1)
#    conn,addr = s.accept()
#    print(f'Connection accepted from :{addr}')
#    with conn:
#        while(True):
#            conn.send(b'Hello World')
#            data =  conn.recv(1024)
#            print(data)
#            break
