import socket
import threading
import sys
from cryptography.fernet import Fernet

# Generate a key for encryption/decryption
# Note: For production, save this key securely
key = Fernet.generate_key()
cipher = Fernet(key)

HOST = str('127.0.0.1')
PORT = int(5500)

if PORT < 0 or PORT > 65535 or not isinstance(PORT, int):
    print("Port number must be between 0 and 65535")
    exit()

client = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
client.connect((HOST, PORT))

def receive():
    while True:
        try:
            encryptedMessage = client.recv(1024)
            if  encryptedMessage:
                  # Decrypt message
                decryptedMessage = cipher.decrypt(encryptedMessage).decode('utf-8')
                print(decryptedMessage)
            print(encryptedMessage)
        except:
            print("An error occurred!")
            client.close()
            break

def send():
    username = input("Enter your username: ")
    client.send(cipher.encrypt(username.encode('utf-8')))
    while True:
        message = input('')
        encryptedMessage = cipher.encrypt(message.encode('utf-8'))
        client.send(encryptedMessage)



receive_thread = threading.Thread(target=receive)
receive_thread.start()

send_thread = threading.Thread(target=send)
send_thread.start()