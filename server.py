import socket
import threading
from cryptography.fernet import Fernet

# Same key as the client (shared securely in production)
key = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='
print(key)
cipher = Fernet(key)

HOST = '127.0.0.1'
PORT = 5500

clients = []
usernames = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f'Server listening on {HOST}:{PORT}')

def handle_client(client, username):
    while True:
        try:
            # Receive encrypted data
            encryptedData = client.recv(1024)
            if not encryptedData:
                break
            
            # Decrypt message
            message = cipher.decrypt(encryptedData).decode('utf-8')
            print(f"{username}: {message}")
            broadcast(f"{username}: {message}")
        except Exception as e:
            print(f"Error : {e}")
            break

    remove(client, username)

def broadcast(message):
    encryptedMessage = cipher.encrypt(message.encode('utf-8'))
    for client in clients:
        client.send(encryptedMessage)

def remove(client, username):
    if client in clients:
        clients.remove(client)
    if username in usernames:
        usernames.remove(username)

try:
    while True:
        client, address = server.accept()
        print(f'User connected from {address}')
        
        # Receive and decrypt username
        encrypted_username = client.recv(1024)
        username = cipher.decrypt(encrypted_username).decode('utf-8')
        
        clients.append(client)
        usernames.append(username)
        
        broadcast(f"{username} has joined!")
        
        # Handle this client in a new thread
        thread = threading.Thread(target=handle_client, args=(client, username))
        thread.start()
except KeyboardInterrupt:
    print("\nServer stopped.")
    server.close()
