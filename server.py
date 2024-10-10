import socket
import threading
from cryptography.fernet import Fernet

# Same key as the client
# This key is used for the fernet cipher encryption of the message later on.
# This key is planned to be the shared secret.
key = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='

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
                print(f"{username} has disconnected.")
                break
            # Decrypt message
            message = cipher.decrypt(encryptedData).decode('utf-8')
            print(f"Received message from {username}: {message}")
            broadcast(f"{username}: {message}", client)
        except Exception as e:
            print(f"Error : {e}")
            break
    remove(client, username)

def broadcast(message, sender_client=None):
    encryptedMessage = cipher.encrypt(message.encode('utf-8'))
    for client in clients:
        if client != sender_client:  # Avoid echoing the message back to the sender
            try:
                client.send(encryptedMessage)
                print(f"Broadcasting message to client: {message}")
            except Exception as e:
                print(f"Failed to send message to a client: {e}")
                remove(client)  # Remove client if it cannot receive messages

def remove(client, username):
    if client in clients:
        clients.remove(client)
        client.close()
    if username in usernames:
        usernames.remove(username)
    if username:
        broadcast(f"{username} has left the chat.")
try:
    while True:
        client, address = server.accept()
        print(f'User connected from {address}')
        
        # Attempt to receive and decrypt the username
        encryptedUsername = client.recv(1024)
        if encryptedUsername:
            print("Received encrypted username:", encryptedUsername)  # Debugging statement
            username = cipher.decrypt(encryptedUsername).decode('utf-8')
            print(f"Username received and decrypted: {username}")
            
            # Send acknowledgment to the client
            client.send(cipher.encrypt(f"Welcome, {username}!".encode('utf-8')))
            
            clients.append(client)
            usernames.append(username)
            
            # Broadcast the join message to other clients
            broadcast(f"{username} has joined!", client)
            
            # Handle this client in a new thread
            thread = threading.Thread(target=handle_client, args=(client, username))
            thread.start()
        else:
            print("No username received, closing connection.")
            client.close()
except KeyboardInterrupt:
    print("\nServer stopped.")
    server.close()