import socket
import threading
from cryptography.fernet import Fernet

#  Sets up a cryptographic key and a cipher for encrypting and decrypting messages, as well as defining the server's address and port.
key = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='
cipher = Fernet(key) # Creates an encryption and decryption tool using this key. For now, the same as client.

HOST = '127.0.0.1' #Sets the IP address for the localhost which means the server and client are running on the same machine. In a real-world deployment it would say IP address
PORT = 5500 # Specifies the port the server listens on. The client will connect to this same port to communicate with the server.

clients = [] #Array of clients
usernames = [] ##Array of usernames

# Start server function
def startServer():
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    while True:
        client, address = server.accept()
        print(f"User connected from {address}")

        # Handle username and add client to lists
        encryptedUsername = client.recv(1024)
        if encryptedUsername:
            username = cipher.decrypt(encryptedUsername).decode('utf-8')
            client.send(cipher.encrypt(f"Welcome, {username}!".encode('utf-8')))
            
            clients.append(client)
            usernames.append(username)
            print('list of usernames', usernames)

            # Broadcast join message and start handling client in new thread
            broadcast(f"{username} has joined!", client)
            thread = threading.Thread(target=handleClient, args=(client, username))
            thread.start()
        else:
            print("No username received, closing connection.")
            client.close()


#The following function manages communication with a single connected client. 
#It receives, decrypts, and broadcasts messages from this client to others, while handling disconnects and errors. 
def handleClient(client, username): 
    while True:
        try:
            encryptedData = client.recv(1024) #Receives up to 1024 bytes of encrypted data from the client.
            if not encryptedData: #: If encryptedData is empty (indicating the client has disconnected), it logs a disconnection message, exits the loop, and stops listening for messages.
                print(f"{username} has disconnected.")
                break
            message = cipher.decrypt(encryptedData).decode('utf-8') #Decrypts the received data using cipher.decrypt(...) and decodes it from UTF-8.
            print(f"Received message from {username}: {message}")
            broadcast(f"{username}: {message}", client) # send the message to all other connected clients, allowing everyone to see it.
        except Exception as e:
            print(f"Error : {e}")
            break
    remove(client, username) #After exiting the loop, remove(client, username) is called to remove the client from the server’s records

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

#Function to remove client and username from respective array and close the socket object.
def remove(client, username):
    if client in clients:
        clients.remove(client)
        client.close()
    if username in usernames:
        usernames.remove(username)
    if username:
        broadcast(f"{username} has left the chat.")

if __name__ == "__main__":
    try:
        startServer()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.close()