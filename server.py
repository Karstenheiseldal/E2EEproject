import socket
import threading
from cryptography.fernet import Fernet

#  Sets up a cryptographic key and a cipher for encrypting and decrypting messages, as well as defining the server's address and port.
KEY = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='
cipher = Fernet(KEY) # Creates an encryption and decryption tool using this key. For now, the same as client.

HOST = '127.0.0.1' # Sets the IP address for the localhost which means the server and client are running on the same machine. In a real-world deployment it would say IP address
PORT = 5500 # Specifies the port the server listens on. The client will connect to this same port to communicate with the server.

clients = [] # Array of clients
usernames = [] # Array of usernames

publicKeys = {}

# Start server function
def startServer():
    global serverObject
    serverObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverObject.bind((HOST, PORT))
    serverObject.listen()
    print(f"Server listening on {HOST}:{PORT}... pretty quiet")

    while True:
        client, address = serverObject.accept()
        print(f"User connected from {address}")
        print(f"Participants: {len(clients)+1}")
        print(usernames)
        # Handle username and add client to lists
        clients.append(client)
        username = client.recv(1024)
        print(username, " is connected.")
        if username:
            usernames.append(username)
            thread = threading.Thread(target=handleClient, args=(client, username))
            thread.start()
        else:
            print("No username received, closing connection.")
            client.close()


# The following function manages communication with a single connected client. 
# It receives, decrypts, and forwards messages from this client to others, while handling disconnects and errors. 
def handleClient(client, username): 
    while True:
        try:
            # Receive encrypted data from the client
            encryptedMessage = client.recv(1024)
            if not encryptedMessage:  # Client disconnected
                print(f"{username} has disconnected.")
                break
            
            print(f"Encrypted data received from {username}: {encryptedMessage}")
            forwardMessage(encryptedMessage, client)  # Forwards as bytes, no conversion
            
        except Exception as e:
            print(f"Error : {e}")
            break
    remove(client, username)
    
def forwardMessage(encryptedMessage: bytes, senderClient=None):
    print("ForwardingMessage message")  # Debug statement
    for client in clients:
        if client != senderClient:  # Avoid echoing the message back to the sender
            try:
                client.send(encryptedMessage)  # Directly send the encrypted message as bytes
            except Exception as e:
                print(f"Failed to send message to a client: {e}")
                remove(client, encryptedMessage(client))

def remove(client, username):
    if client in clients:
        clients.remove(client)
        client.close()
    if username in usernames:
        usernames.remove(username)
    
    # Encrypt and forward the leave message to ensure it’s bytes
    leaveMessage = f"{username} has left the chat.".encode('utf-8')
    forwardMessage(leaveMessage)

if __name__ == "__main__":
    try:
        startServer()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        serverObject.close()
