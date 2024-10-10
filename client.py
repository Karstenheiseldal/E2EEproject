import socket
import threading
from cryptography.fernet import Fernet

#Set host and port
HOST = '127.0.0.1'
PORT = 5500

#socket.socket(...): This function initializes a new socket object that can connect to another machine over the network.
#socket.AF_INET: Specifies the address family as IPv4, meaning it will use IPv4 addresses (e.g., 192.168.1.1).
#socket.SOCK_STREAM: Specifies the socket type as TCP, which is a connection-oriented, reliable, and ordered communication protocol.
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#shuts down threads
shutdownEvent = threading.Event()  # Event to signal threads to stop

#set timer for
client.settimeout(5) #The line client.settimeout(5) sets a timeout for the socket operations associated with client. 

#Here’s what it does:

#Specifies a maximum wait time of 5 seconds for blocking socket operations (such as connect, recieve, send, etc.).
#If any of these operations take longer than 5 seconds, the socket will raise a socket.timeout exception. 

try:
    client.connect((HOST, PORT)) #Attempts to connect the client socket to the server at the specified HOST (IP address or hostname) and PORT (port number).
    print("Connected to the server successfully.")
except socket.error as e: #Catches any socket-related errors that occur during the connection attempt.
    print(f"Could not connect to server: {e}")
    exit(1)  # Exit if the connection fails

key = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='#Fernet key must be 32 url-safe base64-encoded bytes. Random key generated once from Fernet.generate_key
cipher = Fernet(key) #Using fernet as cypher to encrypt and decrypt messages.

def receive():
    while True:
        try:
            encryptedMessage = client.recv(1024)
            if encryptedMessage:
                decryptedMessage = cipher.decrypt(encryptedMessage).decode('utf-8')
                print ('Encrypted message: ', encryptedMessage)
                print('Decrypted Message: ', decryptedMessage)
            else:
                print("Server has closed the connection.")
                client.close()
                break

        except socket.timeout:
            continue  # Ignore timeout and keep looping until connection is closed

        except Exception as e:
            print(f"An error occurred in receive: {e}")
            client.close
            break

def send():
    username = input("Enter your username: ")
    try:
        if not shutdownEvent.is_set():
            encrypted_username = cipher.encrypt(username.encode('utf-8'))
            client.send(encrypted_username)
            print("Username sent to server.")
            print("Username sent. Type messages to send to the server:")
        
        while not shutdownEvent.is_set():
            message = input('')
            if shutdownEvent.is_set():  # Check shutdown event after each input
                break
            encryptedMessage = cipher.encrypt(message.encode('utf-8'))
            client.send(encryptedMessage)
    except socket.timeout:
        print("Socket operation timed out.")
    except OSError as e:
        print(f"An error occurred in send: {e}")
        shutdownEvent.set()
        client.close()

# Start the threads
receiveThread = threading.Thread(target=receive)
sendThread = threading.Thread(target=send)

receiveThread.start()
sendThread.start()

# Ensure both threads close properly
receiveThread.join()
sendThread.join()
