import socket
import threading
from cryptography.fernet import Fernet

#Set host and port
HOST = '127.0.0.1'
PORT = 5500
KEY = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='

"""
    socket.socket(...): This function initializes a new socket object that can connect to another machine over the network.
    socket.AF_INET: Specifies the address family as IPv4, meaning it will use IPv4 addresses (e.g., 192.168.1.1).
    socket.SOCK_STREAM: Specifies the socket type as TCP, which is a connection-oriented, reliable, and ordered communication protocol.
"""
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Shuts down threads. When threading.Event.is_set() then they both shut down.
shutdownEvent = threading.Event()

# Sets a timeout for the socket operations associated with client. 
client.settimeout(5)

try:
    client.connect((HOST, PORT)) # Attempts to connect the client socket to the server at the specified HOST and PORT.
    print("Connected to the server successfully.")
except socket.error as e: # Catches any socket-related errors that occur during the connection attempt.
    print(f"Could not connect to server: {e}")
    exit(1)  # Exits if the connection fails
"""
    Fernet key must be 32 url-safe base64-encoded bytes, therefore so long.
    Random key generated once from Fernet.generate_key. Just using the same key in the server and client for now.
"""
cipher = Fernet(KEY) #Using a Fernet object as cypher to encrypt and decrypt messages.

"""
    This function is for receiving a message.
    It listens for messages until the connection is closed
"""
def receive():
    while True:
        try:
            encryptedMessage = client.recv(1024) # Receives up to 1024 bytes of data from the server. If there’s data, it’s stored in the encryptedMessage variable.
            if encryptedMessage: # Checks if data was received. If it was, it attempts to decrypt it using the cipher and  storing it in decryptedMessage variable.
                decryptedMessage = cipher.decrypt(encryptedMessage).decode('utf-8')
                print ('Encrypted message: ', encryptedMessage)
                print(decryptedMessage)
            else: # If encryptedMessage is empty (indicating the server has closed the connection), it prints a message, closes the socket, and exits the loop to stop listening.
                print("Server has closed the connection.")
                client.close()
                break

        except socket.timeout: # If a timeout occurs (as set by client.settimeout(5)), it ignores the timeout, allowing the loop to continue without interruption.
            continue  # Ignore timeout and keep looping until connection is closed

        except Exception as e:
            print(f"An error occurred in receive: {e}")
            client.close
            break


def encryptUsername(username):
    encryptedUsername = cipher.encrypt(username.encode('utf-8' ))
    return encryptedUsername

def sendUsername(username):
    encryptedUsername = encryptUsername(username)
    client.send(encryptedUsername)

"""
    This function is for sending a message.
    Also it sets the username for the user then sending its encrypted username to the server.
"""
def send():
    username = input("Enter your username: ") # Prompts the user to enter their username, which will be sent to the server as the initial identification.
    try:
        if not shutdownEvent.is_set(): # Checks if the shutdownEvent is triggered, meaning the connection should close. If not, the function proceeds.
            # Encrypts the username, converting it from plaintext to an encrypted byte form.
            sendUsername(username)
            print("Your username is sent to server.")
            print("Type a message in the command line to send a message to the server:")
        
        while not shutdownEvent.is_set(): #: Starts a loop to continuously accept user input messages until the shutdownEvent is triggered.
            message = input('') # Collects a new message from the user each time
            fullMessage = f"[{username}]: {message}"
            if shutdownEvent.is_set():  # After each input, the function checks if shutdownEvent was set (possibly by another function or error). If so, it breaks out of the loop.
                break
            encryptedMessage = cipher.encrypt(fullMessage.encode('utf-8')) # Encrypts message
            client.send(encryptedMessage) # Send using the socket object.
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
