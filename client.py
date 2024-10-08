import socket
import threading
from cryptography.fernet import Fernet

# Pre-shared key for encryption/decryption (for simplicity here, both client and server know the key)
key = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='
print(key)
cipher = Fernet(key)

HOST = '127.0.0.1'
PORT = 5500

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Control flag for both threads
isRunning = True

def receive():
    global isRunning
    while isRunning:
        try:
            encryptedMessage = client.recv(1024)
            if encryptedMessage:
                decryptedMessage = cipher.decrypt(encryptedMessage).decode('utf-8')
                print ('Encrypted message: ', encryptedMessage)
                print('Decrypted Message: ', decryptedMessage)
            else:
                print("Server has closed the connection.")
                isRunning = False
                client.close()
                break
        except Exception as e:
            print(f"An error occurred in receive: {e}")
            isRunning = False
            client.close()
            break

def send():
    global isRunning
    username = input("Enter your username: ")
    try:
        # Ensure socket is open before sending
        if isRunning:
            client.send(cipher.encrypt(username.encode('utf-8')))
        while isRunning:
            message = input('')
            if isRunning:  # Check if the connection is still active
                encryptedMessage = cipher.encrypt(message.encode('utf-8'))
                client.send(encryptedMessage)
            else:
                break
    except OSError as e:
        print(f"An error occurred in send: {e}")
        isRunning = False
    finally:
        client.close()

# Start the threads
receiveThread = threading.Thread(target=receive)
sendThread = threading.Thread(target=send)

receiveThread.start()
sendThread.start()

# Ensure both threads close properly
receiveThread.join()
sendThread.join()
