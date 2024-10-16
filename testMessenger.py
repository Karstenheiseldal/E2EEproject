import unittest
import socket
import threading
import time
import server
from cryptography.fernet import Fernet

# Constants for testing
HOST = '127.0.0.1'
PORT = 5500
KEY = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='
cipher = Fernet(KEY)

class TestMessenger(unittest.TestCase):
    def setUp(self):
        # Start the server in a separate thread
        serverThread = threading.Thread(target=server.startServer)
        serverThread.daemon = True
        serverThread.start()
        time.sleep(1)  # Ensure server is ready before tests start
    
    def testClientConnection(self):
        # Test if the client can connect to the server and send a username
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((HOST, PORT))
        testUsername = 'TestUserName'
        encryptedUsername = cipher.encrypt(testUsername.encode('UTF-8'))
        clientSocket.sendall(encryptedUsername)
        self.assertTrue(clientSocket)
        clientSocket.close()

    def testMessageEncryptionDecryption(self):
        # Test encryption and decryption
        message = "HelloWorld!"
        encryptedMessage = cipher.encrypt(message.encode('utf-8'))
        decryptedMessage = cipher.decrypt(encryptedMessage).decode('utf-8')
        self.assertEqual(decryptedMessage, message)

    def testClientReceiveMessage(self):
        # Test message broadcasting functionality
        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        username1 = 'hey bababa'
        username2 = 'hey hal'
        encryptedUsername1 = cipher.encrypt(username1.encode('utf-8'))
        encryptedUsername2 = cipher.encrypt(username2.encode('utf-8'))

        client1.connect((HOST, PORT))
        client2.connect((HOST, PORT))
        
        # Send usernames for both clients
        client1.sendall(encryptedUsername1)
        client2.sendall(encryptedUsername2)

        # Allow server to process and broadcast the join messages
        time.sleep(1)

        # Client1 sends a message, and we check if Client2 receives it
        message1 = "HelloFromClient1"
        encryptedMessage1 = cipher.encrypt(message1.encode())
        client1.sendall(encryptedMessage1)
        receivedMessage1 = cipher.decrypt(client2.recv(1024)).decode()
        self.assertEqual(receivedMessage1, message1)
        # Client2 sends a message, and we check if Client1 receives it
        message2 = "HelloFromClient2"
        encryptedMessage2 = cipher.encrypt(message2.encode())
        client2.sendall(encryptedMessage2)

        receivedMessage2 = cipher.decrypt(client1.recv(1024)).decode()
        self.assertEqual(receivedMessage2, message2)
        
        client1.close()
        client2.close()
    def tearDown(self):
        # Cleanup server and any connections if necessary
        for client in server.clients:
            client.close()
        server.serverObject.close()  # Close the server socket
"""
# Doesn't work due to the fact that the server can't communicate, only the clients can.
    def testBroadCastMessage(self):
        username1 = 'hey bababa'
        encryptedUsername1 = cipher.encrypt(username1.encode('utf-8'))

        # Test if client can receive messages from the server
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((HOST, PORT))
        clientSocket.sendall(encryptedUsername1)
        
        # Simulate a message broadcast by the server
        broadcastMessage = "WelcomeTestUser!"
        encryptedBroadcast = cipher.encrypt(broadcastMessage.encode())
        clientSocket.sendall(encryptedBroadcast)
        receivedMessage = cipher.decrypt(clientSocket.recv(1024)).decode()
        self.assertEqual(broadcastMessage, receivedMessage)

        clientSocket.close()
"""

if __name__ == "__main__":
    unittest.main()
