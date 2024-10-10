import unittest
import socket
import threading
import time
from server import startServer, clients  # Import startServer and clients list
from cryptography.fernet import Fernet

# Constants for testing
HOST = '127.0.0.1'
PORT = 5500
KEY = '6wsunZhIiHUWxJqQ74p6ICRivUFmlR6hOz8ec_MDUKk='
cipher = Fernet(KEY)


class TestMessenger(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=startServer)  # Correct target syntax
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Add delay to ensure server starts before tests run

    def sendUsername(self, clientSocket, username="test user"):
        # Encrypt and send username
        encryptedUsername = cipher.encrypt(username.encode())
        clientSocket.sendall(encryptedUsername)
    
    def testClientConnection(self):
        # Test if the client can connect to the server and send a username
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((HOST, PORT))
        self.sendUsername(clientSocket)
        self.assertTrue(clientSocket)
        clientSocket.close()

    def testMessageEncryptionDecryption(self):
        # Test encryption and decryption
        message = "Hello, World!"
        encryptedMessage = cipher.encrypt(message.encode('utf-8'))
        decryptedMessage = cipher.decrypt(encryptedMessage).decode('utf-8')
        self.assertEquals(decryptedMessage, message)

    def testBroadcastMessage(self):
        # Test message broadcasting functionality
        client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        client1.connect((HOST, PORT))
        client2.connect((HOST, PORT))
        
        # Send usernames for both clients
        self.sendUsername(client1, "Client 1")
        self.sendUsername(client2, "Client 2")

        client2.recv(1024)  # Read and discard the "Welcome, Client 2!" message
        client1.recv(1024)  

        # Send a message from client1 and check if client2 receives it
        message1 = "Hello from Client 1"
        message2 = "Hello from Client 2"
        encryptedMessage1 = cipher.encrypt(message1.encode())
        client1.sendall(encryptedMessage1)
        receivedMessage1 = cipher.decrypt(client2.recv(1024)).decode()
        self.assertEqual(receivedMessage1, "Hello from Client 1")

        encryptedMessage2 = cipher.encrypt(message2.encode())
        client2.sendall(encryptedMessage2)

        receivedMessage2 = cipher.decrypt(client1.recv(1024)).decode()
        self.assertEqual(receivedMessage2, "Hello from Client 2")
        
        client1.close()
        client2.close()

    def testClientReceiveMessage(self):
        # Test if client can receive messages from the server
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSocket.connect((HOST, PORT))
        self.sendUsername(clientSocket)

        # Simulate a message broadcast by the server
        broadcastMessage = "Welcome, test user!"
        encryptedBroadcast = cipher.encrypt(broadcastMessage.encode())
        clientSocket.sendall(encryptedBroadcast)

        receivedMessage = cipher.decrypt(clientSocket.recv(1024)).decode()
        self.assertEqual(broadcastMessage, receivedMessage)

        clientSocket.close()

    @classmethod
    def tearDownClass(cls):
        # Cleanup server and any connections if necessary
        for client in clients:
            client.close()
       

if __name__ == "__main__":
    unittest.main()