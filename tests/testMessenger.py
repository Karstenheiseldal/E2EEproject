import os
import socket
import threading
import time
import unittest

from Register.server import shutdown_flag, start_server


class TestDiffieHellmanClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Start the server in a background thread before tests."""
        os.environ['TEST_MODE'] = '1'  # Set test mode to skip shutdown listener when testing
        cls.server_thread = threading.Thread(target=start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(2)  # Allow more time for the server to start

    def setUp(self):
        """Set up client sockets for each test."""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 5501))

        self.client_socket_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket_2.connect(('127.0.0.1', 5501))
    
    def tearDown(self):
        """Close the client sockets after each test."""
        self.client_socket.close()
        self.client_socket_2.close()

    def test_registration(self):
        """Test client registration with the server."""
        username = "test_user"
        ip = "127.0.0.1"
        port = 12345

        # Send registration data
        registration_message = f"REGISTER\n{username},{ip},{port}"
        self.client_socket.sendall(registration_message.encode())
        response = self.client_socket.recv(1024).decode()

        # Allow some time for the server to update the clients dictionary
        time.sleep(5)  # Adjust the delay as necessary for your setup
        self.assertEqual(response, "Registration successful")
        self.client_socket.sendall("QUERY\nLIST_CLIENTS".encode())
        response = self.client_socket.recv(1024).decode()
        self.assertIn(username, response)

    def test_list_clients(self):
        """Test querying the list of registered clients."""
        # Register a test user
        username = "test_user"
        ip = "127.0.0.1"
        port = 12345
        registration_message = f"REGISTER\n{username},{ip},{port}"
        self.client_socket.sendall(registration_message.encode())
        time.sleep(2)
        self.client_socket.recv(1024)  # Consume the registration response

        username2 = "test_user2"
        ip = "127.0.0.1"
        port2 = 12348
        registration_message2 = f"REGISTER\n{username2},{ip},{port2}"
        self.client_socket_2.sendall(registration_message2.encode())
        time.sleep(2)
        self.client_socket_2.recv(1024)

        # Allow some time for the server to update
        time.sleep(5)

        # Query the list of clients
        query_message = "QUERY\nLIST_CLIENTS"
        self.client_socket.sendall(query_message.encode())
        response = self.client_socket.recv(1024).decode()

        self.assertIn(username, response)
        self.assertIn(username2, response)

    def test_get_peer_address(self):
        """Test retrieving a peer's address."""
        # Register user
        username = "test_user34"
        ip = "127.0.0.1"
        port = 12345
        registration_message = f"REGISTER\n{username},{ip},{port}"
        self.client_socket.sendall(registration_message.encode())
        self.client_socket.recv(1024)  # Consume the registration response

        # Allow time for registration
        time.sleep(2)

        # Query the peer address
        peer_query_message = f"QUERY\nGET_PEER {username}"
        self.client_socket.sendall(peer_query_message.encode())
        response = self.client_socket.recv(1024).decode()

        expected_response = f"{ip},{port}"
        self.assertEqual(response, expected_response)

    def test_invalid_query(self):
        """Test handling an invalid query."""
        username = "test_user"
        ip = "127.0.0.1"
        port = 12345
        registration_message = f"REGISTER\n{username},{ip},{port}"
        self.client_socket.sendall(registration_message.encode())
        time.sleep(2)
        self.client_socket.recv(1024)  # Consume the registration response
        invalid_query_message = "QUERY\nINVALID_COMMAND"
        self.client_socket.sendall(invalid_query_message.encode())
        # Allow time for server to handle
        time.sleep(2)
        response = self.client_socket.recv(1024).decode()
        self.assertEqual(response, "Unknown Query")

    @classmethod
    def tearDownClass(cls):
        """Shutdown the server after tests."""
        global shutdown_flag
        shutdown_flag = True
        

if __name__ == '__main__':
    unittest.main()
