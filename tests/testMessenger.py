import os
import socket
import threading
import time
import unittest

from Register.server import clients, shutdown_flag, start_server

class TestDiffieHellmanClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Start the server in a background thread before tests."""
        os.environ['TEST_MODE'] = '1'  # Set test mode to skip shutdown listener when testing
        cls.server_thread = threading.Thread(target=start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(5)  # Allow more time for the server to start

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
        self.assertIn(username, clients)
        self.assertEqual(clients[username], (ip, port))

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
        
    '''def test_single_user_connection(self):
        """Test if one client can connect to the server."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 5500))

        # Step 1: Send username to server
        username = "test_user"
        client_socket.sendall(username.encode())

        # Step 2: Receive DH parameter bytes from server
        # Read the first 4 bytes (length prefix) to know the size of the data to receive
        dh_param_length_data = client_socket.recv(4)
        dh_param_length = int.from_bytes(dh_param_length_data, 'big')
        dh_params = client_socket.recv(dh_param_length)

        self.assertTrue(dh_params.startswith(b'-----BEGIN DH PARAMETERS-----'))

        # Step 3: Send a dummy public key (for testing purposes)
        client_public_key = "dummy_public_key"
        client_socket.sendall(client_public_key.encode())

        # Server needs to process and set the client
        time.sleep(5)
        # Check if the client is added to the `clients` dictionary on the server
        self.assertIn(username, clients)
        self.assertEqual(clients[username]['public_key'], client_public_key)
        self.assertEqual(1, len(clients))

        # Step 4: Clean up (disconnect client)
        client_socket.sendall("exit".encode())

    def test_several_user_connection(self):
        """Test if several clients can connect to the server."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 5500))

        username_01 = "test_user01"
        client_socket.sendall(username_01.encode())

        dh_param_length_data = client_socket.recv(4)
        dh_param_length = int.from_bytes(dh_param_length_data, 'big')
        dh_params = client_socket.recv(dh_param_length)

        self.assertTrue(dh_params.startswith(b'-----BEGIN DH PARAMETERS-----'))

        client_public_key_01 = "dummy_public_key01"
        client_socket.sendall(client_public_key_01.encode())

        client_socket_02 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket_02.connect(('127.0.0.1', 5500))

        username_02 = "test_user02"
        client_socket_02.sendall(username_02.encode())

        dh_param_length_data = client_socket_02.recv(4)
        dh_param_length = int.from_bytes(dh_param_length_data, 'big')
        dh_params = client_socket_02.recv(dh_param_length)

        self.assertTrue(dh_params.startswith(b'-----BEGIN DH PARAMETERS-----'))

        client_public_key_02 = "dummy_public_key02"
        client_socket_02.sendall(client_public_key_02.encode())

        client_socket_03 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket_03.connect(('127.0.0.1', 5500))

        username_03 = "test_user03"
        client_socket_03.sendall(username_03.encode())

        dh_param_length_data = client_socket_03.recv(4)
        dh_param_length = int.from_bytes(dh_param_length_data, 'big')
        dh_params = client_socket_03.recv(dh_param_length)

        self.assertTrue(dh_params.startswith(b'-----BEGIN DH PARAMETERS-----'))

        client_public_key_03 = "dummy_public_key02"
        client_socket_03.sendall(client_public_key_03.encode())
        time.sleep(5)
        # Asserts
        self.assertIn(username_01, clients)
        self.assertIn(username_02, clients)
        self.assertIn(username_03, clients)
        self.assertEqual(clients[username_01]['public_key'], client_public_key_01)
        self.assertEqual(clients[username_02]['public_key'], client_public_key_02)
        self.assertEqual(clients[username_03]['public_key'], client_public_key_03)
        self.assertEqual(3, len(clients))
        # Step 4: Clean up (disconnect client)
        client_socket.sendall("exit".encode())
        client_socket_02.sendall("exit".encode())
        client_socket_03.sendall("exit".encode())

    def test_user_deletion(self):
        """Test if the client stays in the clients dictionary after leaving."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 5500))

        # Step 1: Send username to server
        username = "test_user"
        client_socket.sendall(username.encode())

        # Step 2: Receive DH parameter bytes from server
        # Read the first 4 bytes (length prefix) to know the size of the data to receive
        dh_param_length_data = client_socket.recv(4)
        dh_param_length = int.from_bytes(dh_param_length_data, 'big')
        dh_params = client_socket.recv(dh_param_length)

        self.assertTrue(dh_params.startswith(b'-----BEGIN DH PARAMETERS-----'))

        # Step 3: Send a dummy public key (for testing purposes)
        client_public_key = "dummy_public_key"
        client_socket.sendall(client_public_key.encode())

        # Server needs to process and set the client
        time.sleep(5)
        # Check if the client is added to the `clients` dictionary on the server
        self.assertIn(username, clients)
        self.assertEqual(clients[username]['public_key'], client_public_key)
        self.assertEqual(1, len(clients))

        # Step 4: Clean up (disconnect client)
        client_socket.send("exit".encode())
        time.sleep(2)
        self.assertEqual(0, len(clients))'''
    
    @classmethod
    def tearDownClass(cls):
        """Shutdown the server after tests."""
        global shutdown_flag
        shutdown_flag = True
        

if __name__ == '__main__':
    unittest.main()
