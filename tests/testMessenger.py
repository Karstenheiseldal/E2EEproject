import os
import socket
import threading
import time
import unittest

from server import clients, server_socket, shutdown_flag, start_server


class TestDiffieHellmanClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Start the server in a background thread before tests."""
        os.environ['TEST_MODE'] = '1'  # Set test mode to skip shutdown listener
        cls.server_thread = threading.Thread(target=start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    def test_single_user_connection(self):
        global server_socket, clients
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

        # Step 4: Clean up (disconnect client)
        client_socket.close()

    def test_several_user_connection(self):
        global server_socket, clients
        """Test if one client can connect to the server."""
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
        client_socket.close()
        client_socket_02.close()
        client_socket_03.close()

    @classmethod
    def tearDownClass(cls):
        """Shutdown the server after tests."""
        global shutdown_flag
        shutdown_flag = True

if __name__ == '__main__':
    unittest.main()
