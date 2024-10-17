import socket
import threading
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from client import DiffieHellmanClient
from server import shutdown_server, start_server


class TestDiffieHellmanClient(unittest.TestCase):
    def setUp(self):
        """Set up the server in a separate thread and connect two clients."""
        # Start the server in a separate thread
        self.server_thread = threading.Thread(target=start_server)
        self.server_thread.daemon = True  # Ensures the thread terminates with the main thread
        self.server_thread.start()
        # Connect two clients to the server
        self.client1_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect both clients to the server
        self.client1_socket.connect(('127.0.0.1', 5500))
        self.client2_socket.connect(('127.0.0.1', 5500))
        

        # Receive DH parameters from the server for both clients
        param_bytes1 = self.client1_socket.recv(4096)
        self.parameters = serialization.load_pem_parameters(param_bytes1, backend=default_backend())

        # Create DiffieHellmanClient objects for each client
        self.client1 = DiffieHellmanClient(self.parameters)
        self.client2 = DiffieHellmanClient(self.parameters)

        # Exchange public keys between clients
        self.client1_socket.sendall(self.client1.serialize_public_key())
        self.client2_socket.sendall(self.client2.serialize_public_key())

        peer_public_key_client1 = DiffieHellmanClient.deserialize_public_key(self.client2_socket.recv(4096))
        peer_public_key_client2 = DiffieHellmanClient.deserialize_public_key(self.client1_socket.recv(4096))

        # Derive the shared secret for each client
        self.client1.derive_shared_secret(peer_public_key_client1)
        self.client2.derive_shared_secret(peer_public_key_client2)

    def test_client_connection(self):
        """Test if the clients can successfully exchange messages after key establishment."""
        # Encrypt a message from client 1 and send it to client 2
        message = "Hello from Client 1"
        encrypted_message = self.client1.encrypt_message(message)
        self.client1_socket.sendall(encrypted_message)

        # Receive and decrypt the message on client 2
        received_encrypted_message = self.client2_socket.recv(4096)
        decrypted_message = self.client2.decrypt_message(received_encrypted_message)
        print(f"Decrypted message received: {decrypted_message}")
        # Assert that the decrypted message matches the original
        self.assertEqual(decrypted_message, message)

    def test_client_reverse_communication(self):
        """Test message sending from Client 2 to Client 1."""
        # Encrypt a message from client 2 and send it to client 1
        message = "This is a verrry long message, I hope it is gonna pass."
        encrypted_message = self.client2.encrypt_message(message)
        self.client2_socket.sendall(encrypted_message)

        # Receive and decrypt the message on client 1
        received_encrypted_message = self.client1_socket.recv(4096)
        decrypted_message = self.client1.decrypt_message(received_encrypted_message)

        # Assert that the decrypted message matches the original
        self.assertEqual(decrypted_message, message)
        
    def tearDown(self):
        """Shut down the server and close all client connections."""
        shutdown_server(None, [self.client1_socket, self.client2_socket])  # Close connections
        self.client1_socket.close()
        self.client2_socket.close()

if __name__ == '__main__':
    unittest.main()
