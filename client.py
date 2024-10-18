import os
import socket
import threading
import queue

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

input_ready = threading.Event()  # This will be used as a flag to signal when input is allowed.

class DiffieHellmanClient:
    def __init__(self, parameters):
        self.parameters = parameters
        self.private_key = self.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.shared_secret = None

    def generate_private_key(self):
        return self.parameters.generate_private_key()

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(pem):
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def derive_shared_secret(self, peer_public_key):
        shared_key = self.private_key.exchange(peer_public_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        )
        self.shared_secret = hkdf.derive(shared_key)

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(256).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return iv + encrypted_message

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]
        cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
        unpadder = PKCS7(256).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
        return decrypted_message.decode()

def receive_with_length_prefix(conn):
    """Helper function to receive data with a length prefix."""
    data_length = int.from_bytes(conn.recv(4), 'big')
    data = b""
    while len(data) < data_length:
        packet = conn.recv(data_length - len(data))
        if not packet:
            raise ValueError("Connection closed before all data received.")
        data += packet
    return data

def capture_input(input_queue):
    """Thread function to capture user input and store it in a queue."""
    input_ready.wait()  # Wait until the 'READY' signal is received
    while True:
        message = input("Enter message to send: ")
        input_queue.put(message)

def send_messages(client_socket, client, input_queue):
    """Thread function to send messages from the input queue."""
    while True:
        message = input_queue.get()  # Block until there's a message in the queue
        if message:
            encrypted_message = client.encrypt_message(message)
            message_length = len(encrypted_message).to_bytes(4, 'big')
            client_socket.sendall(message_length + encrypted_message)
            print("Encrypted message sent.")

def receive_messages(client_socket, client):
    """Thread function to receive messages."""
    while True:
        try:
            # Receive message length first or the "READY" message
            message_length_data = client_socket.recv(4)
            if not message_length_data:
                print("Connection closed by the peer.")
                break
            
            # Check if the message is "READY"
            if message_length_data == b"READ":
                rest_of_ready = client_socket.recv(1)  # Read the last byte ('Y') from "READY"
                input_ready.set()
                print("Received 'READY' from the server. Clients can start chatting.")
                print()
                continue  # Skip processing and wait for the actual message
            
            message_length = int.from_bytes(message_length_data, 'big')

            # Receive the actual encrypted message based on the length received
            encrypted_message_from_peer = b""
            while len(encrypted_message_from_peer) < message_length:
                packet = client_socket.recv(message_length - len(encrypted_message_from_peer))
                if not packet:
                    raise ValueError("Connection closed before all data received.")
                encrypted_message_from_peer += packet

            # Decrypt the message
            decrypted_message = client.decrypt_message(encrypted_message_from_peer)
            print(f"Decrypted message received: {decrypted_message}")
            
        except Exception as e:
            print(f"Error in receiving messages: {e}")
            break

def start_client(host='127.0.0.1', port=5500):
    input_queue = queue.Queue()  # Create a queue for user input

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        # Step 1: Prompt for username and send it to the server
        username = input("Enter your username: ")
        client_socket.sendall(username.encode('utf-8'))
        print("Username sent. Waiting for peer's public key...")

        # Step 2: Receive DH parameters from the server and create DH key pair
        param_bytes = receive_with_length_prefix(client_socket)
        parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
        client = DiffieHellmanClient(parameters)

        # Step 3: Send client's public key to the server
        public_key_serialized = client.serialize_public_key()
        client_socket.sendall(len(public_key_serialized).to_bytes(4, 'big') + public_key_serialized)
        print("Public key sent to the server.")

        # Step 4: Receive peer's public key with length prefix
        peer_public_key_serialized = receive_with_length_prefix(client_socket)
        print("Received peer's public key:")
        print(peer_public_key_serialized.decode())  # Debug output to inspect the format

        # Deserialize the peer's public key and derive the shared secret
        try:
            peer_public_key = DiffieHellmanClient.deserialize_public_key(peer_public_key_serialized)
            client.derive_shared_secret(peer_public_key)
            print("Shared secret established with peer.")
            print(f"Shared secret (client-side): {client.shared_secret.hex()}")
        except ValueError as e:
            print(f"Failed to deserialize peer's public key: {e}")
            return  # Exit if deserialization fails

        # Step 5: Start threads for sending and receiving messages
        input_thread = threading.Thread(target=capture_input, args=(input_queue,))
        send_thread = threading.Thread(target=send_messages, args=(client_socket, client, input_queue))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, client))

        # Start all threads
        input_thread.start()
        send_thread.start()
        receive_thread.start()

        input_thread.join()
        send_thread.join()
        receive_thread.join()

if __name__ == "__main__":
    start_client()
