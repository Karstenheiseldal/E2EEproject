import os
import socket
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7


class DiffieHellmanClient:
    def __init__(self, parameters):
        # Generate parameters for Diffie-Hellman
        self.parameters = parameters
        self.private_key = self.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.shared_secret = None

    def generate_private_key(self):
        """Generate a private key using the DH parameters."""
        return self.parameters.generate_private_key()

    def serialize_public_key(self):
        """Serialize the public key to PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(pem):
        """Deserialize the public key from PEM format."""
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def derive_shared_secret(self, peer_public_key):
        """Derive the shared secret using the private key and the peer's public key."""
        # Compute the shared key
        shared_key  = self.private_key.exchange(peer_public_key)

        # Derive a key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the derived key in bytes
            salt=None,
            info=b'handshake data'
        )
        self.shared_secret = hkdf.derive(shared_key)

    def encrypt_message(self, message):
        # AES encryption with shared key
        iv = os.urandom(16)  # Random IV for AES CBC mode
        cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding the message to be block-size compatible
        padder = PKCS7(256).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()

        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return iv + encrypted_message  # Prepend IV to the encrypted message

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]  # Extract the IV
        cipher = Cipher(algorithms.AES(self.shared_secret), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()

        # Unpad the decrypted message
        unpadder = PKCS7(256).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

        return decrypted_message.decode()

def send_messages(client_socket, client):
    #username = input("Enter your username: ")
    """Thread function to send messages."""
    while True:
        #send_username(username)
        message = input("Enter message to send: ")
        encrypted_message = client.encrypt_message(message)
        client_socket.sendall(encrypted_message)
        print(f"Encrypted message sent.")

def send_username(username, client_socket):
    client_socket.send(username)

def receive_messages(client_socket, client):
    """Thread function to receive messages."""
    while True:
        try:
            encrypted_message_from_peer = client_socket.recv(4096)
            if encrypted_message_from_peer:
                decrypted_message = client.decrypt_message(encrypted_message_from_peer)
                print(f"Decrypted message received: {decrypted_message}")
            else:
                print("Connection closed by the peer.")
                break
        except Exception as e:
            print(f"Error in receiving messages: {e}")
            break

def start_client(host = '127.0.0.1', port = 5500):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        # Receive DH parameters from the server
        param_bytes = client_socket.recv(4096)
        parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())

        client = DiffieHellmanClient(parameters)

        public_key_serialized = client.serialize_public_key()
        client_socket.sendall(public_key_serialized)
        
        # Receive the other client's public key
        peer_public_key_serialized = client_socket.recv(4096)
        peer_public_key = DiffieHellmanClient.deserialize_public_key(peer_public_key_serialized)

        # Derive shared secret
        client.derive_shared_secret(peer_public_key)
        print(f"Shared secret established")
        # Start threads for sending and receiving messages
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, client))
        send_thread = threading.Thread(target=send_messages, args=(client_socket, client))

        receive_thread.start()  # Start listening for incoming messages first
        send_thread.start()  # Allow the user to send messages

        # Join both threads to keep the main thread alive
        receive_thread.join()
        send_thread.join()

if __name__ == "__main__":
    start_client()
