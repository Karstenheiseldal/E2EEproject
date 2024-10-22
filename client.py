import os
import socket
import threading
import queue

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

# Create events for managing input prompts
input_ready = threading.Event()  # This will be used as a flag to signal when input is allowed.
input_queue = queue.Queue()
send_done_event = threading.Event()  # Event to handle sending
recieve_done_event = threading.Event()  # Event to handle sending


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


def capture_input(input_queue, send_done_event):
    """Thread function to capture user input and store it in a queue."""
    input_ready.wait()  # Wait until the 'READY' signal is received
    while True:
        #recieve_done_event.wait()
        #recieve_done_event.clear()
        send_done_event.wait()  # Wait for the send_done_event to be set before prompting for input
        send_done_event.clear()  # Immediately clear it before input
        print("Enter message to send: ", end='')  # Print the input prompt without a newline
        message = input()  # User enters the message on the same line
        input_queue.put(message)
        # The next prompt will appear after the message is sent

def send_messages(client_socket, client, input_queue, send_done_event):
    """Thread function to send messages from the input queue."""
    while True:
        message = input_queue.get()  # Block until there's a message in the queue
        if message:
            try:
                encrypted_message = client.encrypt_message(message)
                message_length = len(encrypted_message).to_bytes(4, 'big')
                client_socket.sendall(message_length + encrypted_message)
                print(f"Encrypted message sent: {message}")
                send_done_event.set()
                recieve_done_event.set()

            except Exception as e:
                print(f"Error in encrypting or sending message: {e}")
            
            
                
            

def receive_messages(client_socket, client, recieve_done_event):
    """Thread function to receive messages."""
    while True:
        recieve_done_event.clear()
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
                recieve_done_event.set()  # Ensure that input prompt appears after 'READY'
                continue  # Skip processing and wait for the actual message

            # Get the length of the incoming encrypted message
            message_length = int.from_bytes(message_length_data, 'big')

            # Receive the actual encrypted message based on the length received
            encrypted_message_from_peer = b""
            while len(encrypted_message_from_peer) < message_length:
                packet = client_socket.recv(message_length - len(encrypted_message_from_peer))
                if not packet:
                    raise ValueError("Connection closed before all data received.")
                encrypted_message_from_peer += packet
            
            # Decrypt the message
            try:
                decrypted_message = client.decrypt_message(encrypted_message_from_peer)
                print(f"Decrypted message received: {decrypted_message}")
                # Prompt user for new input after receiving a message

            except ValueError as e:
                print(f"Error decrypting message (possibly padding issue): {e}")
            
            recieve_done_event.set()
            send_done_event.set()

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
        print("Username sent")

        # Step 2: Receive DH parameters from the server and create DH key pair
        param_bytes = receive_with_length_prefix(client_socket)
        parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
        client = DiffieHellmanClient(parameters)
        # Step 3: Send client's public key to the server
        public_key_serialized = client.serialize_public_key()
        client_socket.sendall(len(public_key_serialized).to_bytes(4, 'big') + public_key_serialized)
        print("Public key sent to the server.")
        try:
            while True:
                # Get input from the user (client terminal)
                message = input("Enter a message to send to the server (type 'exit' to quit): ")

                # If the user types 'exit', close the connection
                if message.lower() == 'exit':
                    print("Closing connection to the server...")
                    break

                # Send the message to the server
                client_socket.send(message.encode())

                # If the message is "!get_users", expect a response from the server
                if message == "!get_users":
                    # Receive the response from the server
                    server_response = client_socket.recv(1024).decode()
                    print(f"{server_response}")

        except:
            print("Connection has been aborted")
            client_socket.close()
        finally:
            # Close the client connection
            client_socket.close()
        """
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

        send_done_event.set()  # Set the send event to allow the first input
        recieve_done_event.set()

        # Step 5: Start threads for sending and receiving messages
        input_thread = threading.Thread(target=capture_input, args=(input_queue, send_done_event))  # Pass send_done_event
        send_thread = threading.Thread(target=send_messages, args=(client_socket, client, input_queue, send_done_event))  # Pass send_done_event
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, client, recieve_done_event))

        # Start all threads
        input_thread.start()
        send_thread.start()
        receive_thread.start()

        input_thread.join()
        send_thread.join()
        receive_thread.join()
        """

if __name__ == "__main__":
    start_client()
