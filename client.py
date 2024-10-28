import socket
import threading
import os
import sys
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def save_dh_parameters(parameters, filename="dh_parameters.pem"):
    """Save DH parameters to a file."""
    with open(filename, "wb") as f:
        f.write(parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        ))

def load_dh_parameters(filename="dh_parameters.pem"):
    """Load DH parameters from a file."""
    with open(filename, "rb") as f:
        return serialization.load_pem_parameters(f.read())

class DiffieHellmanClient:
    def __init__(self, parameters=None):
        # Use shared parameters if provided, otherwise generate new ones
        self.parameters = parameters if parameters else dh.generate_parameters(generator=2, key_size=2048)
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()


    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_public_key(self, peer_public_key_bytes):
        return serialization.load_pem_public_key(peer_public_key_bytes)

    def derive_shared_secret(self, peer_public_key):
        shared_key = self.private_key.exchange(peer_public_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        )
        return hkdf.derive(shared_key)

# Register client with the registry server
def register_with_server(username, ip, port, server_ip='127.0.0.1', server_port=5500):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, server_port))
             # Send purpose identifier for registration
            registration_data = f"REGISTER\n{username},{ip},{port}"
            print(f"Sending registration data: {registration_data.encode()}")
            sock.sendall(registration_data.encode())  # Send the actual registration data next
            response = sock.recv(1024).decode()
            print(f"Server response: {response}")
            return response == "Registration successful"
        
    except Exception as e:
        print(f"Error registering with server: {e}")
        return False
    
def get_peer_address(peer_username, server_ip='127.0.0.1', server_port=5500):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, server_port))
            query = f"QUERY\nGET_PEER {peer_username}"
            print(f"Requesting address for peer: {peer_username}")
            sock.sendall(query.encode())

            peer_address = sock.recv(1024).decode()

            # Check if peer address is properly formatted or if the peer is not found
            if peer_address == "Peer not found":
                print("Peer not found.")
                return None

            # Ensure we have both an IP and port returned
            print(f"Received peer address: {peer_address}")
            ip, port = peer_address.split(',')
            return ip, int(port)  # Return the peer's IP and port
    except Exception as e:
        print(f"Error retrieving peer address: {e}")
        return None

# Peer-to-peer server that waits for a connection
def p2p_server(host, port, peer_username, parameters):
    client = DiffieHellmanClient(parameters=parameters)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
            server_socket.listen(1)
            print(f"Waiting for {peer_username} to connect on {host}:{port}...")
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")

                # Send the server's public key with a "KEY:" prefix
                serialized_public_key = client.serialize_public_key()
                conn.sendall(f"KEY:{serialized_public_key.decode()}".encode())

                # Receive and handle the client's public key
                peer_public_key_message = conn.recv(2048).decode()
                if peer_public_key_message.startswith("KEY:"):
                    peer_public_key_bytes = peer_public_key_message[4:].encode()
                    peer_public_key = client.deserialize_public_key(peer_public_key_bytes)
                    shared_secret = client.derive_shared_secret(peer_public_key)
                    print(f"Shared secret with {peer_username}: {shared_secret.hex()}")

                    # Signal key exchange completion
                    conn.sendall("KEY_EXCHANGE_DONE".encode())
                    confirmation = conn.recv(1024).decode()
                    if confirmation == "KEY_EXCHANGE_DONE":
                        print("Key exchange completed successfully. Starting chat.")
                        start_messaging(conn, peer_username)
                    else:
                        print("Failed to confirm key exchange.")
                else:
                    print("Expected public key but received something else.")
    except Exception as e:
        print(f"Error in P2P server: {e}")

def p2p_client(peer_ip, peer_port, peer_username, parameters):
    client = DiffieHellmanClient(parameters=parameters)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((peer_ip, peer_port))
            print(f"Connected to peer at {peer_ip}:{peer_port}")

            # Receive and handle the server's public key
            server_public_key_message = client_socket.recv(2048).decode()
            if server_public_key_message.startswith("KEY:"):
                server_public_key_bytes = server_public_key_message[4:].encode()
                peer_public_key = client.deserialize_public_key(server_public_key_bytes)
                shared_secret = client.derive_shared_secret(peer_public_key)
                print(f"Shared secret with {peer_username}: {shared_secret.hex()}")

                # Send the client's public key with a "KEY:" prefix
                serialized_public_key = client.serialize_public_key()
                client_socket.sendall(f"KEY:{serialized_public_key.decode()}".encode())

                # Signal key exchange completion
                client_socket.sendall("KEY_EXCHANGE_DONE".encode())

                # Wait for confirmation to proceed to messaging
                confirmation = client_socket.recv(1024).decode()
                if confirmation == "KEY_EXCHANGE_DONE":
                    print("Key exchange completed successfully. Starting chat.")
                    start_messaging(client_socket, peer_username)
                else:
                    print("Failed to confirm key exchange.")
            else:
                print("Expected public key but received something else.")
    except Exception as e:
        print(f"Error in P2P client: {e}")


def list_registered_clients(server_ip='127.0.0.1', server_port=5500):
    """Request and return the list of registered clients from the server."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, server_port))
            sock.sendall("QUERY\nLIST_CLIENTS".encode())
            clients_list = sock.recv(1024).decode().strip()
            print(f"Registered clients: {clients_list}")
            return clients_list.split(',') if clients_list else []
    except Exception as e:
        print(f"Error retrieving list of clients: {e}")
        return []

def message_sender(client_socket):
    """Continuously sends messages to the peer."""
    while True:
        message = input("You: ")
        if message.lower() == 'exit':
            print("Ending chat session.")
            client_socket.sendall("MSG:Peer has left the chat.".encode())
            client_socket.close()
            break
        try:
            client_socket.sendall(f"MSG:{message}".encode())
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def message_receiver(client_socket, peer_username):
    """Listens for messages from the peer and prints them, prompting the user input afterward."""
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message.startswith("MSG:"):
                print(f"\n{peer_username}: {message[4:]}\nYou: ", end="")
            elif message == "Peer has closed the connection.":
                print(message)
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def start_messaging(conn, peer_username):
    """Starts messaging by creating threads for receiving and sending messages using the existing connection."""
    print("Messaging session started. Type 'exit' to leave.")

    # Start receiving messages in a separate thread
    threading.Thread(target=message_receiver, args=(conn, peer_username), daemon=True).start()

    # Handle sending messages in the main thread
    message_sender(conn)


# Main client function
def start_client():
    try:
        username = input("Enter your username: ")
        ip = '127.0.0.1'
        
        # Automatically assigned port for P2P server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_socket:
            temp_socket.bind((ip, 0))
            port = temp_socket.getsockname()[1]

        # Load or generate shared DH parameters
        try:
            shared_parameters = load_dh_parameters()
            print("Loaded existing DH parameters.")
        except FileNotFoundError:
            shared_parameters = dh.generate_parameters(generator=2, key_size=2048)
            save_dh_parameters(shared_parameters)
            print("Generated and saved new DH parameters.")

        # Register the client with the server
        if not register_with_server(username, ip, port):
            print("Failed to register with the registry server. Exiting...")
            return

        # Query the server for registered clients
        registered_clients = list_registered_clients()
        if len(registered_clients) == 1:  # Only itself is registered
            print("No other clients are registered; starting as a P2P server.")
            time.sleep(0.1)  # Add a small delay
            peer_username = input("Enter peer's username for future connection: ")
            p2p_server(ip, port, peer_username, shared_parameters)
        else:  # Other clients are available
            print("Other clients found; connecting as a P2P client.")
            # Find a peer other than itself
            peer_username = next((client for client in registered_clients if client != username), None)
            if peer_username:
                peer_address = get_peer_address(peer_username, '127.0.0.1', 5500)
                if peer_address:
                    peer_ip, peer_port = peer_address
                    p2p_client(peer_ip, peer_port, peer_username, shared_parameters)  # Initiate P2P client
                else:
                    print("Failed to retrieve peer address.")
            else:
                print("No other clients to connect to.")
    except Exception as e:
        print(f"Error in client operation: {e}")


if __name__ == "__main__":
    start_client()