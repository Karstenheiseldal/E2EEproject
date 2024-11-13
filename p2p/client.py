import socket

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from messaging import start_messaging
from registerCommunication import get_peer_address, list_registered_clients


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
            info=b'handshake data')
        return hkdf.derive(shared_key)

#This modified exception is meant to help the connect or wait method    
class ConnectionRefusedError(Exception):
    """Exception raised when a P2P connection is refused."""
    pass

# Peer-to-peer server that listens for a connection. A new socket therefore have to be made.
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

                    # Send key exchange completion
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

#This is the client connecting to a peer listening at their port
def p2p_client( peer_ip, peer_port, peer_username, parameters):
    client = DiffieHellmanClient(parameters=parameters)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket: #Creates a new socket for p2p comunication as a client
            client_socket.connect((peer_ip, peer_port)) #Attempting to connect with the peer server.

            # Receive and handle the server peer's public key
            server_public_key_message = client_socket.recv(2048).decode()
            if server_public_key_message.startswith("KEY:"):
                server_public_key_bytes = server_public_key_message[4:].encode()
                peer_public_key = client.deserialize_public_key(server_public_key_bytes)
                shared_secret = client.derive_shared_secret(peer_public_key)
                print(f"Shared secret with {peer_username}: {shared_secret.hex()}")

                # Send the client's public key with a "KEY:" prefix
                serialized_public_key = client.serialize_public_key()
                client_socket.sendall(f"KEY:{serialized_public_key.decode()}".encode())

                # Send key exchange completion
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
    except OSError as e:
        if e.errno == 10061:
            raise ConnectionRefusedError(f"Connection to {peer_username} was refused.")
        else:
            print(f"Error in P2P client: {e}")


# Attempt to connect to a peer, and if unsuccessful, act as a server and wait for a connection
def connect_to_peer_or_wait(username, peer_username, ip, port, shared_parameters):
    """Attempt to connect to the peer as client; if unavailable, switch to server mode and wait."""
    peer_address = get_peer_address(peer_username, '127.0.0.1', 5501)
    
    if peer_address:
        peer_ip, peer_port = peer_address

        print(f"{username} will first try to act as the client and connect to {peer_username}.")
        
        try:
            # Pass shared_parameters when calling p2p_client
            p2p_client(peer_ip, peer_port, peer_username, shared_parameters)
        except ConnectionRefusedError:
            print(f"Switching {username} to server mode to wait for {peer_username} to connect.")
            p2p_server(ip, port, peer_username, shared_parameters)
        except Exception as e:
            print(f"Unexpected error: {e}")
    else:
        print(f"User {peer_username} is offline or unavailable.")

def main_menu(ip, port, shared_parameters, client_socket : socket.socket, logged_in):
    """Main menu allowing the user to list clients or initiate a chat."""
    if logged_in:
        while True:
            print("\nOptions:")
            print("1. List registered users")
            print("2. Connect to a user")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                # Get and display a list of registered (online) users
                registered_clients = list_registered_clients(client_socket)
                if registered_clients:
                    print(f"Registered Users: {registered_clients}")
                else:
                    print("No users are online.")

            elif choice == '2':
                # Allow the user to choose a peer and handle role-switching dynamically
                peer_username = input("Enter the username of the person you want to chat with: ")
                if peer_username and peer_username != username:
                    connect_to_peer_or_wait(username, peer_username, ip, port, shared_parameters)
                else:
                    print("Invalid username or you cannot chat with yourself.")

            elif choice == '3':
                print("Exiting...")
                client_socket.sendall(f"QUERY\nREMOVE_USER {username}".encode())
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    else:
        while True:
            print("\nOptions:")
            print("1. Login")
            print("2. Register")
            print("3. Exit")
            choice = input("Enter your choice: ")
            if choice == '1':
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                login_data = f"LOGIN\n{username},{password},{ip},{port}"
                client_socket.sendall(login_data.encode())
                result = client_socket.recv(1024).decode()
                if result == "Successful login":
                    main_menu(ip, port, shared_parameters, client_socket, logged_in=True)
                elif result == "Failed to login":
                    print("Failed to login, please try again")
            if choice == '2':
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                registration_data = f"REGISTER\n{username},{password},{ip},{port}"
                client_socket.sendall(registration_data.encode())
                result = client_socket.recv(1024).decode()
                print(f"RESULT: {result}")
                if result == "Successful registration":
                    main_menu(ip, port, shared_parameters, client_socket, logged_in=True)
                elif result == "Failed to register":
                    print("Failed to register, please try again")
            if choice == '3':
                print("Exiting...")
                client_socket.close()
                break

def load_or_generate_shared_DH_parameters():
        try:
            shared_parameters = load_dh_parameters()
            print("Loaded existing DH parameters.")
        except FileNotFoundError:
            shared_parameters = dh.generate_parameters(generator=2, key_size=2048)
            save_dh_parameters(shared_parameters)
            print("Generated and saved new DH parameters.")
            return shared_parameters
        return shared_parameters

# Main client starting function
def start_client():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip = '127.0.0.1'
        client_socket.connect((ip, 5501))
        port = client_socket.getsockname()[1]
        # Load or generate shared DH parameters

        # Register the client with the server
        #if not register_with_server(username, ip, port):
        #    print("Failed to register with the registry server. Exiting...")
        #    return
        shared_parameters = load_or_generate_shared_DH_parameters()
        # Start the main menu
        main_menu(ip, port, shared_parameters, client_socket, logged_in = False)
        client_socket.close()

    except Exception as e:
        print(f"Error in client operation: {e}")


if __name__ == "__main__":
    start_client()