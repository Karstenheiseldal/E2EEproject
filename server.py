import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

usernames = {}
clients = {}
public_keys = {}

def handle_client(conn, peer_conn):
    """Thread function to relay messages between clients."""
    try:
        while True:
            # Receive the message length first
            message_length_data = conn.recv(4)
            if not message_length_data:
                print("Client disconnected.")
                break
            
            
            message_length = int.from_bytes(message_length_data, 'big')
            print(f"Relaying message from {usernames[conn]} to {usernames[peer_conn]}")
            
            # Receive the full message based on the specified length
            message = b""
            while len(message) < message_length:
                packet = conn.recv(message_length - len(message))
                if not packet:
                    raise ValueError("Connection closed before all data received.")
                message += packet

            # Forward the message with its length prefix to the peer
            peer_conn.sendall(message_length_data + message)  # Ensure length prefix is included

    except Exception as e:
        print(f"Error relaying message: {e}")
    finally:
        conn.close()

def send_with_length_prefix(conn, data):
    """Helper function to send data with a length prefix."""
    data_length = len(data).to_bytes(4, 'big')
    conn.sendall(data_length + data)

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

def start_server(host='127.0.0.1', port=5500):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(2)
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        param_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        print("Server is listening for connections...")

        # Accept connections from Client 1 and Client 2
        conn1, addr1 = server_socket.accept()
        print(f"Connected to Client 1: {addr1}")
        conn2, addr2 = server_socket.accept()
        print(f"Connected to Client 2: {addr2}")

        # Step 1: Receive usernames from both clients and store them in the dictionaries
        username1 = conn1.recv(4096).decode()
        usernames[conn1] = username1
        clients[username1] = conn1
        print(f"Client 1 username: {username1}")

        username2 = conn2.recv(4096).decode()
        usernames[conn2] = username2
        clients[username2] = conn2
        print(f"Client 2 username: {username2}")

        # Step 2: Send DH parameters to both clients
        send_with_length_prefix(conn1, param_bytes)
        send_with_length_prefix(conn2, param_bytes)

        # Step 3: Receive public keys from both clients
        client1_public_key = receive_with_length_prefix(conn1)
        public_keys[username1] = client1_public_key
        print(f"Received public key from {username1}")  # Debug

        client2_public_key = receive_with_length_prefix(conn2)
        public_keys[username2] = client2_public_key
        print(f"Received public key from {username2}")  # Debug

        # Step 4: Relay public keys
        send_with_length_prefix(conn1, public_keys[username2])  # Send Client 2's public key to Client 1
        send_with_length_prefix(conn2, public_keys[username1])  # Send Client 1's public key to Client 2
        print("Public keys exchanged between clients.")

        # Step 5: Notify both clients that they are ready to communicate
        conn1.sendall(b"READY")
        conn2.sendall(b"READY")
        print("Clients notified that they are ready to communicate.")

        # Start threads for message relaying
        client1_thread = threading.Thread(target=handle_client, args=(conn1, conn2))
        client2_thread = threading.Thread(target=handle_client, args=(conn2, conn1))

        client1_thread.start()
        client2_thread.start()

        try:
            client1_thread.join()
            client2_thread.join()
        except KeyboardInterrupt:
            print("Server shutting down due to KeyboardInterrupt.")
            server_socket.close()
        print("Server shutting down...")

if __name__ == "__main__":
    start_server()
