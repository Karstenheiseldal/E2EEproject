import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

clients = dict()

"""
def handle_client(conn, peer_conn):
    #Thread function to relay messages between clients.
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
"""
"""
def receive_with_length_prefix(conn):
    # Helper function to receive data with a length prefix.
    data_length = int.from_bytes(conn.recv(4), 'big')
    data = b""
    while len(data) < data_length:
        packet = conn.recv(data_length - len(data))
        if not packet:
            raise ValueError("Connection closed before all data received.")
        data += packet
    return data
"""

def send_with_length_prefix(conn, data):
    """Helper function to send data with a length prefix."""
    data_length = len(data).to_bytes(4, 'big')
    conn.sendall(data_length + data)

def get_connections(client : socket.socket, clients : dict):
    while True:
        client_message = client.recv(4096).decode()
        if client_message == "!get_users":
            response = ""
            for username, value in clients.items():
                response += f"Username: {username}, Address: {value['address']} \n"
            # Send the response to the client
            client.send(response.encode())

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

        while True:
            client, address = server_socket.accept()
            print(f"User connected from {address}")
            print(f"Participants: {len(clients)+1}")
            client_username = client.recv(4096).decode()
            print(f"Username of the client:{client_username}")
            send_with_length_prefix(client, param_bytes)
            client_public_key = client.recv(4096).decode()
            clients[client_username] = {
                "address" : address,
                "public_key" : client_public_key
            }
            handle_client_thread = threading.Thread(target=get_connections, args=(client, clients))
            handle_client_thread.start()

if __name__ == "__main__":
    start_server()
