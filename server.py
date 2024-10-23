import os
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

clients = dict()
server_socket = None
shutdown_flag = False
client_sockets = []
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

def handle_client(client : socket.socket, client_username):
    global clients, client_sockets
    #while not shutdown_flag:
    while not shutdown_flag:
        try:
            client_message = client.recv(4096).decode()
            if client_message == "!get_users":
                response = ""
                for username, value in clients.items():
                    response += f"Username: {username}, Address: {value['address']} \n"
                # Send the response to the client
                client.send(response.encode())
            if client_message == "exit":
                print("Deleting client from the dictionary and closing the socket on server side.")
                del clients[client_username]
                client_sockets.remove(client)
                client.close()
                break
            # TODO: Figure out how we can compare the client, when client.close() calls . "if not client" does not work in this case.   
            if not client:
                del clients[client_username]
                client_sockets.remove(client)
                break
        except :
            del clients[client_username]
            client_sockets.remove(client)
            client.close()
            break

def listen_for_shutdown():
    global server_socket
    global shutdown_flag

    if os.getenv('TEST_MODE') == '1':
        return  # Skip the shutdown listener in test mode
    while True:
        command = input("")
        if command.lower() == 'shutdown':
            print("Shutting down the server...")
            shutdown_flag = True
            try:
                if server_socket:
                    server_socket.close()  # Close the server socket
                for socket in client_sockets:
                    print("Closing client sockets.")
                    socket.close()
                break
            except Exception as e:
                print(e)

def start_server(host='127.0.0.1', port=5500):
    global server_socket
    global shutdown_flag
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(2)
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    param_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )

    # Start the shutdown listener thread
    shutdown_thread = threading.Thread(target=listen_for_shutdown)
    shutdown_thread.start()
    print("Server is listening for connections...")
    try:
        while not shutdown_flag:
            try:
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
                handle_client_thread = threading.Thread(target=handle_client, args=(client, client_username))
                handle_client_thread.start()
                client_sockets.append(client)
            except OSError:
                print("Server socket has been closed.")
                break
    except Exception as e:
        print(f"An error occurred on the server side. {e}")

if __name__ == "__main__":
    start_server()
