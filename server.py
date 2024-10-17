import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

shutdown_flag = False

def handle_client(conn, peer_conn):
    """Thread function to relay messages between clients."""
    try:
        while not shutdown_flag:
            # Receive message from client
            message = conn.recv(4096)
            if not message:
                print("Client disconnected.")
                break

            # Relay the message to the peer client
            peer_conn.sendall(message)
            print("Message relayed to peer client.")
    except Exception as e:
        print(f"Error relaying message: {e}")
    finally:
        conn.close()

# Start server function
def start_server(host = '127.0.0.1', port = 5500):
    global shutdown_flag
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(2)
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        param_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        print("Server is listening for connections...")
        conn1, addr1 = server_socket.accept()
        print(f"Connected to Client 1: {addr1}")
        conn2, addr2 = server_socket.accept()
        print(f"Connected to Client 2: {addr2}")

        # Send DH parameters to both clients
        conn1.sendall(param_bytes)
        conn2.sendall(param_bytes)

        client1_public_key = conn1.recv(4096)  # Receive Client 1 public key
        client2_public_key = conn2.recv(4096)  # Receive Client 2 public key

        # Relay public keys
        conn1.sendall(client2_public_key)  # Send Client 2 public key to Client 1
        conn2.sendall(client1_public_key)  # Send Client 1 public key to Client 2

        # Start a thread to handle each client
        client1_thread = threading.Thread(target=handle_client, args=(conn1, conn2))
        client2_thread = threading.Thread(target=handle_client, args=(conn2, conn1))

        client1_thread.start()
        client2_thread.start()

        try:
            # Wait for both threads to complete or server shutdown
            client1_thread.join()
            client2_thread.join()
        except KeyboardInterrupt:
            print("Server shutting down due to KeyboardInterrupt.")
            shutdown_server(server_socket, [conn1, conn2])
        print("Server shutting down...")

def shutdown_server(server_socket, connections):
    """Shut down the server and close all connections."""
    global shutdown_flag
    shutdown_flag = True
    print("Shutting down server...")

    # Close client connections
    for conn in connections:
        try:
            conn.close()
        except Exception as e:
            print(f"Error closing connection: {e}")

    # Close the server socket
    try:
        server_socket.close()
        print("Server socket closed.")
    except Exception as e:
        print(f"Error closing server socket: {e}")

if __name__ == "__main__":
    start_server()
