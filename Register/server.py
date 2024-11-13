import os
import socket
import threading

import firebase_admin
from authentication import login_user, signup_user
from firebase_admin import credentials

clients = {}  # Dictionary to store client addresses {username: (ip, port)}
shutdown_flag = False

def listen_for_shutdown(server_socket : socket.socket):
    global shutdown_flag
    if os.getenv("TEST_MODE") == "1":
        # Skip listening for shutdown in test mode
        return
    while True:
        command = input("Type 'shutdown' to stop the server: ")
        if command.lower() == 'shutdown':
            print("Shutting down the server...")
            shutdown_flag = True
            if server_socket:
                server_socket.close()  # Close the server socket
            break

clients_lock = threading.Lock()

def handle_registration(data, client_socket : socket.socket):
    try:
        print(f"Received registration data: {data}")
        data_parts = data.split(',')
        if len(data_parts) == 3:
            username, ip, port = data_parts[0], data_parts[1], int(data_parts[2])
            with clients_lock:  # Use lock to ensure thread safety
                clients[username] = (ip, port)
            print(f"Registered {username} at {ip}:{port}")
            client_socket.sendall(b"Registration successful")
        else:
            client_socket.sendall(b"Invalid registration data")
    except Exception as e:
        print(f"Error during registration: {e}")

def handle_queries(data, client_socket : socket.socket):
    try:
        if shutdown_flag:
            client_socket.sendall(b"Server is shutting down.")
            return
        query = data.strip()
        print(f"Received query: '{query}'")

        if query == "LIST_CLIENTS":
            # Send a list of usernames currently registered
            client_list = ','.join(clients.keys())
            print(f"Sending list of registered clients: {client_list}")
            client_socket.sendall(client_list.encode())

        elif query.startswith("GET_PEER"):
            peer_username = query.split(' ')[1]
            print(f"Client is requesting address for peer: {peer_username}")

            if peer_username in clients:
                peer_ip, peer_port = clients[peer_username]
                response = f"{peer_ip},{peer_port}"
                print(f"Sending peer address: {response}")
                client_socket.sendall(response.encode())
            else:
                print(f"Peer {peer_username} not found")
                client_socket.sendall(b"Peer not found")
        elif query.startswith("REMOVE_USER"): # Removing user from the clients array after it exits
            username = query.split(' ')[1]
            del clients[username]
        else:
            client_socket.sendall(b"Unknown Query")
    except Exception as e:
        print(f"Error during query handling: {e}")

def handle_client(client_socket : socket.socket):
    try:
        if shutdown_flag:
            client_socket.sendall(b"Server is shutting down.")
            client_socket.close()
            return
        while True:  # Keep the connection open for multiple requests
            message = client_socket.recv(1024).decode().strip()
            if not message:  # If no message is received, break the loop
                break

            purpose, data = message.split('\n', 1)
            print(f"Connection purpose: {purpose}")

            if purpose == "REGISTER":
                data = data.split(',')
                username = data[0]
                password = data[1]
                ip = data[2]
                port = data[3]
                if signup_user(username, password, ip, port):
                    client_socket.sendall(b"Successful registration")
                else:
                    client_socket.sendall(b"Failed to register")
            elif purpose == "LOGIN":
                data = data.split(',')
                username = data[0]
                password = data[1]
                ip = data[2]
                port = data[3]
                if login_user(username, password, ip, port):
                    client_socket.sendall(b"Successful login")
                else:
                    client_socket.sendall(b"Failed to login")
            elif purpose == "QUERY":
                handle_queries(data, client_socket)
            else:
                print("Unknown connection purpose.")
                client_socket.sendall(b"Unknown connection purpose.")
    except Exception as e:
        print(f"Error in handle_client: {e}")
    finally:
        client_socket.close()

def start_server(host='127.0.0.1', port=5501):  #Changed port
    global shutdown_flag
    global server_socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((host, port))
            server_socket.listen(5)
            print(f"Server listening on {host}:{port}")
            # Start the shutdown listener thread
            shutdown_thread = threading.Thread(target=listen_for_shutdown, args=(server_socket,))
            shutdown_thread.start()

            while not shutdown_flag:
                try:
                    client_socket, addr = server_socket.accept()
                    print(f"Connection from {addr}")
                    threading.Thread(target=handle_client, args=(client_socket,)).start()
                except OSError as e:
                    if not shutdown_flag:
                        print(f"Error accepting connections: {e}")
                    break
        except Exception as e:
            print(f"Error starting server: {e}")

if __name__ == "__main__":
    cred = credentials.Certificate("./firebase-adminsdk.json")
    firebase_admin.initialize_app(cred, {
    "databaseURL": "https://advanced-project-25097-default-rtdb.europe-west1.firebasedatabase.app/:advanced_ruc_project"
    })
    start_server()
