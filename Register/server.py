import os
import socket
import threading

import firebase_admin
from firebase_admin import credentials
from firebase_functions import get_users, login_user, signup_user, fetch_key, fetch_and_decrypt_message, send_encrypted_message
from security.doubleratchet import initialize_session
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

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

def handle_queries(data, client_socket : socket.socket):
    try:
        if shutdown_flag:
            client_socket.sendall(b"Server is shutting down.")
            return
        query = data.strip()
        print(f"Received query: '{query}'")

        if query == "LIST_CLIENTS":
            # Send a list of usernames currently registered
            users = get_users()
            users = ','.join(users)
            client_socket.sendall(users.encode())

        elif query.startswith("GET_PEER"):
            peer_username = query.split(' ')[1]
            print(f"Client is requesting address for peer: {peer_username}")
            users = get_users()
            print(users)
            print(users[peer_username].values())
            if peer_username in users.keys():
                peer_ip, password, peer_port = users[peer_username].values()
                response = f"{peer_ip},{peer_port}"
                print(f"Sending peer address: {response}")
                client_socket.sendall(response.encode())
            else:
                print(f"Peer {peer_username} not found")
                client_socket.sendall(b"Peer not found")
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
                username, password, ip, port = data.split(',')
                if signup_user(username, password, ip, port):
                    client_socket.sendall(b"Successful registration")
                else:
                    client_socket.sendall(b"Failed to register")
            elif purpose == "LOGIN":
                username, password, ip, port = data.split(',')
                if login_user(username, password, ip, port):
                    client_socket.sendall(b"Successful login")
                else:
                    client_socket.sendall(b"Failed to login")
            elif purpose == "INIT_SESSION":
                sender_private_key = X25519PrivateKey.generate()
                sender, receiver = data.split(",")
                receiver_keys = fetch_key(receiver)
                session_state = initialize_session(sender_private_key, {
                    "identity_key": X25519PublicKey.from_public_bytes(receiver_keys["identity_key"]),
                    "signed_pre_key": X25519PublicKey.from_public_bytes(receiver_keys["signed_pre_key"]),
                    })
                client_socket.sendall(f"Session initialized with {receiver}".encode())
            elif purpose == "SEND_MESSAGE":
                sender, receiver, plaintext = data.split(",", 2)
                send_encrypted_message(sender, receiver, plaintext, session_state)
                client_socket.sendall(b"Message sent")
            elif purpose == "FETCH_MESSAGE":
                username = data.strip()
                fetch_and_decrypt_message(username, session_state)
                client_socket.sendall(b"Messages fetched and processed")
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
