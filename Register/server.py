import socket
import threading

clients = {}  # Dictionary to store client addresses {username: (ip, port)}
shutdown_flag = False

def listen_for_shutdown(server_socket):
    global shutdown_flag
    while True:
        command = input("")
        if command.lower() == 'shutdown':
            print("Shutting down the server...")
            shutdown_flag = True
            if server_socket:
                server_socket.close()  # Close the server socket
            break

def handle_registration(data, client_socket):
    try:
        print(f"Received registration data: {data}")

        data_parts = data.split(',')
        if len(data_parts) == 3:
            username, ip, port = data_parts[0], data_parts[1], int(data_parts[2])
            clients[username] = (ip, port)
            print(f"Registered {username} at {ip}:{port}")
            client_socket.send(b"Registration successful")
        else:
            client_socket.send(b"Invalid registration data")
    except Exception as e:
        print(f"Error during registration: {e}")
    finally:
        client_socket.close()

def handle_queries(data, client_socket):
    try:
        if shutdown_flag:
            client_socket.send(b"Server is shutting down.")
            return
        
        query = data.strip()
        print(f"Received query: '{query}'")

        if query == "LIST_CLIENTS":
            # Send a list of usernames currently registered
            client_list = ','.join(clients.keys())
            print(f"Sending list of registered clients: {client_list}")
            client_socket.send(client_list.encode())

        elif query.startswith("GET_PEER"):
            peer_username = query.split(' ')[1]
            print(f"Client is requesting address for peer: {peer_username}")

            if peer_username in clients:
                peer_ip, peer_port = clients[peer_username]
                response = f"{peer_ip},{peer_port}"
                print(f"Sending peer address: {response}")
                client_socket.send(response.encode())
            else:
                print(f"Peer {peer_username} not found")
                client_socket.send(b"Peer not found")
    except Exception as e:
        print(f"Error during query handling: {e}")
    finally:
        client_socket.close()

def handle_client(client_socket):
    try:
        if shutdown_flag:
            client_socket.send(b"Server is shutting down.")
            client_socket.close()
            return
        
        # Receive the purpose and data in one message, split by newline
        message = client_socket.recv(1024).decode().strip()
        purpose, data = message.split('\n', 1)
        print(f"Connection purpose: {purpose}")

        if purpose == "REGISTER":
            handle_registration(data, client_socket)  # Pass both data and client_socket
        elif purpose == "QUERY":
            handle_queries(data, client_socket)       # Pass both data and client_socket
        else:
            print("Unknown connection purpose.")
            client_socket.send(b"Unknown connection purpose.")
    except Exception as e:
        print(f"Error in handle_client: {e}")
    finally:
        client_socket.close()

def start_server(host='127.0.0.1', port=5500):
    global shutdown_flag
    global server_socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
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
            except OSError:
                break
        shutdown_thread.join()

if __name__ == "__main__":
    start_server()
