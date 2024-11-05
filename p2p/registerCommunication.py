import socket

def list_registered_clients(server_ip='127.0.0.1', server_port=5501):
    """Request and return the list of registered clients from the server."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, server_port))
            sock.sendall("QUERY\nLIST_CLIENTS".encode())
            clients_list = sock.recv(1024).decode().strip()
            return clients_list.split(',') if clients_list else []
    except Exception as e:
        print(f"Error retrieving list of clients: {e}")
        return []
    
    # Register client with the registry server
def register_with_server(username, ip, port, server_ip='127.0.0.1', server_port=5501):
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
    
def get_peer_address(peer_username, server_ip='127.0.0.1', server_port=5501):
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
