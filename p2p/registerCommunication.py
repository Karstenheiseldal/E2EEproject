import socket


def list_registered_clients(client_socket : socket.socket):
    """Request and return the list of registered clients from the server."""
    try:
        client_socket.sendall("QUERY\nLIST_CLIENTS".encode())
        clients_list = client_socket.recv(4096).decode()
        return clients_list if clients_list else []
    except Exception as e:
        print(f"Error retrieving list of clients: {e}")
        return []

def get_peer_address(peer_username, client_socket : socket.socket):
    try:
        query = f"QUERY\nGET_PEER {peer_username}"
        print(f"Requesting address for peer: {peer_username}")
        client_socket.sendall(query.encode())
        peer_address = client_socket.recv(1024).decode()
        # Check if peer address is properly formatted or if the peer is not found
        if peer_address == "Peer not found":
            print("Peer not found.")
            return None
        # Ensure we have both an IP and port returned
        print(f"Received peer address: {peer_address}")
        ip, port = peer_address.split(',')
        print(f"IP, PORT: {ip}, {port}")
        return ip, int(port)  # Return the peer's IP and port
    except Exception as e:
        print(f"Error retrieving peer address: {e}")
        return None
