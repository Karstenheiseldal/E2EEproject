import socket
import threading

from registerCommunication import list_registered_clients


def message_sender(client_socket : socket.socket):
    """Continuously sends messages to the peer."""
    while True:
        message = input("You: ")
        if message.lower() == 'exit':
            print("Ending chat session.")
            client_socket.sendall("MSG:Peer has left the chat.".encode())
            client_socket.close()
            break
        # TODO: Do we need this? For connection we need to break the current session. The only purpose of this could be to show the users of the current session.
        elif message.lower() == '!getusers':
            # Request the user list from the registry server without disrupting the main chat
            registered_clients = list_registered_clients()
            if registered_clients:
                print("Currently registered clients:", ", ".join(registered_clients))
            else:
                print("No other registered clients found.")
        else:
            try:
                client_socket.sendall(f"MSG:{message}".encode())
            except Exception as e:
                print(f"Error sending message: {e}")
                break

def message_receiver(client_socket, peer_username):
    """Listens for messages from the peer and prints them, prompting the user input afterward."""
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message.startswith("MSG:"):
                print(f"\n{peer_username}: {message[4:]}\nYou: ", end="")
            elif message == "Peer has closed the connection.":
                print(message)
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def start_messaging(conn, peer_username):
    """Starts messaging by creating threads for receiving and sending messages using the existing connection."""
    print("Messaging session started. Type 'exit' to leave.")

    # Start receiving messages in a separate thread
    threading.Thread(target=message_receiver, args=(conn, peer_username), daemon=True).start()

    # Handle sending messages in the main thread
    message_sender(conn)
