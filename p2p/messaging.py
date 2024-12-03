import socket
import threading

from p2p.registerCommunication import list_registered_clients
from security.doubleratchet import encrypt, decrypt

def message_sender(client_socket : socket.socket, user_ratchet):
    """Continuously sends messages to the peer."""
    while True:
        message = input("You: ")
        message = message.encode()
        if message.lower() == 'exit':
            print("Ending chat session.")
            client_socket.sendall("MSG:Peer has left the chat.".encode())
            client_socket.close()
            break
        else:
            try:
                message_key = user_ratchet.get_message_key(is_sending=True)
                ciphertext = encrypt(message_key, message)
                print("Before sending cipher")
                print(ciphertext)
                print(type(ciphertext))
                client_socket.sendall(ciphertext)
            except Exception as e:
                print(f"Error sending message: {e}")
                break

def message_receiver(client_socket, peer_username, user_ratchet):
    """Listens for messages from the peer and prints them, prompting the user input afterward."""
    while True:
        try:
            message = client_socket.recv(1024)
            print("Before get_message")
            message_key = user_ratchet.get_message_key(is_sending=False)
            print("After get_message")
            ciphertext = decrypt(message_key, message)
            print(f"CipherText:{ciphertext}")
            print(f"\n{peer_username}: {ciphertext[4:]}\nYou: ", end="")
            if message == "Peer has closed the connection.":
                print(message)
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def start_messaging(conn, peer_username, user_ratchet):
    """Starts messaging by creating threads for receiving and sending messages using the existing connection."""
    print("Messaging session started. Type 'exit' to leave.")

    # Start receiving messages in a separate thread
    threading.Thread(target=message_receiver, args=(conn, peer_username, user_ratchet), daemon=True).start()

    # Handle sending messages in the main thread
    message_sender(conn, user_ratchet)
