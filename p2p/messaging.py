import socket
import threading

from security.doubleRatchet import DoubleRatchet, decrypt, encrypt


# Sending "ratchet"
def message_sender(client_socket : socket.socket, user_ratchet : DoubleRatchet):
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
                # Generate new sending_chain_key
                user_ratchet.check_and_update_keys()
                message_key = user_ratchet.update_symmetric_ratchet_sending_chain()
                serialized_public_key = user_ratchet.serialize_public_key()
                client_socket.sendall(serialized_public_key)
                ciphertext = encrypt(message_key, message)
                client_socket.sendall(ciphertext)
            except Exception as e:
                print(f"Error sending message: {e}")
                break

# Receiving "ratchet"
def message_receiver(client_socket : socket.socket, peer_username, user_ratchet : DoubleRatchet):
    """Listens for messages from the peer and prints them, prompting the user input afterward."""
    while True:
        try:
            peer_public_key = client_socket.recv(1024)
            peer_public_key = user_ratchet.deserialize_public_key(peer_public_key)
            message = client_socket.recv(1024)
            user_ratchet.ratchet_step(peer_public_key)
            message_key = user_ratchet.update_symmetric_ratchet_receiving_chain()
            ciphertext = decrypt(message_key, message).decode()
            print(f"\n{peer_username}: {ciphertext}\nYou: ", end="")
            if message == "Peer has closed the connection.":
                print(message)
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def start_messaging(conn, peer_username, user_ratchet : DoubleRatchet):
    print("Messaging session started. Type 'exit' to leave.")

    threading.Thread(target=message_receiver, args=(conn, peer_username, user_ratchet), daemon=True).start()

    message_sender(conn, user_ratchet)
