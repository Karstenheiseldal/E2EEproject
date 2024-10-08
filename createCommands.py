def handle_command(client,message, clients, usernames):
    if message == 'count':
        userCount(client, clients)
    elif message == 'help':
        helpMessage(client)
    elif message == 'users':
        showUsers(client, usernames)
    elif message == 'clear':
        clearChat(client)
    else:
        client.send(f"Invalid command.".encode('utf-8'))

def userCount(client, clients):
    client.send(f"Number of users online: {len(clients)}".encode('utf-8'))

def showUsers(client, usernames):
    usr = ", ".join(usernames)
    client.send(f"Online users:\n{usr}".encode('utf-8'))

def clearChat(client):
    client.send(b'\033c')

def helpMessage(client):
    help_msg = b"Commands: \n/Count - for number of users in the chat\n/Users - for online users\n/Clear - for clearing chat\n"
    client.send(help_msg)