# End-to-End Encryption Project

## Introduction
Creating a simple messenger app in python for demonstrative purposes. We will try to implement end to end encryption with Signal protocol using extended triple diffie-helman (X3DH) and double ratchet algorithm.

## Depedencies
Python 3.10.x \
Pip 24.2

### Libraries
In requirements.txt

NB Remember to have Python in PATH and pip installed

## How to run
```
   git clone <project's url>
   cd to the project's directory
   Create a .venv / use your own interpreter
   pip install -r path/to/requirements.txt
   First start the server:
   python server.py
   Then start 1 or more clients:
   python client.py
```
## Naming Conventions
For the sake of sanity, and so much more, lets keep these naming conventions when we are coding.

1. **Variables**
   - Use camelCase for all variable names.
   - Example: `userCount`, `totalPrice`, `maxHeight`

2. **Functions and Methods**
   - Use camelCase for function and method names.
   - Example: `calculateTotal()`, `sendMessage()`, `updateUserStatus()`

3. **Classes**
   - Use PascalCase for class names (first letter of each word capitalized).
   - Example: `UserProfile`, `DataProcessor`, `EncryptionService`

4. **Constants**
   - Use ALL_CAPS with underscores to separate words for constants.
   - Example: `MAX_CONNECTIONS`, `DEFAULT_TIMEOUT`, `API_KEY`

5. **File Names**
   - Use camelCase for file names, keeping them descriptive and concise.
   - Example: `userProfile.js`, `dataProcessor.py`, `encryptionService.cs`

6. **Interfaces (if applicable)**
   - Use PascalCase with a prefix like "I" for interfaces (if applicable).
   - Example: `IUser`, `IDataProcessor`

7. **Modules and Packages**
   - Use lowercase for module and package names, with no underscores or hyphens.
   - Example: `userprofile`, `dataprocessor`, `encryptionservice`

8. **Global Variables (if applicable)**
   - Avoid using global variables. If necessary, use camelCase with a clear, descriptive name.
   - Example: `globalSettings`, `sharedData`

9. **Test Methods**
   - Use camelCase prefixed with `test` for test method names.
   - Example: `testUserLogin()`, `testEncryptionProcess()`


 ## Requirements
**End-to-End Encryption (E2EE):** Ensure only clients can decrypt messages, protecting the content from the server and other unauthorized access.

**AES-128 Encryption for Messages:** Secure message contents using AES-128 encryption, where encryption keys are shared exclusively between communicating clients.

**Signal Protocol:** Implement the Signal Protocol to enable asynchronous and secure messaging, supporting robust encryption and communication between online and offline clients.

**Double Ratchet Algorithm:** Use the Double Ratchet algorithm to rotate encryption keys with each message, maintaining forward secrecy and integrity across all interactions.

**Diffie-Hellman Key Exchange:** Use the standard Diffie-Hellman key exchange to establish shared encryption keys over the network securely, ensuring confidentiality during the initial handshake.

(Optional) **Secure Group Chat Support:** Extend encryption capabilities to include group chats, allowing multiple clients to securely exchange messages within a single, private conversation.

**Perfect Forward Secrecy (PFS):** Guarantee that each session uses unique encryption keys, so past communications remain secure even if future keys are compromised.

**User Authentication with RSA:** Use RSA for user identity verification, establishing trust between clients during initial connections and prior to setting up encrypted sessions.

**Command-Line Interface (CLI):** Build a clear, user-friendly CLI for both client and server interactions, enabling users to connect, send messages, and view chat history in the terminal.

**Server-Facilitated Communication:** Have the server handle client connections and message routing while enforcing E2EE, ensuring it cannot access message content directly.
