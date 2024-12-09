# End-to-End Encryption Project

## Introduction
Creating a simple messenger app in python for demonstrative purposes. We will try to implement end to end encryption with Signal protocol using diffie-hellman and double ratchet algorithm.

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
   First start the server from root:
   python -m register.server
   Then start the clients from root:
   python -m p2p.client
```
## Naming Conventions
For the sake of sanity, and so much more, lets keep these naming conventions when we are coding.

1. **Variables**
   - Use snake_case for all variable names.
   - Example: `public_key`, `private_key`, `shared_secret`

2. **Functions and Methods**
   - Use snake_case for function and method names.
   - Example: `serialize_public_key()`, `deserialize_public_key()`, `update_symmetric_ratchet_receiving_chain()`

3. **Classes**
   - Use CamelCase for class names (first letter of each word capitalized).
   - Example: `DoubleRatchet`, `DataProcessor`, `Client`

4. **Constants**
   - Use ALL_CAPS with underscores to separate words for constants.
   - Example: `MAX_CONNECTIONS`, `DEFAULT_TIMEOUT`

5. **File Names**
   - Use camelCase for file names, keeping them descriptive and concise.
   - Example: `doubleRatchet.py`, `registerCommunication.py`, `firebaseFunctions.py`

6. **Test Methods**
   - Use snake_case prefixed with `test` for test method names.
   - Example: `test_user_login()`, `test_encryption_process()`


## Requirements
**End-to-End Encryption (E2EE):** Ensure only clients can decrypt messages, protecting the content from the server and other unauthorized access.

**AES-128 Encryption for Messages:** Secure message contents using AES-128 encryption, where encryption keys are shared exclusively between communicating clients.

**Signal Protocol:** Implement the Signal Protocol to enable asynchronous and secure messaging, supporting robust encryption and communication between online clients.

**Double Ratchet Algorithm:** Use the Double Ratchet algorithm to rotate encryption keys with each (or more) message, maintaining forward secrecy and integrity across all interactions.

**Diffie-Hellman Key Exchange:** Use the standard Diffie-Hellman key exchange to establish shared encryption over the network securely, ensuring confidentiality during the initial handshake.

**Perfect Forward Secrecy (PFS):** Guarantee that each session uses unique encryption keys, so past communications remain secure even if future keys are compromised.

**Command-Line Interface (CLI):** Build a clear, user-friendly CLI for both client and server interactions, enabling users to connect, send messages in the terminal.

**Server-Facilitated Communication:** Have the server handle client connections and message routing while enforcing E2EE, ensuring it cannot access message content directly.
