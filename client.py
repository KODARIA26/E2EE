# Authors: Daria Kokin and Maor Shoval
# Description: The client script appears to implement a messaging application that communicates with a server.
# handles tasks such as registration, verification, key exchange,
# encryption/decryption of messages, and secure messaging.
# The client uses elliptic curve cryptography (via `cryptography.hazmat`) for secure communication.
# It also stores offline messages if a recipient is unavailable.
# Date: 30/12/2024

import socket
import json
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys


class MessagingClient:
    def __init__(self, host='127.0.0.1', port=8888):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((host, port))
            print(f"Connected to server at {host}:{port}")
        except ConnectionRefusedError:
            print("Could not connect to server. Is it running?")
            sys.exit()

        # Setup encryption
        self.reset_encryption_state()

        self.active = True
        self.contacts = {}  # {phone_number: {'name': name, 'online': True/False}}
        self.current_chat = None
        self.name = None
        self.phone = None
        self.shared_keys = {}  # {phone_number: shared_key}
        self.peer_public_keys = {}  # {phone_number: public_key}
        self.key_exchange_in_progress = False  # Add this new field

    def reset_encryption_state(self):
        """Reset all encryption related state"""
        self.shared_keys = {}
        self.peer_public_keys = {}
        self.key_exchange_in_progress = False
        # Generate new key pair
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("Generated new private/public key pair.")

    def generate_shared_key(self, peer_public_bytes):
        """Generate a shared key with a peer's public key"""
        try:
            peer_public_key = serialization.load_pem_public_key(
                peer_public_bytes.encode(),
                backend=default_backend()
            )
            shared_key = self.private_key.exchange(
                ec.ECDH(),
                peer_public_key
            )
            # Derive a key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)
            return derived_key
        except Exception as e:
            print(f"Error generating shared key: {e}")
            return None

    def encrypt_message(self, message, recipient_phone):
        """Encrypt a message for a specific recipient"""
        if recipient_phone not in self.shared_keys:
            print("No shared key for this recipient")
            return None

        try:
            key = self.shared_keys[recipient_phone][:16]  # Use first 16 bytes as AES key
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Pad message to be multiple of 16 bytes
            padded_message = message.encode()
            padding_length = 16 - (len(padded_message) % 16)
            padded_message += bytes([padding_length] * padding_length)

            # Encrypt
            ciphertext = encryptor.update(padded_message) + encryptor.finalize()

            # Convert to base64 for JSON serialization
            from base64 import b64encode
            encrypted_data = b64encode(iv + ciphertext).decode('utf-8')
            return encrypted_data
        except Exception as e:
            print(f"Error encrypting message: {e}")
            return None

    def decrypt_message(self, encrypted_data, sender_phone):
        """Decrypt a message from a specific sender"""
        if sender_phone not in self.shared_keys:
            print("No shared key for this sender")
            return None

        try:
            from base64 import b64decode
            # Convert from base64
            binary_data = b64decode(encrypted_data)

            key = self.shared_keys[sender_phone][:16]
            iv = binary_data[:16]
            ciphertext = binary_data[16:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt and unpad
            padded_message = decryptor.update(ciphertext) + decryptor.finalize()
            padding_length = padded_message[-1]
            message = padded_message[:-padding_length]
            return message.decode()
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return "Error: Could not decrypt message"

    def start_chat(self, recipient):
        """Initiate chat with key exchange"""
        if recipient not in self.contacts:
            print("User not found!")
            return False

        # Only initiate key exchange if we don't have a shared key and not already in progress
        if recipient not in self.shared_keys and not self.key_exchange_in_progress:
            self.key_exchange_in_progress = True
            try:
                send_message(self.socket, {
                    "type": "key_exchange",
                    "recipient": recipient,
                    "public_key": self.public_bytes.decode()
                })
                self.current_chat = recipient
                print(f"\nStarting chat with {self.contacts[recipient]['name']} ({recipient})")
                print("Initiating secure key exchange...")
                return True
            except Exception as e:
                print(f"Error starting chat: {e}")
                self.key_exchange_in_progress = False
                return False
        return True

    def handle_key_exchange(self, sender, sender_public_key):
        """Handle incoming key exchange request"""
        try:
            # Store peer's public key
            self.peer_public_keys[sender] = sender_public_key

            # Generate shared key
            shared_key = self.generate_shared_key(self.peer_public_keys[sender])
            if shared_key:
                self.shared_keys[sender] = shared_key
                self.key_exchange_in_progress = False
                print(f"\nSecure connection established with {self.contacts.get(sender, {'name': sender})['name']}")

                # If this is a response to our key exchange, we don't need to send back
                if self.current_chat == sender:
                    return

                # Send back our public key
                send_message(self.socket, {
                    "type": "key_exchange",
                    "recipient": sender,
                    "public_key": self.public_bytes.decode()
                })

        except Exception as e:
            print(f"Error in key exchange: {e}")
            self.key_exchange_in_progress = False

    def register_or_login(self):
        """Prompt the user to register or log in"""
        print("Welcome to the Messaging App!")
        while True:
            choice = input("Do you want to (1) Register or (2) Log in? Enter 1 or 2: ").strip()
            if choice == '1':
                self.register()
                break
            elif choice == '2':
                self.login()
                break
            else:
                print("Invalid choice. Please enter 1 or 2.")

    def register(self):
        """Register with the server"""
        while True:
            self.name = input("Enter your name: ").strip()
            if self.name:
                break
            print("Name cannot be empty")

        while True:
            self.phone = input("Enter your phone number: ").strip()
            if self.phone:
                break
            print("Phone number cannot be empty")

        registration = {
            "action": "register",
            "name": self.name,
            "phone": self.phone
        }
        print(f"Registering as {self.name} ({self.phone})")

        try:
            send_message(self.socket, registration)
            response = receive_message(self.socket)
            if not response:
                print("No response from server.")
                sys.exit()

            if response.get('status') == 'verification_code':
                print(f"{response['message']}{response['code']}")
                self.verify(response['code'])
            else:
                print(f"Registration error: {response.get('message', 'Unknown error')}")
                sys.exit()
        except Exception as e:
            print(f"Registration failed: {e}")
            sys.exit()

    def login(self):
        """Log in to the server"""
        while True:
            self.phone = input("Enter your registered phone number: ").strip()
            if self.phone:
                break
            print("Phone number cannot be empty")

        login_request = {
            "action": "login",
            "phone": self.phone
        }
        print(f"Logging in as {self.phone}")

        try:
            send_message(self.socket, login_request)
            response = receive_message(self.socket)
            if not response:
                print("No response from server.")
                sys.exit()

            if response.get('status') == 'verification_code':
                print(f"{response['message']}{response['code']}")
                self.verify(response['code'])
            else:
                print(f"Login error: {response.get('message', 'Unknown error')}")
                sys.exit()
        except Exception as e:
            print(f"Login failed: {e}")
            sys.exit()

    def verify(self, expected_code):
        """Verify registration or login with the provided code"""
        user_code = input("Enter the verification code shown above: ").strip()
        if user_code != expected_code:
            print("Incorrect verification code.")
            sys.exit()
        try:
            send_message(self.socket, {"code": user_code})
            response = receive_message(self.socket)
            if not response:
                print("No response from server.")
                sys.exit()

            if response['status'] == 'verified':
                self.name = response.get('name', 'Unknown')
                print(f"\nVerification successful! Welcome, {self.name}!")
                self.process_verification_response(response)
            else:
                print(f"Verification failed: {response.get('message', 'Unknown error')}")
                sys.exit()
        except Exception as e:
            print(f"Verification failed: {e}")
            sys.exit()

    def process_verification_response(self, response):
        """Process the server's response after verification/login"""
        # Reset encryption state on new login/registration
        self.reset_encryption_state()
        # Store contacts with their online status
        for client in response['clients']:
            self.contacts[client['phone']] = {
                'name': client['name'],
                'online': client['online']
            }

        # Start message receiving thread
        thread = threading.Thread(target=self.receive_messages)
        thread.daemon = True
        thread.start()

    def receive_messages(self):
        """Receive and handle incoming messages"""
        while self.active:
            try:
                message = receive_message(self.socket)

                if not message:
                    print("\nConnection closed by server.")
                    self.active = False
                    self.reset_encryption_state()  # Clear keys when connection is lost
                    break

                if message['type'] == 'key_exchange':
                    sender = message['sender']
                    sender_public_key = message['public_key']
                    self.handle_key_exchange(sender, sender_public_key)
                    continue

                elif message['type'] == 'message':
                    sender = message['sender']
                    sender_name = self.contacts.get(sender, {'name': 'Unknown'})['name']

                    # Only ask to start chat once if key not present
                    if sender not in self.shared_keys:
                        if not self.key_exchange_in_progress:
                            print(f"\nNo secure connection with {sender_name}. Establishing one now...")
                            self.start_chat(sender)
                        else:
                            print(f"\nStill establishing secure connection with {sender_name}...")
                        continue

                    content = message['content']
                    decrypted_content = self.decrypt_message(content, sender)
                    if self.current_chat and sender == self.current_chat:
                        print(f"\n{sender_name}: {decrypted_content}")
                    else:
                        print(f"\n[Message from {sender_name}]: {decrypted_content}")
                        print("\nEnter message (or 'menu' for options): ", end='')

                elif message['type'] == 'system':
                    print(f"\nSystem: {message['message']}")
                    # If user reconnects, remove their shared key to force new exchange
                    if "has reconnected" in message['message']:
                        parts = message['message'].split("User ")[1].split(" (")
                        phone = parts[1].split(")")[0]
                        if phone in self.shared_keys:
                            del self.shared_keys[phone]
                            del self.peer_public_keys[phone]
                    # Update contacts based on system messages
                    self.update_contacts_from_system_message(message['message'])

                elif message['type'] == 'offline_messages':
                    senders_without_key = set()
                    for msg in message['messages']:
                        sender = msg['sender']
                        if sender not in self.shared_keys:
                            senders_without_key.add(sender)
                        else:
                            decrypted = self.decrypt_message(msg['content'], sender)
                            print(f"\n[Offline from {self.contacts.get(sender, {'name': 'Unknown'})['name']}]: {decrypted}")

                    for sender in senders_without_key:
                        print(f"\nOffline message from {sender}, but no secure key.")
                        print("Starting new chat to initiate key exchange.")
                        self.start_chat(sender)

                    if senders_without_key:
                        print("\nPlease press '5' again after secure connections are established to decrypt offline messages.")

                if self.current_chat:
                    print("\nEnter message (or 'menu' for options): ", end='')

            except Exception as e:
                print(f"\nError receiving message: {e}")
                self.active = False
                break

    def update_contacts_from_system_message(self, system_message):
        """Update contacts based on system messages"""
        if "has joined" in system_message or "has reconnected" in system_message:
            parts = system_message.split("User ")[1].split(" (")
            name = parts[0]
            phone = parts[1].split(")")[0]
            self.contacts[phone] = {'name': name, 'online': True}
        elif "has disconnected" in system_message:
            parts = system_message.split("User ")[1].split(" (")
            name = parts[0]
            phone = parts[1].split(")")[0]
            if phone in self.contacts:
                self.contacts[phone]['online'] = False

    def send_message(self, message):
        """Send an encrypted message to the current chat recipient"""
        if not self.current_chat:
            print("No active chat selected")
            return

        if not message.strip():
            return

        # Check if we have a shared key
        if self.current_chat not in self.shared_keys:
            if self.key_exchange_in_progress:
                print("Waiting for secure connection to be established...")
                return
            if not self.start_chat(self.current_chat):
                return
            print("Waiting for secure connection to be established...")
            return

        encrypted_message = self.encrypt_message(message, self.current_chat)
        if encrypted_message is None:
            return
        print(f"Sending message to {self.current_chat}: {message}")  # Debug sending message logic

        try:
            send_message(self.socket, {
                "type": "message",
                "recipient": self.current_chat,
                "content": encrypted_message
            })
        except Exception as e:
            print(f"Failed to send message: {e}")
            self.active = False

    def show_menu(self):
        """Display the main menu"""
        print("\n=== Menu ===")
        print("1. Show contacts")
        print("2. Start new chat")
        print("3. Exit current chat")
        print("4. Exit application")
        print("5. Fetch offline messages")
        print("============")

    def show_contacts(self):
        """Display list of contacts with their online status"""
        print("\nContacts:")
        for phone, info in self.contacts.items():
            status = "Online" if info['online'] else "Offline"
            print(f"- {info['name']} ({phone}) - {status}")

    def main_menu_choice(self, choice):
        """Handle main menu choices""" 
        if choice == '1':
            self.show_contacts()
        elif choice == '2':
            self.show_contacts()
            recipient = input("\nEnter recipient's phone number: ").strip()
            if recipient in self.contacts:
                self.current_chat = recipient
                print(f"\nStarting chat with {self.contacts[recipient]['name']} ({recipient})")
                print("Type 'menu' to see options")
                self.start_chat(recipient)
            else:
                print("\nUser not found!")
        elif choice == '3':
            if self.current_chat:
                print(f"\nExiting chat with {self.contacts[self.current_chat]['name']}")
                self.current_chat = None
            else:
                print("\nNo active chat to exit.")
        elif choice == '4':
            print("\nExiting Application Goodbye.")
            self.active = False
        elif choice == '5':
            send_message(self.socket, {"type": "fetch_offline_messages"})
        else:
            print("Invalid choice.")

    def cleanup(self):
        """Clean up resources before exiting"""
        self.active = False
        try:
            send_message(self.socket, {"type": "exit"})
        except:
            pass
        self.socket.close()


# Utility functions for sending and receiving messages with length-prefix framing

def send_message(conn, message_dict):
    message_json = json.dumps(message_dict)
    message_bytes = message_json.encode()
    message_length = len(message_bytes)
    length_header = f"{message_length:<10}".encode()  # Fixed 10-byte header
    conn.sendall(length_header + message_bytes)


def receive_message(conn):
    # Read the 10-byte length header
    length_header = b''
    while len(length_header) < 10:
        try:
            chunk = conn.recv(10 - len(length_header))
            if not chunk:
                return None  # Connection closed
            length_header += chunk
        except socket.timeout:
            return None

    try:
        message_length = int(length_header.strip())
    except ValueError:
        print("Invalid length header received.")
        return None

    # Read the actual message
    message_bytes = b''
    while len(message_bytes) < message_length:
        try:
            chunk = conn.recv(message_length - len(message_bytes))
            if not chunk:
                return None  # Connection closed or incomplete data
            message_bytes += chunk
        except socket.timeout:
            return None

    message_json = message_bytes.decode()
    try:
        message_dict = json.loads(message_json)
        return message_dict
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return None


def main():
    client = MessagingClient()
    client.register_or_login()

    print("\nChat session started!")
    print("Type 'menu' at any time to show options")
    print("----------------------------------------")

    try:
        while client.active:
            if not client.current_chat:
                client.show_menu()
                choice = input("\nEnter choice (1-5): ").strip()  # Changed from 1-4 to 1-5
                client.main_menu_choice(choice)
            else:
                message = input("\nEnter message (or 'menu' for options): ").strip()
                if message.lower() == 'menu':
                    client.show_menu()
                    choice = input("\nEnter choice (1-5): ").strip()  # Changed from 1-4 to 1-5
                    client.main_menu_choice(choice)
                else:
                    client.send_message(message)

    except KeyboardInterrupt:
        print("\nExiting chat...")
    finally:
        client.cleanup()

    print("\nChat session ended.")


if __name__ == "__main__":
    main()