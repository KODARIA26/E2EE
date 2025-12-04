# Authors: Daria Kokin and Maor Shoval
# Description:  The server script handles client connections,
# authenticates users via phone numbers, and facilitates message exchange between clients.
# It also stores offline messages if a recipient is unavailable.
# Date: 30/12/2024

import socket
import threading
import json
import random


class MessagingServer:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(10)

        self.clients = {}  # {phone_number: client_data}
        # client_data: {'connection': conn, 'address': addr, 'name': name, 'online': True/False}
        self.registered_clients = {}  # {phone_number: {'name': name}}
        self.verification_codes = {}  # {phone_number: code}
        self.offline_messages = {}  # {recipient_phone: [messages]}
        print(f"Server initialized on {host}:{port}")

    def sendBySecureChannel(self):
        """Generate a 6-digit verification code"""
        code = str(random.randint(100000, 999999))
        return code

    def broadcast_user_status(self, user_phone, message):
        """Notify all clients about user status changes"""
        for phone, client_data in self.clients.items():
            if client_data['online'] and phone != user_phone:
                try:
                    send_message(client_data['connection'], {
                        "type": "system",
                        "message": message
                    })
                except:
                    print(f"Failed to send system message to {phone}")
                    client_data['online'] = False

    def send_user_list(self, conn, requesting_phone):
        """Send the list of registered users with their online status"""
        clients_list = []
        for phone, data in self.registered_clients.items():
            client_info = {
                "phone": phone,
                "name": data['name'],
                "online": self.clients.get(phone, {}).get('online', False)
            }
            clients_list.append(client_info)
        send_message(conn, {
            "status": "verified",
            "message": "Successfully connected!",
            "name": self.registered_clients[requesting_phone]['name'],
            "clients": clients_list
        })

    def handle_client(self, conn, addr):
        """Handle individual client connections"""
        client_phone = None
        try:
            # Handle registration or login
            conn.settimeout(30.0)
            initial_data = receive_message(conn)
            conn.settimeout(None)
            if not initial_data:
                print(f"No data received from {addr}")
                return

            action = initial_data.get('action')
            if action == 'register':
                name = initial_data['name']
                client_phone = initial_data['phone']
                print(f"Registration request from {name} ({client_phone})")

                # Check if already registered
                if client_phone in self.registered_clients:
                    send_message(conn, {
                        "status": "error",
                        "message": "Phone number already registered. Please log in."
                    })
                    return

                # Generate and send verification code
                code = self.sendBySecureChannel()
                self.verification_codes[client_phone] = code
                self.registered_clients[client_phone] = {'name': name}
                send_message(conn, {
                    "status": "verification_code",
                    "message": "Your verification code is: ",
                    "code": code
                })

                # Handle verification
                verification = receive_message(conn)
                if not verification:
                    print(f"No verification code received from {client_phone}")
                    return
                if verification.get('code') != self.verification_codes[client_phone]:
                    send_message(conn, {
                        "status": "error",
                        "message": "Invalid verification code"
                    })
                    return

            elif action == 'login':
                client_phone = initial_data['phone']
                print(f"Login request from {client_phone}")

                if client_phone not in self.registered_clients:
                    send_message(conn, {
                        "status": "error",
                        "message": "Phone number not registered. Please register first."
                    })
                    return

                # Generate and send verification code for login
                code = self.sendBySecureChannel()
                self.verification_codes[client_phone] = code
                send_message(conn, {
                    "status": "verification_code",
                    "message": "Your verification code is: ",
                    "code": code
                })

                # Handle verification
                verification = receive_message(conn)
                if not verification:
                    print(f"No verification code received from {client_phone}")
                    return
                if verification.get('code') != self.verification_codes[client_phone]:
                    send_message(conn, {
                        "status": "error",
                        "message": "Invalid verification code"
                    })
                    return

            else:
                send_message(conn, {
                    "status": "error",
                    "message": "Invalid action."
                })
                return

            # Client is verified or logged in
            name = self.registered_clients[client_phone]['name']
            self.clients[client_phone] = {
                'connection': conn,
                'address': addr,
                'name': name,
                'online': True
            }
            print(f"Client {name} ({client_phone}) connected from {addr}")

            # Send the list of clients to the connected client
            self.send_user_list(conn, client_phone)

            # Notify others about new user or reconnection
            if action == 'register':
                message = f"User {name} ({client_phone}) has joined"
            else:
                message = f"User {name} ({client_phone}) has reconnected"
            self.broadcast_user_status(client_phone, message)

            # Remove automatic offline message sending here:
            # if client_phone in self.offline_messages:
            #     ...
            # ...existing code...

            # Main message handling loop
            while True:
                message = receive_message(conn)
                print(f"Received message from {client_phone}: {message}")
                if not message:
                    print(f"Connection lost with {client_phone}")
                    break

                if message.get('type') == 'exit':
                    print(f"{client_phone} has exited.")
                    break

                # Handle key exchange messages
                if message['type'] == 'key_exchange':
                    recipient = message['recipient']
                    if recipient in self.clients and self.clients[recipient]['online']:
                        # Forward the key exchange message to the recipient
                        send_message(self.clients[recipient]['connection'], {
                            "type": "key_exchange",
                            "sender": client_phone,
                            "public_key": message['public_key']
                        })
                    else:
                        print(f"Recipient {recipient} not found or offline for key exchange.")
                    continue

                if message['type'] == 'message':
                    recipient = message['recipient']
                    content = message['content']

                    formatted_message = {
                        "type": "message",
                        "sender": client_phone,
                        "content": content
                    }

                    if recipient in self.clients and self.clients[recipient]['online']:
                        print(f"Recipient {recipient} is online. Sending message!")
                        recipient_conn = self.clients[recipient]['connection']
                        try:
                            send_message(recipient_conn, formatted_message)
                        except Exception as e:
                            print(f"Failed to send message to {recipient}: {e}")
                            # Store the message for offline delivery
                            if recipient not in self.offline_messages:
                                self.offline_messages[recipient] = []
                            self.offline_messages[recipient].append(formatted_message)
                    else:
                        # Recipient is offline, store the message
                        print(f"Recipient {recipient} is offline, storing message.")
                        if recipient not in self.offline_messages:
                            self.offline_messages[recipient] = []
                        self.offline_messages[recipient].append(formatted_message)

                if message['type'] == 'fetch_offline_messages':
                    if client_phone in self.offline_messages:
                        offline_msgs = self.offline_messages[client_phone]
                        self.offline_messages[client_phone] = []
                        print(f"Sending offline messages to {client_phone}: {offline_msgs}")
                        send_message(conn, {
                            "type": "offline_messages",
                            "messages": offline_msgs
                        })
                    else:
                        print(f"No offline messages for {client_phone}")
                        send_message(conn, {
                            "type": "offline_messages",
                            "messages": []
                        })
                    continue

        except Exception as e:
            print(f"Error handling client {client_phone}: {e}")

        finally:
            if client_phone and client_phone in self.clients:
                name = self.clients[client_phone]['name']
                self.clients[client_phone]['online'] = False
                self.broadcast_user_status(client_phone, f"User {name} ({client_phone}) has disconnected")
                print(f"Client {name} ({client_phone}) disconnected")
                conn.close()

    def start(self):
        """Start the server"""
        print(f"Server starting on {self.host}:{self.port}")
        try:
            while True:
                conn, addr = self.server.accept()
                print(f"New connection from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            self.server.close()


# Utility functions for sending and receiving messages with length-prefix framing

def send_message(conn, message_dict):
    try:
        message_json = json.dumps(message_dict)
        message_bytes = message_json.encode()
        message_length = len(message_bytes)
        length_header = f"{message_length:<10}".encode()  # Fixed 10-byte header
        conn.sendall(length_header + message_bytes)
        print(f"Message sent: {message_dict}")
    except Exception as e:
        print(f"Failed to send message: {e}")



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


if __name__ == "__main__":
    server = MessagingServer()
    server.start()