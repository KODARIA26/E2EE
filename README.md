# E2EE
End-to-end encrypted communication system implementing hybrid cryptography (ECC + AES), user authentication via OTP, offline message handling, and secure key exchange. Built as part of an online security course, focusing on confidentiality, integrity, and controlled availability of messages in a decentralized environment.
# E2EE – Secure End-to-End Communication System

This project implements a distributed messaging system designed to ensure confidentiality, integrity, and controlled availability of communication between users. The system provides secure user registration, authentication, hybrid encryption, message delivery, and offline message handling.

---

## Overview

In modern communication systems, protecting data is essential. This project examines the security aspects of a decentralized messaging environment, focusing on:

- Hybrid encryption using asymmetric cryptography (ECC) for secure key exchange and symmetric encryption (AES) for message confidentiality.
- User authentication through one-time passcodes (OTP).
- Ensuring message integrity and authenticity through digital signatures.
- Reliable message handling, including offline message storage for unavailable users.
- Minimal server-side data retention to maintain privacy and reduce exposure.

---

## System Architecture

The system consists of a server and multiple clients communicating over TCP. Each client identifies itself using a phone number, receives a one-time authentication code, and establishes secure communication with other users.

### Components

| Component | Description |
|----------|-------------|
| `server.py` | Manages clients, authentication, key exchange, message routing, and offline message storage |
| `client.py` | Handles user cryptographic operations, interaction menus, and encrypted chat functionality |

The server supports multiple concurrent clients using threads.

---

## Cryptographic Model

| Layer | Technique | Purpose |
|------|-----------|---------|
| Key Exchange | ECC + Diffie-Hellman | Establishes a secure shared secret |
| Message Encryption | AES | Fast symmetric encryption for messages |
| Authentication | One-Time Passcode (OTP) | Verifies user identity |
| Integrity | Digital Signatures | Ensures authenticity and prevents tampering |

No cryptographic keys are permanently stored on the server.

---

## User Interaction

After successful authentication, the client displays the following menu:

--- MENU ---

1. View online users

2. Start chat

3. View offline messages

4. Exit chat

5. Quit application
(Type 'menu' anytime to return)


Messages sent to users who are offline are queued and delivered once they reconnect.

---

## Availability Considerations

While absolute availability cannot be guaranteed, the system enhances reliability through:

- Threaded message reception
- Offline message queueing
- Automatic retry for key exchange
- Graceful handling of connection loss
- Dynamic updates to user status

These mechanisms ensure continuity and usability even in unstable network conditions.

---

## Authors

Daria Kokin (`KODARIA26`)  
Maor Shoval (`maorshoval`)

Developed as part of the "Online Space Security" university course.

---

## Future Improvements

- Support for more than 10 concurrent clients
- Encrypted persistent storage
- Improved offline message synchronization
- Graphical or web-based interface

---

## License

This project is intended for academic and educational purposes only.  
It is not recommended for production use without further review.






