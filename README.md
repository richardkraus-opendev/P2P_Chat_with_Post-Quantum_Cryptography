# Peer-to-Peer Chat with Post-Quantum Cryptography

**Description:**  
This will be an experimental, web-based peer-to-peer chat application that will use post-quantum cryptography for secure messaging. All keys and messages will be stored locally, and communication will take place directly between peers without relying on central servers.

**Purpose:**  
This project will serve as a proof-of-concept to explore post-quantum cryptography in a web-based peer-to-peer chat application. The initial implementation will be developed in Python for rapid prototyping and testing, with possible future plans to rewrite performance-critical parts in Rust or C.

**Project Structure:**  
- `src/` - will contain the source code of the application  
  - `crypto/` - will handle key generation, encryption, and decryption  
  - `network/` - will manage peer-to-peer communication modules  
  - `frontend/` - will include the web-based frontend components  
  - `config/` - will contain configuration files and application settings  
- `docs/` - will contain documentation and technical notes about the project  