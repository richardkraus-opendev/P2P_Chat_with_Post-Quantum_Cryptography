from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import oqs

class KeyPair:
    def __init__(self):
        self.privX25519 = x25519.X25519PrivateKey.generate()
        self.pubX25519 = self.privX25519.public_key()
        self.peerX25519

        self.algQP = "Kyber512"
        self.privKyber = oqs.KeyEncapsulation(self.algQP)
        self.pubKyber = self.privKyber.generate_keypair()
        self.peerKyber

    def export_public(self):
        exportX25519 = self.pubX25519.public_bytes()
        exportKyber = self.pubKyber
        return exportX25519, exportKyber

    def load_peer_keys(self, x25519Bytes, kyberBytes):
        self.peerX25519 = x25519.X25519PublicKey.from_public_bytes(x25519Bytes)
        self.peerKyber = kyberBytes

        return True

class HybridKeyExchange:
    def __init__(self):
        self.privX25519
        self.peerX25519
        
        self.privKyber
        self.peerKyber