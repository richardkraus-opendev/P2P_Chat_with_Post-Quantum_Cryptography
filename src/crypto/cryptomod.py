import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import oqs

class KeyPair:
    def __init__(self):
        self.privX25519 = x25519.X25519PrivateKey.generate()
        self.pubX25519 = self.privX25519.public_key()
        self.peerX25519 = None

        self.algQP = "Kyber512"
        self.privKyber = oqs.KeyEncapsulation(self.algQP)
        self.pubKyber = self.privKyber.generate_keypair()
        self.peerKyber = None

    def export_public(self):
        exportX25519 = self.pubX25519.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        exportKyber = self.pubKyber

        return exportX25519, exportKyber

    def load_peer_keys(self, x25519Bytes: bytes, kyberBytes: bytes):
        self.peerX25519 = x25519.X25519PublicKey.from_public_bytes(x25519Bytes)
        self.peerKyber = kyberBytes

        return True

class HybridKeyExchange:
    def __init__(self, local: KeyPair, peerKyes: tuple):
        self.local = local

        if peerKyes is not None:
            self.local.load_peer_keys(peerKyes[0], peerKyes[1])

    def derive_x25519_secret(self) -> bytes:
        return self.local.privX25519.exchange(self.local.peerX25519)
    
    def derive_sender_kyber_secret(self):
        return self.local.privKyber.encap_secret(self.local.peerKyber)
    
    def derive_recipient_kyber_secret(self, ciphertext: bytes):
        return self.local.privKyber.decap_secret(ciphertext)

    def combine_secrets(self, secretX25519: bytes, secretKyber: bytes, length: int = 32, salt: bytes = None, info: bytes = b"hybrid key") -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info
        ).derive(secretX25519 + secretKyber)

class SecureMessages:
    def __init__(self, sessionKey):
        self.cipher = ChaCha20Poly1305(sessionKey)
        self.perfix = os.urandom(4)
        self.txCounter = 0

    def make_nonce(self) -> bytes:
        nonce = self.perfix + self.txCounter.to_bytes(8, "little")
        self.txCounter += 1
        return nonce

    def encrypt_message(self, message: bytes) -> tuple:
        nonce = self.make_nonce()
        packet = self.cipher.encrypt(nonce, message, None)
        return nonce, packet

    def decrypt_message(self, nonce: bytes, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext
