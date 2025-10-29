from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import oqs

class KeyGeneration:
    def __init__(self):
        self.privX25519 = x25519.X25519PrivateKey.generate()
        self.pubX25519 = self.privX25519.public_key()

        self.algQP = "Kyber512"
        self.privKyber = oqs.KeyEncapsulation(self.algQP)
        self.pubKyber = self.privKyber.generate_keypair()
        print("keys generated")

    def get_public_keys(self):

        x25519_bytes = self.pubX25519.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print("---------------------1")

        print("X25519 public key:")
        print(x25519_bytes.hex())

        print("---------------------2")

        print("\nPost-Quantum public key (Kyber512):")
        print(self.pubKyber.hex())


if __name__ == "__main__":
    keys = KeyGeneration()
    keys.get_public_keys()