import secrets
import hmac
import hashlib
from Crypto.Cipher import AES  # Requires PyCryptodome
import base64
from lib.profiler import profile

class Cryptographic_Library:
    """
    A production-ready class for authenticated symmetric encryption and signing.
    It uses AES-GCM for encryption/decryption and HMAC-SHA256 for signing/verification.
    """
    def process_key(self, shared_key: str):
        # Convert the shared key (hex string) to bytes.
        key_bytes = bytes.fromhex(shared_key)
        # Ensure key length is appropriate for AES (16, 24, or 32 bytes). If not, derive a 32-byte key.
        if len(key_bytes) not in [16, 24, 32]:
            key_bytes = hashlib.sha256(key_bytes).digest()
        return key_bytes

    @profile
    def encrypt(self, shared_key: str, plaintext: str, associated_data: bytes = None) -> bytes:
        """
        Encrypts plaintext using AES in GCM mode.
        Returns a concatenated byte string of: nonce (12 bytes) || tag (16 bytes) || ciphertext.
        """
        sym_key = self.process_key(shared_key)

        plaintext_bytes = plaintext.encode('utf-8')

        # Generate a 12-byte nonce for AES-GCM.
        nonce = secrets.token_bytes(12)
        cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    
        encrypted = nonce + tag + ciphertext
        return encrypted.hex()

    @profile
    def decrypt(self, shared_key: str, data: str, associated_data: bytes = None) -> bytes:
        """
        Decrypts the data (which should be in the format nonce||tag||ciphertext) and returns the plaintext.
        """
        sym_key = self.process_key(shared_key)

        data_bytes = bytes.fromhex(data)

        # Extract nonce (12 bytes), tag (16 bytes), and ciphertext.
        nonce = data_bytes[:12]
        tag = data_bytes[12:28]
        ciphertext = data_bytes[28:]

        cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    @profile
    def sign(self, shared_key: str, message: bytes) -> bytes:
        """
        Creates an HMAC-SHA256 signature of the message using the shared key.
        """
        signature = hmac.new(self.key, message, hashlib.sha256).digest()
        return signature

    @profile
    def verify(self, shared_key: str, message: bytes, signature: bytes) -> bool:
        """
        Verifies the HMAC-SHA256 signature for the given message.
        """
        computed_sig = hmac.new(self.key, message, hashlib.sha256).digest()
        return hmac.compare_digest(computed_sig, signature)

obj_crypt = Cryptographic_Library()