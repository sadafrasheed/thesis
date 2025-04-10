from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Tuple


class IBE: 

    @classmethod
    def encrypt(cls, plaintext: str, shared_secret: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts the plaintext with AES in CBC mode using the provided key.
        
        Steps:
        1. Generate a random IV.
        2. Pad the plaintext to a multiple of the AES block size.
        3. Encrypt the plaintext using AES-CBC.
        
        Returns:
        A tuple (iv, ciphertext).
        """
        iv = get_random_bytes(16)
        cipher = AES.new(shared_secret, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv, ciphertext


    @classmethod
    def decrypt(cls, ciphertext: bytes, iv: bytes, shared_secret:bytes) -> str:
        """
        Decrypts the AES ciphertext using the provided key and IV in CBC mode.
        
        Steps:
        1. Initialize the AES cipher in CBC mode with the given IV.
        2. Decrypt the ciphertext.
        3. Unpad the decrypted plaintext.
        
        Returns:
        The plaintext message.
        """
        cipher = AES.new(shared_secret, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    # Needs implementation...
    @classmethod
    def sign(cls, text:str, private_key:int) -> bytes:
        pass

    @classmethod
    def verify(cls, text:bytes, public_key:Tuple[int, int]) -> bool:
        pass