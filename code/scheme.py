#!/usr/bin/env python3
"""
Certificateless IBE-based lightweight authentication scheme for IoT devices.

Entities:
  - CloudServer: Acts as KGC; sets up system parameters and issues partial private keys.
  - Entity: Represents an IoT device or a user.
  
Workflow:
  1. Registration: Each entity registers with CloudServer.
     - The server computes a partial private key d = s * H(ID).
     - The entity picks a random secret x and computes its full private key (x, d) and public key.
  2. Token Generation: When a user wants to access a device,
     - The user sends the device’s identity to CloudServer.
     - CloudServer generates a random token and sends signed token (securely) to both parties.
  3. Message Exchange:
     - The user encrypts the token+message (using a symmetric key derived from a pairing-based shared secret)
       and signs the payload.
     - The device decrypts the ciphertext and verifies the token and signature.
  
This example uses the BN254 pairing group.
"""

import sys, hashlib, binascii
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction

# ----------------------------
# Cloud Server (KGC) Definition
# ----------------------------
class CloudServer:
    def __init__(self, group_name='BN254'):
        self.group = PairingGroup(group_name)
        self.P, self.s, self.mpk = self.setup()
    
    def setup(self):
        # System parameters: Generator P, master secret s, and master public key mpk.
        P = self.group.random(G1)
        s = self.group.random(ZR)
        mpk = s * P
        return P, s, mpk
    
    def extract_partial_private_key(self, identity):
        # Maps identity to a group element and computes d = s * H(ID)
        Q_id = self.group.hash(identity, G1)
        d = self.s * Q_id
        return d
    
    def generate_token(self):
        # Generates a random token (a nonce) for session authentication.
        token = self.group.random(ZR)
        return token

# ----------------------------
# Entity (IoT device or User)
# ----------------------------
class Entity:
    def __init__(self, system: CloudServer, identity: str):
        self.system = system
        self.identity = identity
        self.full_sk = None  # Tuple: (user secret x, partial key d)
        self.public_key = None
        self.generate_keys()
    
    def generate_keys(self):
        # 1. Get partial private key from CloudServer.
        d = self.system.extract_partial_private_key(self.identity)
        # 2. Choose a random secret x.
        x = self.system.group.random(ZR)
        self.full_sk = (x, d)
        # 3. Compute h = H(identity || mpk) and derive the public key: (x + h)*P.
        h = self.system.group.hash(self.identity + str(self.system.mpk), ZR)
        self.public_key = (x + h) * self.system.P

# ----------------------------
# Encryption and Signature (User Side)
# ----------------------------
def encrypt_and_sign(user: Entity, device: Entity, token, message, system: CloudServer):
    # Compute a pairing-based shared secret.
    # Here, we use the pairing between the user's partial key and the device's public key.
    shared_secret = system.group.pair(user.full_sk[1], device.public_key)
    # Derive a symmetric key (using SHA-256) from the serialized shared secret.
    sym_key = hashlib.sha256(system.group.serialize(shared_secret)).digest()
    sym_cipher = SymmetricCryptoAbstraction(sym_key)
    
    # Form the payload by concatenating the token and the message.
    payload = f"{token}|{message}"
    ciphertext = sym_cipher.encrypt(payload.encode('utf-8'))
    
    # Sign the payload using the user's secret x (this is a simple placeholder signature).
    signature = hashlib.sha256((payload + str(user.full_sk[0])).encode('utf-8')).hexdigest()
    
    return ciphertext, signature

# ----------------------------
# Decryption and Verification (Device Side)
# ----------------------------
def decrypt_and_verify(device: Entity, ciphertext, signature, token_expected, user: Entity, system: CloudServer):
    # Recompute the shared secret as used by the user.
    shared_secret = system.group.pair(user.full_sk[1], device.public_key)
    sym_key = hashlib.sha256(system.group.serialize(shared_secret)).digest()
    sym_cipher = SymmetricCryptoAbstraction(sym_key)
    
    payload = sym_cipher.decrypt(ciphertext).decode('utf-8')
    token_received, message = payload.split("|", 1)
    
    # Verify that the received token matches the expected token.
    if token_received != str(token_expected):
        raise Exception("Token mismatch!")
    
    # Verify the signature (again, this is a placeholder; use a proper signature scheme in production).
    expected_signature = hashlib.sha256((payload + str(user.full_sk[0])).encode('utf-8')).hexdigest()
    if expected_signature != signature:
        raise Exception("Signature verification failed!")
    
    return message

# ----------------------------
# Demonstration Main Function
# ----------------------------
def main():
    # Initialize the CloudServer (KGC) with system parameters.
    system = CloudServer('BN254')
    
    # Register an IoT device and a user with the system.
    device = Entity(system, "device123@iot.com")
    user = Entity(system, "user@example.com")
    
    # When the user wants to access the device, the user sends the device's identity to the server.
    token = system.generate_token()
    print(f"Token generated by server: {token}")
    
    # The server sends the token to both device and user over secure channels (assumed secure here).
    # The user encrypts and signs a message along with the token.
    message = "Command: Turn on"
    ciphertext, signature = encrypt_and_sign(user, device, token, message, system)
    print("Ciphertext (hex):", binascii.hexlify(ciphertext))
    print("Signature:", signature)
    
    # The device receives the token and the ciphertext, then decrypts and verifies.
    decrypted_message = decrypt_and_verify(device, ciphertext, signature, token, user, system)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
