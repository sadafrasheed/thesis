from lib.elliptic_curve import EllipticCurve, ZR
import hashlib
#from charm.toolbox.pairinggroup import PairingGroup, G1, ZR

class DH_Party:
    def __init__(self, generator=None):
        """
        Initializes a party for Diffie-Hellman exchange.
        """
        self.curve = EllipticCurve('BN254', generator)
        self.group = self.curve.group
        self.P = self.curve.P
        self.ephemeral_private = None
        self.ephemeral_public = None
        self.generate_ephemeral_key()
    

    def setup(self, private_key, P):
        self.ephemeral_private = private_key
        self.curve.P = self.P = P
        self.ephemeral_public = self.ephemeral_private * self.P


    def generate_ephemeral_key(self):
        """
        Generates an ephemeral key pair:
          - ephemeral_private: Random element in ZR.
          - ephemeral_public: ephemeral_private * P.
        """
        self.ephemeral_private = self.group.random(ZR)
        self.ephemeral_public = self.ephemeral_private * self.P

    def compute_shared_secret(self, other_ephemeral_public):
        """
        Computes the shared secret using the party's ephemeral private key and the other party's ephemeral public key.
        The shared point is then hashed with SHA-256 to derive a symmetric key.
        """
        shared_point = self.ephemeral_private * other_ephemeral_public
        shared_bytes = self.group.serialize(shared_point)
        symmetric_key = hashlib.sha256(shared_bytes).hexdigest()
        return shared_point, symmetric_key


def dh_exchange_demo():

    """
    Demonstrates a Diffie–Hellman key exchange between two parties (Alice and Bob) using ephemeral keys.
    """
    print("\n=== Diffie–Hellman Key Exchange Demo ===")
    # Alice generates her ephemeral key pair.
    alice = DH_Party()
    print("Alice's ephemeral public key (R_A):", alice.ephemeral_public)
    
    # Bob generates his ephemeral key pair.
    bob = DH_Party()
    print("Bob's ephemeral public key (R_B):", bob.ephemeral_public)
    
    # Each party computes the shared secret.
    _, symmetric_key_A = alice.compute_shared_secret(bob.ephemeral_public)
    _, symmetric_key_B = bob.compute_shared_secret(alice.ephemeral_public)
    
    print("Alice's computed shared secret key:", symmetric_key_A)
    print("Bob's computed shared secret key  :", symmetric_key_B)
    
    if symmetric_key_A == symmetric_key_B:
        print("Shared secret established successfully.")
    else:
        print("Error: Shared secrets do not match!")
