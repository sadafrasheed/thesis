from typing import Tuple
import hashlib
import secrets
import sys
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR
from datetime import date

from lib.common import log

class EllipticCurve:
    def __init__(self, group_name='BN254', generator = None):
        """
        The system parameters:
          - P: Generator of group G1.
          - s: Master secret key.
          - mpk: Master public key = s * P.
        """
        try:
            self.group = PairingGroup(group_name)
        except Exception as e:
            print("Error initializing pairing group:", e)
            sys.exit(1)
        
        #self.P = self.group.random(G1)  

        if generator is None:
            generator = date.today().strftime("%d/%m/%Y")

        self.P = self.group.hash(generator, G1)        
        #print(self.group.serialize(self.P))


    def generate_master_keys(self):
        msk = self.group.random(ZR)
        mpk = msk * self.P
        return msk, mpk

    def extract_partial_private_key(self, identity, msk):
        """
        Extracts a partial private key for the given identity.
        The partial private key is computed as: d_id = s * H(identity)
        """
        Q_id = self.group.hash(identity, G1)
        d_id = msk * Q_id
        return d_id

    def generate_user_keys(self, identity, partial_sk, mpk):
        """
        Generates the user's keys:
          - Obtains partial private key.
          - Picks a random secret x.
          - Forms full private key as a tuple (x, d_id).
          - Computes the public key as (x + h)*P, where h = H(identity || mpk).
        """
        # Get the partial private key from the KGC
        #d_id = self.extract_partial_private_key(identity, msk)
        d_id = partial_sk
        
        # User picks a random secret x.
        x = self.group.random(ZR)        
        
        # Derive a hash value h from the identity and master public key.
        h = self.group.hash(identity + str(mpk), ZR)

        full_sk = (x + h) * d_id
        
        # Compute the public key.
        public_key = full_sk * self.P

        return full_sk, public_key


    def compute_shared_secret(self, ephemeral_private, other_ephemeral_public):
        """
        Computes the shared secret using the party's ephemeral private key and the other party's ephemeral public key.
        The shared point is then hashed with SHA-256 to derive a symmetric key.
        """
        shared_point = ephemeral_private * other_ephemeral_public
        shared_bytes = self.group.serialize(shared_point)
        symmetric_key = hashlib.sha256(shared_bytes).hexdigest()
        return shared_point, symmetric_key


    def hexify_key(self, key):
        import binascii
        return binascii.hexlify(self.group.serialize(key)).decode('utf-8')
    
    def dehexify_key(self, hex):
        import binascii
        return self.group.deserialize(binascii.unhexlify(hex))

curve = EllipticCurve('BN254')    