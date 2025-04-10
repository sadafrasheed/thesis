from lib.common import log
from server.kgs import kgs

from lib.db import db

class Registration_Server:

    def __init__(self, client_id):
        self.client_id = client_id
        

    def register(self):

        """
        2. The server sends (a) partial secret key against the sent identity, encrypted using the 
            symmetic shared key and (b) DH ephemeral public key.
        """    
        
        
        hex_partial_key, hex_generator = kgs.generate_partial_private_key(self.client_id)
        return  hex_partial_key, hex_generator, kgs.hexified_master_public()

        

    def save_public_key(self, key):
        # Save the partial private key (hex-encoded) 
        where_clause = "identity = '{0}'".format(self.client_id)
        if db.does_record_exist(where_clause):
            db.update_record(where_clause, 'public_key', key)
        
