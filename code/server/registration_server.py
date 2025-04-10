from lib.common import log
from server.kgs import KGServer
from lib.elliptic_curve import curve, ZR
from lib.db import db

class Registration_Server:

    def __init__(self, client_id):
        self.client_id = client_id
        

    def register(self):

        """
        2. The server sends (a) partial secret key against the sent identity, encrypted using the 
            symmetic shared key and (b) DH ephemeral public key.
        """    
        
        kgs = KGServer()
        hex_partial_key, hex_generator = kgs.generate_partial_private_key(self.client_id)
        return  hex_partial_key, hex_generator, kgs.hexified_master_public()

        

    def save_public_key(self, key):
        # Save the partial private key (hex-encoded) 
        where_clause = "identity = '{0}'".format(self.client_id)
        if db.does_record_exist(where_clause):
            db.update_record(where_clause, 'public_key', key)
        
    def fetch_client_credentials(self):
        # get public key from db and decrypt
        row = db.select_by_fields('identity', self.client_id)[0]
        client = {}
        client['generator'] = curve.dehexify_key(row[2])
        client['master_public_key'] = curve.dehexify_key(row[3])
        client['master_secret_key'] = curve.dehexify_key(row[4])
        client['partial_private_key'] = curve.dehexify_key(row[5])
        client['public_key'] = curve.dehexify_key(row[6])

        return client