import json
import os

from lib.json_model import Json_Model

class Credentials_Model(Json_Model):

    def __init__(self, client_id):
        """
        Credentials_Model initialization that runs after token_model's initialization.
        
        Args:
            client_id (str): The path to the JSON file.
        """
        
        # Call the parent's __init__ to load the JSON data.
        super().__init__(f"jsons/{client_id}/credentials.json")


        # data = {
        #     "client_id": self.id,
        #     "public_key": curve.hexify_key(self.public_key),
        #     "private_key": curve.hexify_key(self.private_key),
        #     "d_partial": curve.hexify_key(self.d_partial),
        #     "master_public_key": curve.hexify_key(self.master_public_key),
        #     "generator": curve.hexify_key(self.generator)            
        # }
    
    