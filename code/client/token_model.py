import json
import os

from lib.json_model import Json_Model

class Token_Model(Json_Model):

    def __init__(self, client_id):
        """
        Token_Model initialization that runs after token_model's initialization.
        
        Args:
            client_id (str): The path to the JSON file.
        """
        
        # Call the parent's __init__ to load the JSON data.
        super().__init__(f"jsons/{client_id}/tokens.json")

        

    
    def set(self, id, key, token):
        """
        Set the value for a key in the JSON data and save the file.
        
        Args:
            key (str): The key to update or add.
            value (Any): The value to associate with the key.
        """
        value = {'public_key':key, 'token':token}
        super().set(id, value)
