import os
from lib.common import get_from_environment
from lib.credentials_model import Credentials_Model
from lib.elliptic_curve import curve
from server.kgs import KGServer

class Server:
    def __init__(self):
        self.id = get_from_environment("SERVER_ID")

        server_directory = f"jsons/{self.id}/"
        if not os.path.exists(server_directory):
            os.makedirs(server_directory)

        self.credentials_file = f"{server_directory}credentials.json"
        self.credentials = Credentials_Model(self.id)
        
        if(self.credentials.is_empty()):
            kgs = KGServer()
            hex_partial_key, hex_generator = kgs.generate_partial_private_key(self.id)
            self.d_partial = curve.dehexify_key(hex_partial_key)        
            self.generator = curve.dehexify_key(hex_generator)
            self.master_public_key = curve.dehexify_key(kgs.hexified_master_public())        
            self.private_key, self.public_key = curve.generate_user_keys(self.id, self.d_partial, self.master_public_key )

            self.credentials.put("public_key", curve.hexify_key(self.public_key))
            self.credentials.put("private_key", curve.hexify_key(self.private_key))
            self.credentials.put("d_partial", curve.hexify_key(self.d_partial))
            self.credentials.put("master_public_key", curve.hexify_key(self.master_public_key))
            self.credentials.put("generator", curve.hexify_key(self.generator))
            self.credentials.save()

        else:
            self.d_partial = curve.dehexify_key(self.credentials.get("d_partial"))        
            self.public_key = curve.dehexify_key(self.credentials.get("public_key"))
            self.private_key = curve.dehexify_key(self.credentials.get("private_key"))
            self.master_public_key = curve.dehexify_key(self.credentials.get("master_public_key"))
            self.generator = curve.P = curve.dehexify_key(self.credentials.get("generator"))
            #self.master_secret_key = curve.dehexify_key(self.credentials.get("master_secret_key"))


        
            
