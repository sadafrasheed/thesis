# kgs.py
import secrets
import json
from lib.db import db
from lib.common import log, error
from lib.elliptic_curve import curve


class KGServer:

    def __init__(self): # KG setup: choose a master secret and compute the KG's public key.
        self.__master_secret_key, self.__master_public_key, self.__generator = self.__initialize_master_keys()
         

    def __initialize_master_keys(self):
        msk = mpk = None
        filename = "jsons/kg_server.json"
        try:
            # Open and read the JSON file
            with open(filename, "r") as file:
                data = json.load(file)
                msk = curve.dehexify_key(data["master_secret_key"])
                mpk = curve.dehexify_key(data["master_public_key"])
                curve.P = curve.dehexify_key(data["generator"])

        except FileNotFoundError:
            error(f"Error: File '{filename}' not found!")           
        except json.JSONDecodeError:
            error(f"Error: File '{filename}' contains invalid JSON!")
            
        if msk is None:
            msk, mpk = curve.generate_master_keys()            
            with open(filename, "w") as f:
                json.dump({"master_secret_key":curve.hexify_key(msk),"master_public_key":curve.hexify_key(mpk), "generator":curve.hexify_key(curve.P) }, f)

        return msk, mpk, curve.P
    
    def setup_from_db(self, master_secret_key, master_public_key, generator):
        self.__master_secret_key = master_secret_key
        self.__master_public_key = master_public_key
        self.__generator = curve.P = generator


    def hexified_master_public(self):
        return curve.hexify_key(self.__master_public_key)

    def generate_partial_private_key(self, identity):
        
        partial_private_key = curve.extract_partial_private_key(identity, self.__master_secret_key)
        
        
        #log(f"Partial Key: {partial_private_key}")
        hex_partial_key = curve.hexify_key(partial_private_key)
        hex_master_secret = curve.hexify_key(self.__master_secret_key)
        hex_master_public = curve.hexify_key(self.__master_public_key)
        hex_generator =  curve.hexify_key(curve.P)
        
        # Save the partial private key (hex-encoded) 
        where_clause = "identity = '{0}'".format(identity)
        if db.does_record_exist(where_clause):
            db.update_record(where_clause, 'identity',identity,'generator',f"{hex_generator}",'master_public_key',hex_master_public,'master_secret_key',hex_master_secret,'partial_private_key',hex_partial_key)
        else:
            db.insert_record('identity', identity,'generator',hex_generator,'master_public_key',hex_master_public,'master_secret_key',hex_master_secret,'partial_private_key',hex_partial_key)
        
        #log("Hex Partial Key: ",hex_partial_key)
        return hex_partial_key, hex_generator

    

    
