import json
from lib.db import db
from lib.common import log, get_from_environment, recv_json
from server.actions import receive_message
from lib.dh_party import DH_Party
from lib.cryptographic_library import obj_crypt
from server.registration_server import Registration_Server
from server.server import Server
from lib.elliptic_curve import curve
#from server.kgs import kgs

class Worker:
    def __init__(self):
        self.client_socket = None
        self.id = get_from_environment("SERVER_ID")
        self.client_id = None

        self.server = Server()

        #self.dh_party = None
        #self.dh_other_ephemeral_public = None
        #self.dh_shared_secret = None
        
        

    def handle_client(self):
        #try:
            while True:
                msg = recv_json(self.client_socket)
                # Process the data...
                if msg is None:
                    break
                
                self.client_id = msg['client_id']                 

                if msg.get('client_dh_public') is not None:
                    dh_party = DH_Party()  
                    dh_other_ephemeral_public = msg['client_dh_public']
                    client_ephemeral_public = dh_party.curve.dehexify_key(dh_other_ephemeral_public)
                    _, dh_shared_secret = dh_party.compute_shared_secret(client_ephemeral_public)

                
                action = msg.get("action")

                match action:
                    case 'register':
                        
                        reg_server = Registration_Server(self.client_id)
                        hex_partial_key, hex_generator, hexified_master_public = reg_server.register()

                        cipher_generator = obj_crypt.encrypt(dh_shared_secret, hex_generator)
                        cipher_partial_secret = obj_crypt.encrypt(dh_shared_secret, hex_partial_key)

                        hex_dh_public = dh_party.curve.hexify_key(dh_party.ephemeral_public)
                        
                        result = {
                            "action": "registration_response",
                            "master_public_key": hexified_master_public,     
                            "dh_ephemeral_public": hex_dh_public,   
                            "generator" : cipher_generator,
                            "encrypted_partial_private": cipher_partial_secret,
                            "server_public_key": dh_party.curve.hexify_key(self.server.public_key)
                        }

                    case 'set_pk':       
                        reg_server = Registration_Server(self.client_id)             
                        hex_public_key = obj_crypt.decrypt(dh_shared_secret, msg['client_public'])                    
                        reg_server.save_public_key(hex_public_key)
                        result = {}
                        self.client_socket.close()

                    case 'receive':
                        result = receive_message(msg)

                    case 'token_request':
                        # generate a new token for the device from requesting client
                        print(msg)
                        ciphered_for_device = msg['for_device']

                        token = curve.generate_token()
                        hex_token = curve.hexify_key(token)

                        hex_public_key = None
                        error_msg = None

                        # get public key from db and decrypt
                        ref_server = Registration_Server(self.client_id)
                        client = ref_server.fetch_client_credentials() 
                        #print(client)

                        _, shared_secret = curve.compute_shared_secret(self.server.private_key, client['public_key'])

                        for_device = obj_crypt.decrypt(shared_secret, ciphered_for_device).decode("utf-8")
                        print(for_device)

                        # check if the requesting client is authorized to access the other client
                        db.table_name = "authorization"
                        where_clause = "identity = '{0}' and can_access='{1}'".format(self.client_id, for_device)
                        print (where_clause)
                        records = db.select_with_where(where_clause)
                        if bool(records and len(records) > 0):

                            db.update_record(where_clause, 'identity',self.client_id,'can_access',for_device,'current_token', hex_token)

                            db.table_name = "identities"
                            row = db.select_by_fields('identity', self.client_id)[0]
                            
                            hex_public_key = row[6].decode()
                            #response = f"{hex_public_key} | {hex_token}"
                            #cipher = obj_crypt.encrypt(shared_secret,response)
                            # send token to requested device (for_device) as well, along with requestee's public key.
                        else:
                            error_msg = "Access Denied"

                        result = {
                            "action": "token_response",
                            "token": obj_crypt.encrypt(shared_secret, hex_token),     
                            "error": error_msg,
                            "public_key": hex_public_key
                        }

                    case 'bye':
                        log('Requesting to close connection...')
                        result = {}
                        self.client_socket.close()
                    case _:
                        result = {}
                        log("Unknown action: ", action)

                
                # Send the script output back to the client.   
                if self.client_socket.fileno() >= 0:
                    match result:
                        case dict():
                            response = json.dumps(result) + "\n"
                            self.client_socket.sendall(response.encode())
                        case str():                    
                            self.client_socket.sendall(result.encode())
                        case None:
                            pass
                        case _:
                            log("Unknown type:", type(result))
                else:            
                    break

        # except Exception as e:
        #     log(f"Error in worker: {e}")
        # finally:
        #     self.client_socket.close()


