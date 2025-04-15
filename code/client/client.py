import os
import sys
import json
import socket
from lib.dh_party import DH_Party
from lib.cryptographic_library import obj_crypt
from lib.common import log, error, get_from_environment, recv_json, server_address,  server_identity,peer_address
from lib.elliptic_curve import curve
from client.token_model import Token_Model
from lib.credentials_model import Credentials_Model


# -----------------------------
# Client Class
# -----------------------------
class Client:
    def __init__(self, client_id):
        self.id = client_id
        client_directory = f"jsons/{client_id}/"
        if not os.path.exists(client_directory):
            os.makedirs(client_directory)

        self.credentials_file = f"{client_directory}credentials.json"
        self.credentials = Credentials_Model(client_id)
        self.tokens = Token_Model(client_id)

        self.d_partial = None    
        self.private_key = None
        self.public_key = None
        self.generator = None
        self.master_public_key = None    
        self.server_public_key = None    
        

        # DH Stuff
        # generator = "server_id | client_id"
        #self.dh_party = DH_Party(f"{server_id} | {self.id}" )        
        #self.dh_server_shared_secret = None
        

        if(self.is_registered()):
            self.__load_credentials()

    def is_registered(self):
        return self.credentials.get('client_id') is not None

    def __load_credentials(self):
        self.d_partial = curve.dehexify_key(self.credentials.get("d_partial"))        
        self.public_key = curve.dehexify_key(self.credentials.get("public_key"))
        self.private_key = curve.dehexify_key(self.credentials.get("private_key"))
        self.master_public_key = curve.dehexify_key(self.credentials.get("master_public_key"))
        self.server_public_key = curve.dehexify_key(self.credentials.get("server_public_key"))
        self.generator = curve.P = curve.dehexify_key(self.credentials.get("generator"))

        #self.dh_party.setup(self.private_key, self.generator)
        #_, self.dh_server_shared_secret = self.dh_party.compute_shared_secret(self.master_public_key)

        
            

        
    #------------------------------------
    def register(self):
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_identity, server_address[1]))

        # --- Registration Phase ---
        server_id = get_from_environment("SERVER_ID")
        dh_party = DH_Party()
        client_public = dh_party.ephemeral_public

        reg_request = {
            "action": "register",
            "client_id": self.id,
            "client_dh_public": dh_party.curve.hexify_key(client_public)
        }

        data = json.dumps(reg_request) + "\n"
        sock.sendall(data.encode())
        #log(f"Registration request sent with client_id '{self.id}'")

        response = recv_json(sock)
        if response and response.get("action") == "registration_response":
            #log(response)        
            reg_request = self.__process_registration_response(response, dh_party)
            data = json.dumps(reg_request) + "\n"
            sock.sendall(data.encode())
            sock.close()
            
        
        #log(f"Client Key: {client_public}")
        #log(f"Serialized generator (hex): {self.dh_party.curve.hexify_key(client_public)}")
        

    def __process_registration_response(self, response, dh_party):
        # Receive public parameters and the server's ephemeral public key for DH.

        server_ephemeral_public = dh_party.curve.dehexify_key(response['dh_ephemeral_public'])
        _, dh_shared_secret = dh_party.compute_shared_secret(server_ephemeral_public)

        #log(f"Shared Secret: {dh_shared_secret}")
        cipher_generator = response['generator']
        cipher_partial_secret = response["encrypted_partial_private"]
        
        #log(f"Generator: {cipher_generator}")
        #log(f"Key: {cipher_partial_secret}")

        hex_generator = obj_crypt.decrypt(dh_shared_secret, cipher_generator)        
        hex_partial_key = obj_crypt.decrypt(dh_shared_secret, cipher_partial_secret)        
       
        self.generator = curve.dehexify_key(hex_generator)
        self.d_partial = curve.dehexify_key(hex_partial_key)

        self.master_public_key = curve.dehexify_key(response['master_public_key'])

        self.server_public_key = curve.dehexify_key(response['server_public_key'])

        curve.P = self.generator
        self.private_key, self.public_key = curve.generate_user_keys(self.id, self.d_partial, self.master_public_key )
        
        self.__store_credentials()
        
        return {
            "action": "set_pk",
            "client_id": self.id,
            "client_public": obj_crypt.encrypt(dh_shared_secret, curve.hexify_key(self.public_key) )
        }


    def __store_credentials(self):

        self.credentials.put("client_id", self.id)
        self.credentials.put("public_key", curve.hexify_key(self.public_key))
        self.credentials.put("private_key", curve.hexify_key(self.private_key))
        self.credentials.put("d_partial", curve.hexify_key(self.d_partial))
        self.credentials.put("master_public_key", curve.hexify_key(self.master_public_key))
        self.credentials.put("server_public_key", curve.hexify_key(self.server_public_key))
        self.credentials.put("generator", curve.hexify_key(self.generator))
        self.credentials.save()
        
        

    # ------------------------------------------

    def request_token(self, device_id):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_identity, server_address[1]))

        _, shared_secret = curve.compute_shared_secret(self.private_key, self.server_public_key)

        request = {
            "action": "token_request",
            "client_id": self.id,
            "for_device": obj_crypt.encrypt(shared_secret, device_id)    
        }
        
        data = json.dumps(request) + "\n"
        sock.sendall(data.encode())
        #log(f"Token request sent for device '{device_id}'")

        response = recv_json(sock)
        if response and response.get("action") == "token_response":
            #log(response)        
            t_response = self.__process_token_response(device_id, response, shared_secret)   
            request = {'action': 'bye','client_id': self.id}
            sock.sendall(f"{json.dumps(request)}\n".encode())
            sock.close()

            return t_response    

    def __process_token_response(self, device_id, response, shared_secret):
        # Receive public parameters and the server's ephemeral public key for DH.

        cipher_token = response['token']
        error_msg =  response['error']

        if (error_msg is None) : 
            token = str(obj_crypt.decrypt(shared_secret, cipher_token), "utf-8")  
            hex_public_key = response['public_key']

            self.tokens.set(device_id, hex_public_key, token)
            #print(token)
            return curve.dehexify_key(hex_public_key), token
        
        else:
            error(error_msg)
            sys.exit(1)


    #---------------------------------------------

    def send_encrypted_message_to_peer(self, device_id, message):
        from lib.common import recv_json, peer_address
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(device_id)
        sock.connect((device_id, peer_address[1]))

        peer_dict = self.tokens.get(device_id)
        
        public_key = curve.dehexify_key(peer_dict['public_key'])        
        token = peer_dict['token']
        #print(token)
        #print(public_key)
        _,shared_secret = curve.compute_shared_secret(self.private_key, public_key)

        #print(shared_secret)
        cipher_token = obj_crypt.encrypt(shared_secret, token)
        cipher_message = obj_crypt.encrypt(shared_secret, message)
        #print(curve.hexify_key(self.public_key))
        request_data = {
            "command": 'test',
            "id": self.id,
            "token": cipher_token,
            "public_key": curve.hexify_key(self.public_key),
            "message": cipher_message
        }
        
        data = json.dumps(request_data) + "\n"

        sock.sendall(data.encode())
        # response = recv_json(sock)
        # if response:                    
        #     t_response = self._message_response(response, shared_secret)            
        sock.close()


    def _message_response(self, response, shared_secret):
        print(obj_crypt.decrypt(shared_secret, response))


    def receive_token(self, msg):
        _, shared_secret = curve.compute_shared_secret(self.private_key, self.server_public_key)
        cipher_token = msg['token']
        token = str(obj_crypt.decrypt(shared_secret, cipher_token), "utf-8")   
        hex_public_key = msg['public_key']
        #print(hex_public_key)
        peer_id = msg['peer_id']
        self.tokens.set(peer_id, hex_public_key, token)



    def run_command(self, msg):
        
        public_key = curve.dehexify_key(msg['public_key'])        
        cipher_token = msg['token']
        cipher_message = msg['message']
        peer_id = msg['id']

        print(f"Command from: {peer_id}")

        _,shared_secret = curve.compute_shared_secret(self.private_key, public_key)

        #print(shared_secret)

        token = str(obj_crypt.decrypt(shared_secret, cipher_token),"utf-8")
        message = str(obj_crypt.decrypt(shared_secret, cipher_message),"utf-8")

        if(self._validate_token(peer_id, public_key, token)):
            print("Valid Token")
            print(f"{peer_id} sent {message}")


    def send_server(self, msg, action="receive"):
        from lib.common import server_address, server_identity, recv_json
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_identity, server_address[1]))

        #encrypt using device private key
        #signcryption
        cipher_text = self.encrypt(msg, server_identity)
        reg_request = {
            "action": action,
            "cipher": cipher_text.hex(),
            "identity": self.id
        }
        
        data = json.dumps(reg_request) + "\n"

        sock.sendall(data.encode())
        response = recv_json(sock)
        sock.close()

    def _validate_token(self, peer_id, key, token):
        saved = self.tokens.get(peer_id)
        saved_pk = curve.dehexify_key(saved['public_key'])
        return saved_pk == key and saved['token'] == token and curve.is_token_valid(token)