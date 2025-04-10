import json
from lib.common import log, get_from_environment, recv_json
from lib.dh_party import DH_Party
from lib.cryptographic_library import obj_crypt

from client.client import Client


class Worker:
    def __init__(self):
        self.client_socket = None
        self.id = get_from_environment("CLIENT_ID")
        self.me = Client(self.id)
        self.peer_id = None

        self.dh_party = None
        self.dh_other_ephemeral_public = None
        self.dh_shared_secret = None
        
        

    def handle_client(self):
        try:
            while True:
                msg = recv_json(self.client_socket)
                # Process the data...
                if msg is None:
                    break
                
                self.client_id = msg['client_id']             
                self.dh_party = DH_Party(f"{self.id} | {self.client_id}" )  

                if msg.get('client_dh_public') is not None:
                    self.dh_other_ephemeral_public = msg['client_dh_public']
                    client_ephemeral_public = self.dh_party.curve.dehexify_key(self.dh_other_ephemeral_public)
                    _, self.dh_shared_secret = self.dh_party.compute_shared_secret(client_ephemeral_public)

                
                action = msg.get("action")

                match action:
                    
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

        except Exception as e:
            log(f"Error in worker: {e}")
        finally:
            self.client_socket.close()


