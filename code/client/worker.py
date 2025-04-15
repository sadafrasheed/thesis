import json
from lib.common import log, get_from_environment, recv_json
from lib.dh_party import DH_Party
from lib.cryptographic_library import obj_crypt
import socket
from client.client import Client


class Worker:
    def __init__(self):
        self.client_socket = None
        self.id = get_from_environment("CLIENT_ID")
        self.me = Client(self.id)
        self.peer_id = None

     
        

    def handle_client(self):
        #try:
            while True:
                msg = recv_json(self.client_socket)
                # Process the data...
                if msg is None:
                    break
                
                self.peer_id = msg['id']             

                
                command = msg.get("command")
                result = {}

                match command:
                    case 'receive_token':
                        result = self.me.receive_token(msg)
                    case 'test':
                        result = self.me.run_command(msg)                        
                    case 'bye':
                        #log('Requesting to close connection...')                        
                        self.client_socket.close()
                    case _:                        
                        log("Unknown command: ", command)

                if (result is None):
                    continue
                else:
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
        #    self.client_socket.close()


