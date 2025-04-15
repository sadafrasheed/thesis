import os
import sys
import json
import socket
from client.client import Client
from lib.common import recv_json, server_address, log, get_from_environment, server_identity

def send_server(client, message):
    client.send_server(message)

def send_peer(client, device_id, message):
    # 1. get token from server
    # 2. send message with token
    import time
    public_key, token = client.request_token(device_id)
    time. sleep(2)
    client.send_encrypted_message_to_peer(device_id, message)
    


def receive(msg):
    client_id = get_from_environment("CLIENT_ID")
    client = Client(client_id)
    plaint_text = client.decrypt(msg['cipher'])    
    print(plaint_text)


def test_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall('{"action": "bye"}\n'.encode())
    sock.close()

def request_token(peer_id):
    pass

def main():
    client_id = get_from_environment("CLIENT_ID")
    
    if len(sys.argv) < 2:
        print("Error: No action provided. Usage: main.py <action> <params>")
        return
    
    action = sys.argv[1]  # Extract action (first argument)
    parameters = sys.argv[2:]  # Extract remaining parameters
  
    client = Client(client_id)

    match action:
        case "register":
            # python3 -m client.actions register
            """
            1. Client sends unencrypted registration request to server.
            it sends it's identity to server and DH ephemeral public key with the request.
            2. The server sends (a) partial secret key against the sent identity, encrypted using the 
            symmetic shared key and (b) DH ephemeral public key.
            3. The client generates the DH shared key and decrypts the message to get it's partial key. 
            The client then generates keys pair and send it's encrypted public key back to the server.
            """
            client.register()

        case "test_socket":
            test_socket()
        case "send_server":
            # python3 -m client.actions send_server "message"
            send_server(client, parameters[0])        
        case "send_peer":
            # python3 -m client.actions send_peer peer_id "message" 
            send_peer(client, parameters[0], parameters[1])        
        case "request_token": 
            # python3 -m client.actions request_token peer_id           
            request_token(parameters[0])
        case "reset":
            os.system('rm -rf jsons/*')
        case _:
            print(f"Error: Unknown action '{action}'")
            return
        
        

if __name__ == "__main__":
    main()