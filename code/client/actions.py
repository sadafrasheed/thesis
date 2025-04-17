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
            In order to register with Cloud Server, the smart IoT devices sends an unencrypted request to the server. 
            This request includes smart device identity and a public ephemeral key to be used in ECDH key exchange. 
            The server generates master public key, master secret key and device's partilal key against the sent 
            identity to be used with IBE. The server encrypts partial secret key and master public key and its own 
            IBE public key using the ECDH symmetic shared key. It then send this encrypted keys and it's 
            ephemeral public key used in ECDH key exchange. The smart IoT device generates the DH shared key 
            and decrypts the message to get it's partial key and server's public key. The device then generates 
            it's keys pair using partial key and master public key. The device securely saves it's key pair and 
            sends public key to the server which saves it in secure database for later use. All future communication 
            between server and smart device is encrypted using the just shared Identity-based asymmetric keys.
            """
            client.register()

        case "test_socket":
            test_socket()
        case "send_server":
            # python3 -m client.actions send_server "message"
            send_server(client, parameters[0])        
        case "send_peer":
            # python3 -m client.actions send_peer peer_id "message" 
            """
            When a smart IoT device wants to access another smart IoT device, it sends encrypted request to 
            the server. The request includes it's own and the requested peer device's identity. The server 
            first verifies the requestee. If server can decrypt the message using the public key it has 
            saved against the requestee device, that means the requesting device is infact the one it claims 
            to be. Next the server checks it database for requesting device's access to the requested device. 
            If the server finds the access record, it generates a random session token and a timestamp, 
            encrypts it for both requesting and requested devices and send the encrypted token+timestamp and 
            public key of other device to both the devices. The requesting device uses peer device's public 
            key and it's own private key to encrypt the message, which includes token and timestamp in 
            addition to other data and send this ciphertext to the peer device.
            The peer device upon getting the message, decrypts it using the it's own private key and the 
            public key of sending device shared by the server. This proves the validity of sending device. 
            Next the receiving device, matches the token and verifies the timestamp to avoid replay attack. 
            Upon successful varifications, the device moves on to process the message recieved.
            """
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