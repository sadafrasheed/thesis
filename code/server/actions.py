import secrets
from lib.db import db
from lib.common import server_identity, log, error, get_from_environment
from lib.dh_party import DH_Party
from lib.cryptographic_library import obj_crypt
from server.kgs import KGServer

def authorization(user_id, device_id):    
    # Save the partial private key (hex-encoded) 
    where_clause = "identity = '{0}'".format(user_id)
    if db.does_record_exist(where_clause):
        where_clause = "identity = '{0}'".format(device_id)
        if db.does_record_exist(where_clause):
            db.table_name = "authorization"
            where_clause = "identity = '{0}' and can_access='{1}'".format(user_id, device_id)
            if db.does_record_exist(where_clause):
                db.update_record(where_clause, 'identity',user_id,'can_access',device_id)
            else:
                db.insert_record('identity', user_id,'can_access',device_id)
            db.table_name = "identities"
        else:
            log(f"{device_id} is not registered")
    else:
        log(f"{user_id} is not registered")


            
    
def receive_message(msg):
    pass


def send_message(client_identity, message):

    import json
    import socket
    from lib.common import peer_address, recv_json

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(peer_address)
    
    cipher_text = "None"
    reg_request = {
            "action": "receive",
            "cipher": cipher_text.hex(),
            "identity": client_identity
        }
    
    data = json.dumps(reg_request) + "\n"

    sock.sendall(data.encode())
    response = recv_json(sock)
    sock.close()


def main():
    import sys
    import argparse

    # parser = argparse.ArgumentParser(
    #     description="Server for Cloud Assisted IoT"
    # )
    # parser.add_argument("--action", type=str, required=True, help="Action to be performed by the server")
    # parser.add_argument("--Alice", type=str, required=True, help="Alice identity (email or username)")
    # args = parser.parse_args()

    # action = args.action.strip()
    # if not action:
    #     log("Empty action provided.")
    #     sys.exit(1)

    
    action = sys.argv[1]  # Extract action (first argument)
    parameters = sys.argv[2:]  # Extract remaining parameters

    match action:        
        case "send":
            # python -m server.actions send front_cam_1 "message from server"
            send_message(parameters[0], parameters[1])     

        case "authorization":
            # python -m server.actions authorization user@example.com front_cam_1
            authorization(parameters[0], parameters[1]) 

        case _:
            print(f"Error: Unknown action '{action}'")
            return
        

if __name__ == "__main__":
    main()
