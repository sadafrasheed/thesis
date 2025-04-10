from client.client import Client

from lib.common import get_from_environment
from lib.elliptic_curve import curve
from server.registration_server import Registration_Server
from server.kgs import KGServer
from server.server import Server

def main():
    
    #client_id = "user@example.com"
    client_id = "front_cam_1"


    obj_client = Client(client_id)
    server_id = get_from_environment("SERVER_ID")

    server = Registration_Server(client_id)
    db_client = server.fetch_client_credentials() 
    
    print (f"client_id: {client_id}")
    print (f" obj_client.public_key==db_client['public_key'] : {obj_client.public_key==db_client['public_key']}" )
    print (f" obj_client.d_partial==db_client['partial_private_key'] : {obj_client.d_partial==db_client['partial_private_key']}" )
    print (f" obj_client.generator==db_client['generator'] : {obj_client.generator==db_client['generator']}" )
    print (f" obj_client.master_public_key==dh_server_party.master_public_key : {obj_client.master_public_key==db_client['master_public_key']}" )
    
    print("--------------")
    curve.P = db_client['generator']
    print(f"generator: {curve.P}")

    print(f"obj_client.private_key: {obj_client.private_key}")
    print(f"obj_client.master_public_key: {obj_client.master_public_key}")

    print(f"db_client['master_secret_key']: {db_client['master_secret_key']}")
    print(f"obj_client.public_key: {obj_client.public_key}")



    obj = Server()
    #server.client_id = obj.id
    

    _,client_shared_key = curve.compute_shared_secret(obj_client.private_key, obj.public_key)
    
    _,server_shared_key = curve.compute_shared_secret(obj.private_key, obj_client.public_key)

    print (f"client_shared_key==server_shared_key : {client_shared_key==server_shared_key}" )

    # obj_client.d_partial     
    # obj_client.private_key 
    # obj_client.public_key 
    # obj_client.generator 
    # obj_client.master_public_key          
    # obj_client.dh_party
    # obj_client.dh_server_shared_secret


if __name__ == "__main__":
    main()
