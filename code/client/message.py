from client.client import Client

from lib.common import get_from_environment
from lib.elliptic_curve import curve


def main():
    
    client_id = "iot-device-high-end"
    
    device_id = "iot-device-low-end"


    obj_client = Client(client_id)
    server_id = get_from_environment("SERVER_ID")

    #print(f"generator: {curve.P}")

    #print(f"obj_client.private_key: {obj_client.private_key}")
    #print(f"obj_client.master_public_key: {obj_client.master_public_key}")
    #print(f"obj_client.public_key: {obj_client.public_key}")



    obj_device = Client(device_id)



    #obj = Server()
    #server.client_id = obj.id

    curve.P = obj_client.generator
    public_key = curve.dehexify_key( curve.hexify_key(obj_device.public_key) )
    _,client_shared_key = curve.compute_shared_secret(obj_client.private_key, public_key)
    

    curve.P = obj_device.generator
    public_key = curve.dehexify_key( curve.hexify_key(obj_client.public_key) )
    _,device_shared_key = curve.compute_shared_secret(obj_device.private_key, public_key)


    print (f"client_shared_key : {client_shared_key}" )
    print (f"device_shared_key : {device_shared_key}" )


    print (f"client_shared_key==device_shared_key : {client_shared_key==device_shared_key}" )


if __name__ == "__main__":
    main()
