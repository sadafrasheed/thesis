from lib.elliptic_curve import EllipticCurve, curve
from client.client import Client
from server.kgs import kgs
from lib.elliptic_curve import curve
from lib.cryptographic_library import obj_crypt

from lib.common import get_from_environment
from lib.dh_party import DH_Party

import hashlib

def main():
    
    client_id = "user@example.com"

    obj_client = Client(client_id)
    server_id = get_from_environment("SERVER_ID")
    device_id = "front_cam_1"

    # obj_client.d_partial     
    # obj_client.private_key 
    # obj_client.public_key 
    # obj_client.generator 
    # obj_client.master_public_key          
    # obj_client.dh_party
    # obj_client.dh_server_shared_secret

    dh_party1 = DH_Party()
    dh_party1.setup(obj_client.private_key, obj_client.generator )
    #_,shared_secret1 = dh_party1.compute_shared_secret(self.master_public_key)

    shared_point1 = obj_client.private_key * obj_client.master_public_key
    shared_bytes1 = dh_party1.group.serialize(shared_point1)
    symmetric_key1 = hashlib.sha256(shared_bytes1).hexdigest()
    print(f"symmetric_key1: {symmetric_key1}")


    print(f"obj_client.dh_server_shared_secret: {obj_client.dh_server_shared_secret}")
    ciphered_device_id = obj_crypt.encrypt(obj_client.dh_server_shared_secret, device_id)  

    print(f" Ciphered Device Id: {ciphered_device_id}")


    db_client = kgs.fetch_client_credentials(client_id) 
    dh_server_party = DH_Party()
    dh_server_party.setup(db_client['master_secret_key'], db_client['generator'])
    _,shared_secret = dh_server_party.compute_shared_secret(db_client['public_key'])

    print(f"shared_secret: {shared_secret}")


    print (f" obj_client.public_key==db_client['public_key'] : {obj_client.public_key==db_client['public_key']}" )
    print (f" obj_client.generator==db_client['generator'] : {obj_client.generator==db_client['generator']}" )
    print (f" obj_client.master_public_key==dh_server_party.ephemeral_public : {obj_client.master_public_key==dh_server_party.ephemeral_public}" )
    #print (f" obj_client.master_public_key==db_client['master_secret_key'] : {obj_client.master_public_key==db_client['master_secret_key']}" )


    shared_point2 = db_client['master_secret_key'] * db_client['public_key']
    shared_bytes2 = dh_server_party.group.serialize(shared_point2)
    symmetric_key2 = hashlib.sha256(shared_bytes2).hexdigest()

    print(f"symmetric_key2: {symmetric_key2}")
    
    if obj_client.dh_server_shared_secret == symmetric_key2:
        print("Shared secret established successfully.")
    else:
        print("Error: Shared secrets do not match!")

    #for_device = obj_crypt.decrypt(shared_secret, ciphered_device_id)
    
    #print(f"for_device: {for_device}")


    # alice_identity = "alice@example.com"
    # bob_identity = "bob@example.com"

    # master_secret_key, master_public_key = curve.generate_master_keys()


    # alice_partial = curve.extract_partial_private_key(alice_identity, master_secret_key)

    # bob_partial = curve.extract_partial_private_key(bob_identity, master_secret_key)



    # alice_sk, alice_pk = curve.generate_user_keys(alice_identity, alice_partial, master_public_key)

    # bob_sk, bob_pk = curve.generate_user_keys(bob_identity, bob_partial, master_public_key)


    # _, alice_shared_key = curve.compute_shared_secret(alice_sk, bob_pk)
    # _, bob_shared_key = curve.compute_shared_secret(bob_sk, alice_pk)

    # print("Alice's computed shared secret key:", alice_shared_key)
    # print("Bob's computed shared secret key  :", bob_shared_key)

    # if alice_shared_key == bob_shared_key:
    #     print("Shared secret established successfully.")
    # else:
    #     print("Error: Shared secrets do not match!")


    # # Initialize the secure channel using the shared secret key.
    # secure_channel = SecureChannel(alice_shared_key)

    # # Example: AES encryption/decryption.
    # message = b"Hello, this is a secret message!"
    # encrypted_data = secure_channel.encrypt(message)

    # decrypted_message = secure_channel.decrypt(encrypted_data)
    # print("Decrypted message:", decrypted_message)

    # # Example: Sign/Verify functionality.
    # signature = secure_channel.sign(message)
    # if secure_channel.verify(message, signature):
    #     print("Signature verification succeeded.")
    # else:
    #     print("Signature verification failed.")


if __name__ == "__main__":
    main()
