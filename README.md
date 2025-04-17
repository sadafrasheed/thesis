
### Lightweight Authentication Mechanism for CAIoT

I am extending the work done in this [paper](https://ieeexplore.ieee.org/document/10114980) and proposing a scheme for lightweight authentication mechanism in Cloud Assisted IoT.

I am proposing to use Eliptic curve cryptography with Identity-based encryption. I am using BN254 elliptic curve.

The following is how my system works.

A user creates an account on Cloud server. While creating an account, he registers his smart phone so that he can login via password and biometric varification. The user, then adds identities of his smart IoT devices and set the access priveleges, which smart device can access which of the other smart devices. The database saves this access information in its secure database to be used later.
 
In order to register with Cloud Server, the smart IoT devices sends an unencrypted request to the server. This request includes smart device identity and a public ephemeral key to be used in ECDH key exchange. The server generates master public key, master secret key and device's partilal key against the sent identity to be used with IBE. The server encrypts partial secret key and master public key and its own IBE public key using the ECDH symmetic shared key. It then send this encrypted keys and it's ephemeral public key used in ECDH key exchange. The smart IoT device generates the DH shared key and decrypts the message to get it's partial key and server's public key. The device then generates it's keys pair using partial key and master public key. The device securely saves it's key pair and sends public key to the server which saves it in secure database for later use. All future communication between server and smart device is encrypted using the just shared Identity-based asymmetric keys. 

When a smart IoT device wants to access another smart IoT device, it sends encrypted request the server. The request includes it's own and the requested peer device's identity. The server first verifies the requestee. If server can decrypt the message using the public key it has saved against the requestee device, that means the requesting device is infact the one it claims to be. Next the server checks it database for requesting device's access to the requested device. If the server finds the access record, it generates a random session token and a timestamp, encrypts it for both requesting and requested devices and send the encrypted token+timestamp and public key of other device to both the devices. The requesting device uses peer device's public key and it's own private key to encrypt the message, which includes token and timestamp in addition to other data and send this ciphertext to the peer device.

The peer device upon getting the message, decrypts it using the it's own private key and the public key of sending device shared by the server. This proves the validity of sending device. Next the receiving device, matches the token and verifies the timestamp to avoid replay attack. Upon successful varifications, the device moves on to process the message recieved.
