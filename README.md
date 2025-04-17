
### Lightweight Authentication Mechanism for CAIoT

I am extending the work presented in this [paper](https://ieeexplore.ieee.org/document/10114980) by proposing a scheme for a lightweight authentication mechanism in Cloud-Assisted IoT systems.

Specifically, I propose the use of Elliptic Curve Cryptography (ECC) in combination with Identity-Based Encryption (IBE). The scheme utilizes the BN254 elliptic curve.

The following outlines the operation of the proposed system:

A user creates an account on the cloud server. During account creation, the user registers their smartphone to enable login through both a password and biometric verification. The user then adds the identities of their smart IoT devices and sets access privileges, specifying which smart devices are allowed to communicate with others. This access information is securely stored in the cloud server's database for future use.

To register with the cloud server, a smart IoT device sends an unencrypted request that includes the device's identity and a public ephemeral key to be used for Elliptic Curve Diffie–Hellman (ECDH) key exchange. The server generates a master public key, a master secret key, and a partial private key corresponding to the device's identity for use with IBE. The server encrypts the partial private key, the master public key, and its own IBE public key using the symmetric key derived from the ECDH key exchange. It then sends this encrypted data along with its own ephemeral public key to the device.

Upon receiving the message, the smart IoT device computes the shared ECDH key and decrypts the message to retrieve its partial key and the server’s public key. The device then generates its key pair using the partial key and the master public key. This key pair is securely stored on the device. The device also sends its public key to the server, which saves it in a secure database for later use. All future communications between the server and the device are encrypted using the identity-based asymmetric keys that were just established.

When a smart IoT device wishes to access another smart device, it sends an encrypted request to the server. The request includes the identities of both the requesting and the target devices. The server first verifies the identity of the requesting device. If it can decrypt the message using the stored public key associated with the claimed identity, this confirms the authenticity of the requester.

The server then checks the database to verify whether the requesting device has access rights to communicate with the target device. If access is permitted, the server generates a random session token and a timestamp, encrypts this information separately for each device using their respective public keys, and sends the encrypted token, timestamp, and the peer device’s public key to both devices.

The requesting device then encrypts a message—containing the token, timestamp, and additional data—using the peer device’s public key and its own private key, and sends this ciphertext to the target device.

Upon receiving the message, the target device decrypts it using its own private key and the public key of the sending device (as provided by the server). This confirms the authenticity of the sending device. The target device then verifies the token and checks the timestamp to guard against replay attacks. Upon successful verification, the device proceeds to process the received message.
