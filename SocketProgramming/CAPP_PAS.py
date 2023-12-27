import argparse
import socket, pickle
import os
# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey

import hashlib
import time

from Primitives import *

#PAS identities from registration.py

PAS_Identity= 13385647806998004153020035149177702292929509406886890249193697053202672561527

PAS_priv_key= 27035679567817885497930140100479440063071582958031951165314744143627511123473
PAS_pub_key_X= 0x6aadbccb88ad8839c21e7a3754e42f7281eeb2b75a07358f6889eef9030c1793
PAS_pub_key_Y= 0x869e40c7c429fa96ddc6ad3576224ff5bd95c55a68224a0d1f734e4786443af5
PAS_pub_key=Point(PAS_pub_key_X, PAS_pub_key_Y, curve=P256)

PAS_sigma= 25106535378440752376581550080743121753402285117385170558988665032551770271000

PAS_C_a_X= 0xb617e0900b2d6304a11d7a99e27e7498483b6563b47c1ee06dd2dc73e62408fb
PAS_C_a_Y= 0x90dcbf5075f41420fc7a51b078dfbe2a1b401d6d431e7df45072a8134186cae6
PAS_C_a=Point(PAS_pub_key_X, PAS_pub_key_Y, curve=P256)

Y_a_C_a_X= 0x3dda16e64b2fde142872b07e2a28271ac3b014425e15575caa405bdfb6052b94
Y_a_C_a_Y= 0xc797bb1d4a12fedc152c3b2aedb1f34a12537b6b5ec388502bdc2825565d2d
Y_a_C_a=Point(PAS_pub_key_X, PAS_pub_key_Y, curve=P256)

P_g_X= 0x6d1973e8554c68424fc51542ff8b0fe6a84bd7c88f2e2f19f4d0712a13604d55
P_g_Y= 0xe64e6122ce7a70e26f7496510ea93fb5730a9894448d1a6b4bd15da8c08cfdc0
P_g=Point(P_g_X, P_g_Y, curve=P256)

Receiver_pub_key_X= 0x6880bbbb54c1a66f3618249d550fa629ec31eece9a3be989e6093ac1b790dbb2
Receiver_pub_key_Y= 0xa315167d2f09b9a27b0fe53fc96b47eea13bc8deaea8c50cabde9428e8683d03
Receiver_pub_key=Point(Receiver_pub_key_X, Receiver_pub_key_Y, curve=P256)

Sender_pub_key_X= 0xf81cc47e2caf24468ddf86ab9279c14bae235a07c5c2f960a1ba395ffc14d2b6
Sender_pub_key_Y= 0xd8d7dab908578b5aa9f87118662117587bd44f38b8d67eb0e9b4439f04f8a723
Sender_pub_key=Point(Sender_pub_key_X, Sender_pub_key_Y, curve=P256)



# The Socket programming
parser = argparse.ArgumentParser(description = 'Server CA for IoT Simulation')
args = parser.parse_args()

def PAS_program():

    Veh_socket = socket.socket()  # get instance
    host = '127.0.0.1'
    port = 5000  # socket server port number

    # look closely. The bind() function takes tuple as argument
    Veh_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    Veh_socket.listen(10)    

    while True:
    
        conn, address = Veh_socket.accept()  # accept new connection
        print("PAS:Connection from: " + str(address))

        #Step 1: Receiving the identity of the sender and receiver from the Veghicle
        data = conn.recv(2048)         
        print('PAS: step 1: received from Vehicle: ')
        print(pickle.loads(data))  # show in terminal
        message=pickle.loads(data)
        Sender_Identity=message[0]
        Receiver_Identity=message[1]
        print('The sender:', Sender_Identity)
        print("The receiver:", Receiver_Identity)

        Nonce = int.from_bytes(os.urandom(1024),'big')%P256.q
        message = Encrypt_nonce_Send_Receiver_Identity(Nonce)

        #Step 2: sending Encrypted Nonce and the public key of the receiver to the vehicle
        conn.send(pickle.dumps(message)) 
        print("PAS:The sent data to the vehicle", message)

        #Step 3: Receiving A||ID_s||Encryption of the incremneted nonce from the Veghicle
        data = conn.recv(2048)         
        print('PAS: step 3: received from Vehicle: ')
        print(pickle.loads(data))  # show in terminal


        #computing sigma_1
        message=ComputingSigma_1(Sender_Identity,Receiver_Identity)
        #Step 4: sending sigma_1 and B to the vehicle
        conn.send(pickle.dumps(message)) 
        print("PAS:The sent data to the vehicle", message)
             

def Encrypt_nonce_Send_Receiver_Identity(Nonce):
    iv = Random.new().read(AES.block_size)
    PAS_key=PAS_priv_key*Sender_pub_key
    Nonce_encrypted, PAS_EncKey= AES_Enc_using_Key(PAS_key,iv,Nonce)
    return iv, Nonce_encrypted, Receiver_pub_key

def ComputingSigma_1():
    hash_sigma_a=Hash(PAS_sigma)
    h_tr=Hash(Sender_Identity,Receiver_Identity,hash_sigma_a,A.x,A.y)
    B=h_tr*PAS_pub_key

    # Compute I_p and sigma_t
    I_p=Hash(Receiver_Identity,A.x,A.y,ExpiryPeriod,B.y)
    sigma_t=I_p*PAS_sigma+h_tr*PAS_priv_key+PAS_priv_key
    return sigma_t, B


if __name__ == '__main__':
    PAS_program()
