import argparse
import socket, pickle
import os
import hashlib

# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey
import hashlib
import time

# The HMAC function
from Crypto.Hash import HMAC
import hmac

from PrimitivePackage.Primitives import *

#Identity from registration.py
Sender_Identity= 6330614295947393657856040725909354215571545936334951160496604125994438196162

Receiver_Identity= 8169104755805935683608881213542562938956147541291769502712984486856835317573

Sender_priv_key= 62718740499567001559645896635471998470595369862886026081752443059900420476791

Sender_pub_key_X= 0xf81cc47e2caf24468ddf86ab9279c14bae235a07c5c2f960a1ba395ffc14d2b6
Sender_pub_key_Y= 0xd8d7dab908578b5aa9f87118662117587bd44f38b8d67eb0e9b4439f04f8a723
PAS_pub_key=Point(Sender_pub_key_X, Sender_pub_key_Y, curve=P256)

P_g_X= 0x6d1973e8554c68424fc51542ff8b0fe6a84bd7c88f2e2f19f4d0712a13604d55
P_g_Y= 0xe64e6122ce7a70e26f7496510ea93fb5730a9894448d1a6b4bd15da8c08cfdc0
PAS_pub_key=Point(P_g_X, P_g_Y, curve=P256)



parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='CA server to connect to') 
args = parser.parse_args()


def Vehicle_program():
    PAS_socket = socket.socket()  # get instance
    Ambulance_socket = socket.socket()  # get instance

    # get the hostname
    bind_address = '127.0.0.1'
    port = 5000  # initiate port no above 1024
    host = args.connect # CA server
        
    PAS_socket.connect((bind_address, port))  # connect to the server

    # first step: sending Identity of the sender and receiver to the PAS
    message = SendID_Sender_Receiver()
    PAS_socket.send(pickle.dumps(message))    
    print('Vehicle: step 1: sent to PAS: ' + str(message))

    # Second step: Receiving the encrypted nonce from the PAS
    data = PAS_socket.recv(2048)         
    print('Vehicle: step 2: received from PAS: ')
    print(pickle.loads(data))  # show in terminal

    # does the decryption and the increment of the nonce
    
    r_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
    z_a = int.from_bytes(os.urandom(1024),'big')%P256.q
    A = r_1*z_a*P256.G

    message = Send_A_IncrementedNonce()

    # Third step: sending A and the encrypted incremented nonce to the PAS
    PAS_socket.send(pickle.dumps(message))    
    print('Vehicle: step 3: sent to PAS: ' + str(message))

    # Fourth step: Receiving sigma_1 and B
    data = PAS_socket.recv(2048)         
    print('Vehicle: step 4: received from PAS: ')
    print(pickle.loads(data))  # show in terminal

    # Compute I_p and sigma_t
    I_p=Hash(Receiver_Identity,A.x,A.y,ExpiryPeriod,B.y)
    sigma_t=I_p*PAS_sigma+h_tr*PAS_priv_key+PAS_priv_key 

    print("Vehicle: Creating new socket for the firefighter")

    bind_address = '127.0.0.1'
    port = 5001  # initiate port no above 1024
    

    # Ambulance_socket.connect((bind_address, port))  # connect to the server
    # Ambulance_socket.send(pickle.dumps("Hello Msg to the Ambulance Department"))


    

def SendID_Sender_Receiver():
    return Sender_Identity, Receiver_Identity

def Send_A_IncrementedNonce():
    return A, Receiver_Identity

if __name__ == '__main__':
    Vehicle_program()
