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
import json

#Identity from registration.py

Receiver_Identity= 8169104755805935683608881213542562938956147541291769502712984486856835317573
Receiver_priv_key= 3822204222889312141452796624401703944169653051092257917058141841645549240302
Receiver_pub_key_X= 0x6880bbbb54c1a66f3618249d550fa629ec31eece9a3be989e6093ac1b790dbb2
Receiver_pub_key_Y= 0xa315167d2f09b9a27b0fe53fc96b47eea13bc8deaea8c50cabde9428e8683d03
Receiver_pub_key=Point(Receiver_pub_key_X, Receiver_pub_key_Y, curve=P256)


P_g_X= 0x6d1973e8554c68424fc51542ff8b0fe6a84bd7c88f2e2f19f4d0712a13604d55
P_g_Y= 0xe64e6122ce7a70e26f7496510ea93fb5730a9894448d1a6b4bd15da8c08cfdc0
Receiver_pub_key=Point(P_g_X, P_g_Y, curve=P256)


# The Socket programming
parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='server to connect to') 
parser.add_argument('-i', '--iterations', default=1, help='how many tim to run') 
args = parser.parse_args()

def Ambulance_program():

    Veh_socket = socket.socket()  # instantiate
    host = args.connect # as both code is running on same pc
    # iterations = int(args.iterations) # how many time to run
    bind_address = '0.0.0.1'
    port = 5001  # socket server port number

    # look closely. The bind() function takes tuple as argument
    Veh_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    Veh_socket.listen(10)
    
    # i = 0

    while True:
    
        conn, address = Veh_socket.accept()  # accept new connection
        print("Ambulance:Connection from: " + str(address))
        message = ""
        #Step 1: Receive Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5 from the gateway
        data = conn.recv(2048) 
        print("Ambulance:The received data from the vehicle", data)            
        


    
if __name__ == '__main__':
    Ambulance_program()
