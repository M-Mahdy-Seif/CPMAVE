from fastecdsa.curve import Curve
from fastecdsa import curve, ecdsa, keys

from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from fastecdsa import curve, ecdsa, keys
from hashlib import sha384
import binascii

import hashlib
import os 
import sys
import time

def Hash(*dataListByte):
    h = hashlib.new('sha256')
    Mydata=b""
    for data in dataListByte:
        #print("Data: ",data)
        Mydata = Mydata + data.to_bytes(32, 'big')
    h.update(Mydata)
    HashResult=h.hexdigest()
    Hash_value=int(HashResult,16)%P256.q
    return Hash_value

def Registration_With_KGC(KGC_priv_key):
    KGC_yA_priv_key, KGC_yA_pub_key = keys.gen_keypair(curve.P256)
    h_a=Hash(KGC_yA_priv_key)
    C_a=h_a*KGC_yA_priv_key*P256.G
    sigma=(KGC_priv_key+h_a*KGC_yA_priv_key+KGC_yA_priv_key)%P256.q
    return C_a,sigma, KGC_yA_pub_key

def AES_Enc_using_Key(Key, iv, message):
    #converting the key from a point to a string
    h = hashlib.new('sha256')
    h.update(Key.x.to_bytes(32, 'big')+Key.y.to_bytes(32, 'big'))
    HashResult=h.hexdigest()
    EncKey=bytes(h.hexdigest(),'utf-8')

    #The Encryption
    ENC = AES.new(EncKey[:16], AES.MODE_CBC, iv)
    Msg_encrypted=ENC.encrypt(message.to_bytes(32,'big'))

    return Msg_encrypted, EncKey

def AES_Dec_using_Key(Key, iv, Cipher):
    #converting the key from a point to a string
    h = hashlib.new('sha256')
    h.update(Key.x.to_bytes(32, 'big')+Key.y.to_bytes(32, 'big'))
    HashResult=h.hexdigest()
    DecKey=bytes(h.hexdigest(),'utf-8')

    #The Decryption
    DEC = AES.new(DecKey[:16], AES.MODE_CBC, iv)
    Cipher_decrypted=int.from_bytes(DEC.decrypt(Cipher),'big')

    return Cipher_decrypted, DecKey