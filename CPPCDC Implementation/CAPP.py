from ..SocketProgramming.Primitives import *

#######     PAS identity & Keys     ################# 
PAS_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
PAS_priv_key, PAS_pub_key = keys.gen_keypair(curve.P256)

###############       sender Identity & Keys      ##################### 
Sender_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
Sender_priv_key, Sender_pub_key = keys.gen_keypair(curve.P256)

###############       Receiver Identity & Keys      #####################
Receiver_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
Receiver_priv_key, Receiver_pub_key = keys.gen_keypair(curve.P256)

###############     The Generation of the KGC keys      ##################
_one_KGC_priv_key, _one_KGC_pub_key = keys.gen_keypair(curve.P256)
_two_KGC_priv_key, _two_KGC_pub_key = keys.gen_keypair(curve.P256)
_three_KGC_priv_key, _three_KGC_pub_key = keys.gen_keypair(curve.P256)

#############################################################################
##################     PAS Registration   ###################################
#############################################################################

###########     PAS registration with 1st KGC      ##################
C_a_1, sigma_1, KGC_1_yA_pub_key = Registration_With_KGC(_one_KGC_priv_key)

###########     PAS registration with 2nd KGC      ##################
C_a_2, sigma_2, KGC_2_yA_pub_key = Registration_With_KGC(_two_KGC_priv_key)

###########     PAS registration with 3rd KGC      ##################
C_a_3, sigma_3, KGC_3_yA_pub_key = Registration_With_KGC(_three_KGC_priv_key)

###########     PAS credentials     ##################
PAS_sigma=(sigma_1+sigma_2+sigma_3)%P256.q
PAS_C_a=C_a_1+C_a_2+C_a_3
Y_a_C_a=KGC_1_yA_pub_key+KGC_2_yA_pub_key+KGC_3_yA_pub_key

###########     The accumulated Public key      ##################
P_g=_one_KGC_pub_key+_two_KGC_pub_key+_three_KGC_pub_key

#############################################################################
#######    OBTAINING SIGNATURE FROM PAS   ###################################
#############################################################################

Nonce = int.from_bytes(os.urandom(1024),'big')%P256.q

############    Encryption of the nonce with H(privatePAS_PublicVehicle)    ##############

iv = Random.new().read(AES.block_size)
PAS_key=PAS_priv_key*Sender_pub_key

Nonce_encrypted, PAS_EncKey= AES_Enc_using_Key(PAS_key,iv,Nonce)

# The Expiry Period

ExpiryPeriod=int.from_bytes(os.urandom(1024),'big')%P256.q
r_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
z_a = int.from_bytes(os.urandom(1024),'big')%P256.q
A = r_1*z_a*P256.G

###############     Decryption of the nonce using H(privateVehicle_publicPAS)   #########

vehicle_key=Sender_priv_key*PAS_pub_key
Nonce_decrypted, Vehicle_DecKey= AES_Dec_using_Key(vehicle_key,iv,Nonce_encrypted)
Nonce_incremented=Nonce_decrypted+1

###############     Encryption of the Nonce+1  on the Vehicle   #############################
Nonce_incremented_encrypted, Vehicle_EncKey= AES_Enc_using_Key(vehicle_key,iv,Nonce_incremented)

#############       Decryption of the nonce on the PAS      ##############################
ReceivedIncrementedNonce, Vehicle_DecKey= AES_Dec_using_Key(PAS_key,iv,Nonce_incremented_encrypted)

############################################################################################
hash_sigma_a=Hash(PAS_sigma)
h_tr=Hash(Sender_Identity,Receiver_Identity,hash_sigma_a,A.x,A.y)
B=h_tr*PAS_pub_key

# Compute I_p and sigma_t
I_p=Hash(Receiver_Identity,A.x,A.y,ExpiryPeriod,B.y)
sigma_t=I_p*PAS_sigma+h_tr*PAS_priv_key+PAS_priv_key

################################################################################
###########   UAV sending Msg to Authority   #####################################
################################################################################

r_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
r_3 = int.from_bytes(os.urandom(1024),'big')%P256.q

P_1= r_2*P_g
P_2= r_2*PAS_C_a
P_3= r_2*Y_a_C_a
P_4= r_2*B
P_5= r_2*PAS_pub_key
T_1=r_3*P_g

I_c=Hash(A.x,A.y,P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,T_1.x,T_1.y)
sigma_2= (r_2*sigma_t+I_c*r_1*z_a)%P256.q
s_1=(r_3+I_c*r_2)%P256.q

print("The verification of s_1",s_1*P_g==(T_1+I_c*P_1))
print("The verification of the IoT authentication token",sigma_t*P256.G==(I_p*P_g+I_p*PAS_C_a+I_p*Y_a_C_a+B+PAS_pub_key))
print("The verification of sigma_2",sigma_2*P256.G==(I_p*P_1+I_p*P_2+I_p*P_3+P_4+P_5+I_c*A))