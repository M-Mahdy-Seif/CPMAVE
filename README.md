# CPPCDC
This is a python implementation of our protocol CPPCDC: Conditional Privacy-Preserving Protocol for
Cross-Domain Communications in VANET. Our implementation consists of three parts.
## The Cryptographic Overhead Timing
A Python program to calculate the cryptographic overhead time, which comes from the cryptographic primitives in our protocol, such as the SHA-256 hash function, HMAC function, random number generation, AES-CBC mode encryption, fractional Hamming distance, EC point addition, EC scalar multiplication, and bilinear pairing. The measurements were reported based on the performance on two platforms: the Raspberry Pi 1 Model B+ with 512 MB of RAM and 0.7 GHz, and the Raspberry Pi 4 equipped with a 1.5 GHz 64-bit Quad-core ARM Cortex-A72 processor running Raspbian GNU/Linux 11 (bullseye) with Python 3.9.2.

### Running on The Raspberry Pi 1 and Pi 4
First, install the requirements:
```
pip install -r requirements.txt
```

Run the cryptographic primitives on the Raspberry Pi 4. The results will be stored in `PrimitiveComputationTime {iteration}.txt`

```
cd "Raspberry Pi 4 Computation"
python3 computationTime.py <# of iterations>
```

Run the cryptographic primitives on the Raspberry Pi 1. The results will be stored in `PrimitiveComputationTime {iteration}.txt`

```
cd "Raspberry Pi 1 Computation"
python3 computationTime.py <# of iterations>
```


## The Protocol Implementation
A Python implementation of the protocol where the registration for a PAS "Proxy Access Server" is done. Afterwards, the protocol is executed between the sender vehicle and the adminstrative authority. This implementation shows the completeness of our the protocol and the receiving of the message by the adminstrative authority.

### Running the protocol on the Laptop:
```
cd "CPPCDC Implementation"
python3 CAPP.py
```

## The Socket Programming
A Python socket programming implementation of CPPCDC to simulate the flow of our protocol messages between the sender vehicle and the adminstrative aurthority in a real-time experiment and to measure the end-to-end latency. 
The Raspberry Pi $1$ of $0.7$ GHz ARM11 processor and $512$ MB of RAM represents the OBU "On Board Unit" of the sender vehicle while the Intel laptop 11th Gen Core i7-11800H clocked at 2.3 GHz with 16 GB RAM, acts as the PAS  and the Raspberry Pi $4$ represents the adminstrative authority.
### Running the Socket Programming
Start the PAS on the Laptop. The PAS will listen on port 5001:
```
cd "Socket Programming"
python3 CAPP_PAS.py
```
Start the adminstrative authority on the Raspberry Pi 4. The gateway will listen on port 5000. 
```
cd "Socket Programming"
python3 CAPP_FireFighter
```

Start the sender vehicle on the Raspberry Pi 1. The sender vehicle will listen on port 5002.
```
cd "Socket Programming"
python3 CAPP_Vehicle
```
 
