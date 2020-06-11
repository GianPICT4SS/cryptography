import hashlib
from hashlib import blake2b
import os
import secrets
import random
import time
import numpy as np


     
aU = int.from_bytes(b"it is the constant a", byteorder='little')
bU = int.from_bytes(b"it is the constant b", byteorder='big')


# sample DSA parameters for 1024-bit key from RFC 6979

pDSA = 0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779

qDSA = 0x996F967F6C8E388D9E28D01E205FBA957A5698B1

gDSA = 0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD




def egcd(a, b):
    """computes g, x, y such that g = GCD(a, b) and x*a + y*b = g"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(a, m):
    """computes a^(-1) mod m"""
    g, x, y = egcd(a % m, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def get_x_bytes_of_hash(message, x):

    return hashlib.sha256(message).digest()[:x]

def get_bytesArray_from_int(n_bits, x):

    n_byte = int(n_bits/8) + 1
    return x.to_bytes(n_byte, byteorder='big')



def check_collision(n, k):
    # n is the number of bit length of the input msg

    # counters
    C_1 = C_2 = {}
    uC_1 = uC_2 = {}

    m0 = None
    m1 = None

    # initial string
    x = secrets.randbits(n + 8)


    for z in range(k):
        C_1[z+1] = 0
        C_2[z+1] = 0
        uC_1[z+1] = 0
        uC_2[z+1] = 0

        x_0 = get_bytesArray_from_int(n, x)
        print(f'bytearray of x: {x_0} \n x len bit: {x.bit_length()}')

        # get 4 bytes of hash x_0 and x_1
        x_1 = get_x_bytes_of_hash(x_0, z+1)
        x_2 = get_x_bytes_of_hash(x_1, z+1)
        ux_1 = universal_hash(msg=x_0, digest_length=z+1)
        ux_2 = universal_hash(msg=ux_1, digest_length=z+1)
        # loop until our hashes are equal
        while x_1 != x_2:
            x_1 = get_x_bytes_of_hash(x_1, z+1)
            x_2 = get_x_bytes_of_hash(get_x_bytes_of_hash(x_2, z+1), z+1)
            C_1[z+1] += 1
        print(f'type {ux_1}: {type(ux_1)}')
        while ux_1 != ux_2:
            ux_1 = universal_hash(ux_1, digest_length=z+1)
            ux_2 = universal_hash(msg=universal_hash(ux_2, digest_length=z+1), digest_length=z+1)
            uC_1[z+1] += 1
        # Now H^i(x_0) == H^{2i}(x_0)
        print(f'H^i(x_0): {x_1}, H^(2i)(x_0) = {x_2}')
        print(f'found collision in {z+1} bytes string after: {C_1[z+1]} tries')

        # Now H^i(x_0) == H^{2i}(x_0)
        x_1 = x_0
        ux_1 = x_0
        # Loop until they match again ...
        x_1 = get_x_bytes_of_hash(x_1, z+1)
        x_2 = get_x_bytes_of_hash(x_2, z+1)
        ux_1 = universal_hash(msg=ux_1, digest_length=z+1)
        ux_2 = universal_hash(msg=ux_2, digest_length=z+1)
        while x_1 != x_2:
            m0 = x_1
            x_1 = get_x_bytes_of_hash(x_1, z+1)
            x_2 = get_x_bytes_of_hash(x_2, z+1)
            C_2[z+1] += 1
        print(f'the first {z+1} bytes of the sha256 hash of {m0} are equal to {x_2}')

        while ux_1 != ux_2:
            ux_1 = universal_hash(msg=ux_1, digest_length=z+1)
            ux_2 = universal_hash(msg=ux_2, digest_length=z+1)
            uC_2[z+1] += 1


        #x_2 = get_x_bytes_of_hash(x_1, z+1)
        #while x_1 != x_2:
        #    m1 = x_2
        #    x_2 = get_x_bytes_of_hash(x_2, z+1)
        #print(f'the first {z+1} bytes of the sha256 hash of {m1} are equal to {x_2}')
        #x_1 = get_x_bytes_of_hash(x_0, z+1)
        #x_2 = get_x_bytes_of_hash(x_1, z+1)

    print(f'm0: {m0}, m1: {m1}, C0: {C_1}, C1: {C_2}')

    return C_1, C_2, m0, m1, uC_1, uC_2


def universal_hash(a=aU, b=bU, q=qDSA, msg=b'SHA-256 is a cryptographic hash function', digest_length=2):

    m = int.from_bytes(msg, byteorder='big')
    h = (a*m + b) % q
    assert h.bit_length() <= q.bit_length()
    hash = h.to_bytes(int(q.bit_length()/8), byteorder='big')
    return hash[:digest_length]





    

def main():
    print('(p-1) mod q:', (pDSA - 1) % qDSA)
    print('g^q mod p:', pow(gDSA, qDSA, pDSA))
    
    message = b"SHA-256 is a cryptographic hash function"
    m = hashlib.sha256()
    m.update(message)
    hash = m.digest()

    m.update(b"Ciaone")
    hash_1 = m.digest()
    
    print(f'hash of {message} is {hash}, instead hash_2: {hash_1}')
    print('32 bit hash is:', hash[:4])
    print('64 bit hash is:', hash[:8])

    start = time.time()
    c0, c1, m0, m1, uC1, uC2 = check_collision(n=4*32, k=4)
    elapsed = time.time() - start
    print(f'c0= {c0}, c1= {c1}; elapsed time: {elapsed} \n uc1={uC1}, uc2={uC2}')
    return c0, c1, m0, m1
    
   
    

if __name__ == '__main__':
    uh = universal_hash()
    print(f'Universal hash digest: {uh}')
    c0, c1, m0, m1, uC1, uC2 = main()
