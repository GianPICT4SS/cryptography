import hashlib
import os
import secrets
import random


     
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


def check_collision(n):
    # n is the number of bit length of the input msg

    C_1 = C_2 = 0
    H = hashlib.sha256()
    x = secrets.randbits(n+8)
    print(f'random number: {x}')
    n_byte = int(n/8) + 1
    assert type(n_byte) == int
    x_0 = x.to_bytes(n_byte, byteorder='big')
    print(f'bytearray of x: {x_0}')
    H.update(x_0)
    x_1 = H.digest()  # Hash of x_0
    print(f'Hash of {x_0}: {x_1}')
    print(f'x_1: {x_1}')
    H.update(x_1)
    x_2 = H.digest()  # Hash of x_1
    print(f'Hash of {x_1}: {x_2}')
    while x_1 != x_2:
        H.update(x_1)
        x_1 = H.digest()  # H(x_1)
        x_1 = x_1[:1]
        H.update(x_2)
        x_2 = H.digest()  # H(x_2)
        x_2 = x_2[:1]
        C_1 += 1
        print(f'C_1: {C_1}')

    x_1 = x_0
    H.update(x_1)
    x_1 = H.digest()
    H.update(x_2)
    x_2 = H.digest()
    while x_1 != x_2:
        H.update(x_1)
        x_1 = H.digest()
        x_1 = x_1[:1]
        H.update(x_2)
        x_2 = H.digest()
        x_2 = x_2[:1]
        C_2 += 1
        print(f'C_2: {C_2}')

    return C_1, C_2




    

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


    c0, c1 = check_collision(n=8*32)
    print(f'c0= {c0}, c1= {c1}')
    
   
    

if __name__ == '__main__':
    main()
