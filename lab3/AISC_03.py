import sys
import os
import time
import json

from random import randrange, getrandbits, randint
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# 2048-bit group of order q based on Z_p^* with p=2*q+1, p,q primes
# p, q, g as recommended in RFC 7919 for Diffie-Hellman key exchange

pDH = 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF

# generator of the subgroup of Z_p^* of order q
gDH = 2

qDH = 0x7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C30942E4BFFFFFFFFFFFFFFFF



def encryptAESCTR(key, plaintext):
    """Encrypts plaintext using AES-CTR mode with given key
       key:       bytes-like object, should be 16, 24, or 32 bytes long
       plaintext: bytes-like object
       return iv, ciphertext as bytes-like objects
    """
    # 128-bit iv, securely generated
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)
    
    
def decryptAESCTR(key, iv, ciphertext):
    """Decrypts ciphertext encrypted using AES-CTR mode with given key and iv
       key:        bytes-like object, should be 16, 24, or 32 bytes long
       iv:         bytes-like object, should be 16 bytes long
       ciphertext: bytes-like object
       return plaintext as bytes-like object
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
    



    
def generate_prime_candidate(length):
    """ Generate an odd integer via secure random generator
        Args:
            length -- int -- the length of the number to generate, in bits
        return an odd integer in range(sqrt(2)*2^(length-1), 2^length)
    """
    mask = (1 << length) - 1
    offs = 1.4142135623731 * (1 << (length-1))
    p = 0
    while p < offs:
        # generate big integer from random bytes
        p = int.from_bytes(os.urandom((length+7)//8), byteorder='little')
        # apply a mask to limit to length bits
        p &= mask
    # apply a mask to set LSB to 1
    p |= 1
    return p
    
    

    
def encodeText(s, bitlen):
    """Encode string s in a list of positive integers each representable with bitlen-8 bits (bitlen // 8 - 1 bytes)"""
    sbytes = bytearray(s.encode('utf-8'))
    # do not use most significant byte
    bytelen = (bitlen // 8) - 1
    m = []
    while len(sbytes) > bytelen:
        m.append(int.from_bytes(sbytes[:bytelen], byteorder='little'))
        sbytes[:bytelen] = []
    m.append(int.from_bytes(sbytes, byteorder='little'))
    return m
    
    
def decodeText(m, bitlen):
    """Decode a list of positive integers each representable with bitlen-8 bits (bitlen // 8 - 1 bytes) into a string s.
        Ensures decodeText(encodeText(s, bitlen), bitlen) == s"""
    # do not use most significant byte
    bytelen = (bitlen // 8) - 1
    mbytes = bytearray()
    for x in m:
        mbytes += x.to_bytes(bytelen, byteorder='little')
    return mbytes.rstrip(b'\x00').decode('utf-8')

def miller_rabin(n, k):
    """Implementation uses the Miller-Rabin Primality Test. The optimal number of rounds for this test is 40"""

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1

    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):

        a = randrange(2, n - 1)

        x = pow(a, s, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break

        else:
            return False

    return True


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x

def main():
    keylen = 1024
    p = 2
    q = 2
    while 1:
        p = generate_prime_candidate(keylen//2)
        if miller_rabin(p, k=100):
            while 1:
                q = generate_prime_candidate(keylen//2)
                if miller_rabin(q, k=100):
                    break
            break

    N = p*q
    try:
        assert N.bit_length() == keylen
    except AssertionError:
        print('N generation error:')
        print('size of N is', N.bit_length(), 'bits instead of', keylen)
        sys.exit(1)
        
    print('p:', p)
    print('q:', q)
    print('N:', N)
    print('Generate a integer e relatively prime with (p-1)(q-1)')
    phiN = (p-1)*(q-1)
    e = randint((keylen // 2), (pow(2, 16)+1))
    print(f'e: {e}')
    g = 0
    while g != 1:
        g, x, y = egcd(e, phiN)



    d = x % phiN  # private key
    print(f'Found d = x & phiN = {d}')
    assert (d*e) % phiN == 1




    
    s = "Today’s programs need to be able to handle a wide variety of characters. Applications are often internationalized to display messages and output in a variety of user-selectable languages; the same program might need to output an error message in English, French, Japanese, Hebrew, or Russian. Web content can be written in any of these languages and can also include a variety of emoji symbols. Python’s string type uses the Unicode Standard for representing characters, which lets Python programs work with all these different possible characters."
    
    
    print('s:', s)
    m = encodeText(s, keylen)
    print('m:', m)
    
    #integers in m can be safely encrypted using a RSA key on keylen bits
    
    s2 = decodeText(m, keylen)
    print('decoded m:', s2)
    try:
        assert s == s2
    except AssertionError:
        print('message decoding error:')
        print('message is:')
        print(s)
        print('decoded message is:')
        print(s2)
        sys.exit(1)
    

    
    key = os.urandom(16)
    plaintext = s.encode('utf-8')
    
    # first call may take longer to execute due to crypto library initializations
    start_time = time.time()
    (iv, ciphertext) = encryptAESCTR(key, plaintext)
    elapsed_time = time.time() - start_time
    print('AES encryption time (first call):', elapsed_time)
    
    start_time = time.time()
    plaintext = decryptAESCTR(key, iv, ciphertext)
    elapsed_time = time.time() - start_time
    print('AES decryption time:', elapsed_time)
    
    plaintext = s.encode('utf-8')
    # this call should be much faster
    start_time = time.time()
    (iv, ciphertext) = encryptAESCTR(key, plaintext)
    elapsed_time = time.time() - start_time
    print('AES encryption time (second call):', elapsed_time)
    
    start_time = time.time()
    plaintext = decryptAESCTR(key, iv, ciphertext)
    elapsed_time = time.time() - start_time
    print('AES decryption time:', elapsed_time)
    
    try:
        assert s == plaintext.decode('utf-8')
    except AssertionError:
        print('AES error:')
        print('message is:')
        print(s)
        print('decrypted message is:')
        print(plaintext.decode('utf-8'))
        sys.exit(1)

    print(f'Public Key: N = {N}, e = {e}')
    print(f'Private Key: N = {N}, d = {d}')
    dict_ = {'Public-Key': {'N': N, 'e': e},
             'Private-key': {'N': N, 'd': d}}

    with open('./config.json', 'w') as f:
        msg = json.dumps(dict_)
        f.write(msg)

    
    
    
if __name__ == '__main__':
    main()
