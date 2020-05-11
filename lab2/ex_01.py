"""This exercise aims to evaluate avalanche effect when simplified AES is implemented using different number of rounds.
 Then, it will see how improperly implemented versions of simplified AES can be easily broken."""

import numpy as np
np.random.seed(124)
import random
random.seed(124)
from AISC_02 import *

#=========================
# Avalanche Effect check
#=========================

def diffusion(key, N=1000):
    """diffusion property check: 2 rounds"""

    hamming_distance_d = []
    ciphertext_ls_d = []
    keyExp(key)  # Key schedule algorithm: expanding key
    plaintext_r = random.getrandbits(16)  # a random 16-bits plaintext
    ciphertext = encrypt(plaintext_r)  # simple AES encryption (just 2 round)
    ciphertext_ls_d.append(ciphertext)

    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        plaintext_e = plaintext_r ^ error  # flip a bit in the plaintext
        ciphertext_ls_d.append(encrypt(plaintext_e))
        hamming_distance_d.append(hamming(ciphertext_ls_d[i], ciphertext_ls_d[i + 1]))

    avg_hamm_dist = np.array(hamming_distance_d).mean()  # 5.934
    return avg_hamm_dist


def confusion(ptext, N=1000):
    """ confusion property check: two rounds"""

    hamming_distance_c = []
    ciphertext_ls_c = []
    r_key = random.getrandbits(16)
    keyExp(r_key)
    ciphertext = encrypt(ptext)
    ciphertext_ls_c.append(ciphertext)
    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        key_e = r_key ^ error  # flip a bit in the plaintext
        keyExp(key_e)
        ciphertext_ls_c.append(encrypt(ptext))
        hamming_distance_c.append(hamming(ciphertext_ls_c[i], ciphertext_ls_c[i + 1]))

    avg_hamm_dist_c = np.array(hamming_distance_c).mean()
    return avg_hamm_dist_c
#====================
# Diffusion
#====================

key = 0b1100010101000110  # a 16-bits key
key_ = 0b0100101011110101
avg_hamm_dist = diffusion(key=key)

#============
# Confusion
#============

plaintext = 0b1010101100001011
avg_hamm_dist_c = confusion(ptext=plaintext)


print('Simplified version of AES with just two rounds:')
print(f'Average Hamming distance (diffusion): {avg_hamm_dist}')
print(f'Average Hamming distance (confusion): {avg_hamm_dist_c}')

# =========================
# three rounds
# =========================

# diffusion
def diffusion_three(key, N=1000):
    """diffusion property check: 3 rounds"""

    hamming_distance_d = []
    ciphertext_ls_d = []
    keyExp(key)  # Key schedule algorithm: expanding key
    plaintext_r = random.getrandbits(16)  # a random 16-bits plaintext
    ciphertext = encrypt_three_rounds(plaintext_r)  # simple AES encryption (just 2 round)
    ciphertext_ls_d.append(ciphertext)

    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        plaintext_e = plaintext_r ^ error  # flip a bit in the plaintext
        ciphertext_ls_d.append(encrypt_three_rounds(plaintext_e))
        hamming_distance_d.append(hamming(ciphertext_ls_d[i], ciphertext_ls_d[i + 1]))

    avg_hamm_dist = np.array(hamming_distance_d).mean()  # 5.934
    return avg_hamm_dist
#confusion
def confusion_three(ptext, N=1000):
    """ confusion property check: three rounds"""

    hamming_distance_c = []
    ciphertext_ls_c = []
    r_key = random.getrandbits(16)
    keyExp(r_key)
    ciphertext = encrypt_three_rounds(ptext)
    ciphertext_ls_c.append(ciphertext)
    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        key_e = r_key ^ error  # flip a bit in the plaintext
        keyExp(key_e)
        ciphertext_ls_c.append(encrypt_three_rounds(ptext))
        hamming_distance_c.append(hamming(ciphertext_ls_c[i], ciphertext_ls_c[i + 1]))

    avg_hamm_dist_c = np.array(hamming_distance_c).mean()
    return avg_hamm_dist_c

avg_hamm_dist = diffusion_three(key=key)
avg_hamm_dist_c = confusion_three(ptext=plaintext)

print('###########################################################')
print('Simplified version of AES with three rounds:')
print(f'Average Hamming distance (diffusion): {avg_hamm_dist}')
print(f'Average Hamming distance (confusion): {avg_hamm_dist_c}')

# =========================
# four rounds
# =========================

# diffusion
def diffusion_four(key, N=1000):
    """diffusion property check: 4 rounds"""

    hamming_distance_d = []
    ciphertext_ls_d = []
    keyExp(key)  # Key schedule algorithm: expanding key
    plaintext_r = random.getrandbits(16)  # a random 16-bits plaintext
    ciphertext = encrypt_four_rounds(plaintext_r)  # simple AES encryption (just 2 round)
    ciphertext_ls_d.append(ciphertext)

    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        plaintext_e = plaintext_r ^ error  # flip a bit in the plaintext
        ciphertext_ls_d.append(encrypt_four_rounds(plaintext_e))
        hamming_distance_d.append(hamming(ciphertext_ls_d[i], ciphertext_ls_d[i + 1]))

    avg_hamm_dist = np.array(hamming_distance_d).mean()  # 5.934
    return avg_hamm_dist
#confusion
def confusion_four(ptext, N=1000):
    """ confusion property check: four rounds"""

    hamming_distance_c = []
    ciphertext_ls_c = []
    r_key = random.getrandbits(16)
    keyExp(r_key)
    ciphertext = encrypt_four_rounds(ptext)
    ciphertext_ls_c.append(ciphertext)
    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        key_e = r_key ^ error  # flip a bit in the plaintext
        keyExp(key_e)
        ciphertext_ls_c.append(encrypt_four_rounds(ptext))
        hamming_distance_c.append(hamming(ciphertext_ls_c[i], ciphertext_ls_c[i + 1]))

    avg_hamm_dist_c = np.array(hamming_distance_c).mean()
    return avg_hamm_dist_c

avg_hamm_dist = diffusion_four(key=key)
avg_hamm_dist_c = confusion_four(ptext=plaintext)

print('###########################################################')
print('Simplified version of AES with four rounds:')
print(f'Average Hamming distance (diffusion): {avg_hamm_dist}')
print(f'Average Hamming distance (confusion): {avg_hamm_dist_c}')

# =========================
# four rounds lazy
# =========================

# diffusion
def diffusion_four_lazy(key, N=1000):
    """diffusion property check: 4 rounds"""

    hamming_distance_d = []
    ciphertext_ls_d = []
    keyExp(key)  # Key schedule algorithm: expanding key
    plaintext_r = random.getrandbits(16)  # a random 16-bits plaintext
    ciphertext = lazy_simplified(plaintext_r)  # simple AES encryption (just 2 round)
    ciphertext_ls_d.append(ciphertext)

    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        plaintext_e = plaintext_r ^ error  # flip a bit in the plaintext
        ciphertext_ls_d.append(lazy_simplified(plaintext_e))
        hamming_distance_d.append(hamming(ciphertext_ls_d[i], ciphertext_ls_d[i + 1]))

    avg_hamm_dist = np.array(hamming_distance_d).mean()  # 5.934
    return avg_hamm_dist
#confusion
def confusion_four_lazy(ptext, N=1000):
    """ confusion property check: four rounds"""

    hamming_distance_c = []
    ciphertext_ls_c = []
    r_key = random.getrandbits(16)
    keyExp(r_key)
    ciphertext = lazy_simplified(ptext)
    ciphertext_ls_c.append(ciphertext)
    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        key_e = r_key ^ error  # flip a bit in the plaintext
        keyExp(key_e)
        ciphertext_ls_c.append(lazy_simplified(ptext))
        hamming_distance_c.append(hamming(ciphertext_ls_c[i], ciphertext_ls_c[i + 1]))

    avg_hamm_dist_c = np.array(hamming_distance_c).mean()
    return avg_hamm_dist_c

avg_hamm_dist = diffusion_four_lazy(key=key)
avg_hamm_dist_c = confusion_four_lazy(ptext=plaintext)

print('###########################################################')
print('Simplified Lazy version of AES with four rounds:')
print(f'Average Hamming distance (diffusion): {avg_hamm_dist}')
print(f'Average Hamming distance (confusion): {avg_hamm_dist_c}')

# =========================
# four rounds very lazy
# =========================

# diffusion
def diffusion_four_very_lazy(key, N=1000):
    """diffusion property check: 4 rounds"""

    hamming_distance_d = []
    ciphertext_ls_d = []
    keyExp(key)  # Key schedule algorithm: expanding key
    plaintext_r = random.getrandbits(16)  # a random 16-bits plaintext
    ciphertext = very_lazy_simplified(plaintext_r)  # simple AES encryption (just 2 round)
    ciphertext_ls_d.append(ciphertext)

    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        plaintext_e = plaintext_r ^ error  # flip a bit in the plaintext
        ciphertext_ls_d.append(very_lazy_simplified(plaintext_e))
        hamming_distance_d.append(hamming(ciphertext_ls_d[i], ciphertext_ls_d[i + 1]))

    avg_hamm_dist = np.array(hamming_distance_d).mean()  # 5.934
    return avg_hamm_dist
#confusion
def confusion_four_very_lazy(ptext, N=1000):
    """ confusion property check: four rounds (very lazy implemetation: MixColumns-ShiftRows and Addkey cancelled"""

    hamming_distance_c = []
    ciphertext_ls_c = []
    r_key = random.getrandbits(16)
    keyExp(r_key)
    ciphertext = very_lazy_simplified(ptext)
    ciphertext_ls_c.append(ciphertext)
    # average hamming distance between ciphertexts
    for i in range(1000):
        error = 1 << random.randrange(16)
        key_e = r_key ^ error  # flip a bit in the plaintext
        keyExp(key_e)
        ciphertext_ls_c.append(very_lazy_simplified(ptext))
        hamming_distance_c.append(hamming(ciphertext_ls_c[i], ciphertext_ls_c[i + 1]))

    avg_hamm_dist_c = np.array(hamming_distance_c).mean()
    return avg_hamm_dist_c

avg_hamm_dist = diffusion_four_very_lazy(key=key)
avg_hamm_dist_c = confusion_four_very_lazy(ptext=plaintext)

"""in general, as expected, diffusion depends on mixcol-row, while confusion changes with addkey"""
print('###########################################################')
print('Simplified Very Lazy version of AES with four rounds:')
print(f'Average Hamming distance (diffusion): {avg_hamm_dist}')
print(f'Average Hamming distance (confusion): {avg_hamm_dist_c}')


# ================================================================
# Improperly implemented block cipher: decrypt ciphertext.txt
# ================================================================
known_plain = 0b0111001001101110
known_cipher = 0b0010111000001101
with open('ciphertext.txt', 'r') as ct:
    encryption = base64.b64decode(ct.read())

print(f'type(encryption) = {type(encryption)}, value: {encryption}')

for i in range(len(encryption)-1):
    cipher = (encryption[i] << 8) + encryption[i+1]

assert cipher == known_cipher

state_1_e = sub4NibList(sBox, intToVec(known_plain))
state_2_e = shiftRow(state_1_e)
state_3_e = intToVec(known_cipher)  # indeed, encryption_foo(ptext) return vecToInt(state_3)=known_cipher

print(f'state_3_e: {state_3_e}, state_2_e: {state_2_e}')

key_p = vecToInt(state_3_e) ^ vecToInt(state_2_e)
assert key_p == 29063

keyExp(key_p)
c_prova = encrypt_foo(known_plain)
assert c_prova == known_cipher

pl = decrypt_foo(c_prova)

encr = bytearray()

b = bin(c_prova)
for i in range(len(b)):
    encr.append(int(b[i])<<8-(int(b[i])+1))

encr_ = base64.b64encode(encr)













