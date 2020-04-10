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

#====================
# Diffusion
#====================
hamming_distance_d = []
ciphertext_ls_d = []
key = 0b1100010101000110  # a 16-bits key
keyExp(key)  # Key schedule algorithm: expanding key
plaintext_r = random.getrandbits(16)  # a random 16-bits plaintext
ciphertext = encrypt(plaintext_r)  # simple AES encryption (just 2 round)
ciphertext_ls_d.append(ciphertext)

# average hamming distance between ciphertexts
for i in range(1000):
    error = 1 << random.randrange(16)
    plaintext_e = plaintext_r ^ error  # flip a bit in the plaintext
    ciphertext_ls_d.append(encrypt(plaintext_e))
    hamming_distance_d.append(hamming(ciphertext_ls_d[i], ciphertext_ls_d[i+1]))

avg_hamm_dist = np.array(hamming_distance_d).mean()  # 5.934

#============
# Confusion
#============
hamming_distance_c = []
ciphertext_ls_c = []
plaintext = 0b1010101100001011
r_key = random.getrandbits(16)
keyExp(r_key)
ciphertext = encrypt(plaintext)
ciphertext_ls_c.append(ciphertext)
# average hamming distance between ciphertexts
for i in range(1000):
    error = 1 << random.randrange(16)
    key_e = r_key ^ error  # flip a bit in the plaintext
    keyExp(key_e)
    ciphertext_ls_c.append(encrypt(plaintext))
    hamming_distance_c.append(hamming(ciphertext_ls_c[i], ciphertext_ls_c[i+1]))

avg_hamm_dist_c = np.array(hamming_distance_c).mean()

print('Simplified version of AES with just two rounds:')
print(f'Average Hamming distance (diffusion): {avg_hamm_dist}')
print(f'Average Hamming distance (confusion): {avg_hamm_dist_c}')



