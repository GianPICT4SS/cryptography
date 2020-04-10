"""This exercise aims to evaluate avalanche effect when simplified AES is implemented using different number of rounds.
 Then, it will see how improperly implemented versions of simplified AES can be easily broken."""

import numpy as np
from AISC_02 import *

key = np.binary_repr(2**15 + 564) # key 16-bits size

keyExp(int(key))

plaintext = int(np.binary_repr(2**15 + 522))
ciphertext = encrypt(plaintext)



