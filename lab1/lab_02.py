
import numpy as np
from lab1.AISC_01 import crypto_freq, periodic_corr, Vigenere_decrypt

alfabet_dict = {0: 'a', 1 : 'b', 2: 'c', 3: 'd', 4: 'e', 5: 'f', 6: 'g', 7: 'h', 8: 'i', 9: 'j', 10:'k', 11:'l', 12:'m',
                13:'n', 14:'o', 15:'p', 16:'q', 17:'r', 18:'s', 19:'t', 20:'u', 21:'v', 22:'w', 23:'x', 24:'y', 25:'z'}

english_letter_freqs = [0.085516907,
    0.016047959,
    0.031644354,
    0.038711837,
    0.120965225,
    0.021815104,
    0.020863354,
    0.049557073,
    0.073251186,
    0.002197789,
    0.008086975,
    0.042064643,
    0.025263217,
    0.071721849,
    0.074672654,
    0.020661661,
    0.001040245,
    0.063327101,
    0.067282031,
    0.089381269,
    0.026815809,
    0.010593463,
    0.018253619,
    0.001913505,
    0.017213606,
    0.001137563]

with open('ciphertexts/cryptogram03.txt', 'r') as f:
    ciphertext = f.read()


def find_length_key(cipher_text=ciphertext, l_key=5):
    """generate a subsequence of the cipertext by taking a letter every l_key letters.
    Compute the relative frequencies of the letters in the subsequence. Compute the score:
    S = sum(Q_i^2), where Q_i denotes the frequency of the ith letter."""

    subsequence = ciphertext[0::l_key]
    frequencies = crypto_freq(subsequence)
    S = sum(frequencies**2)
    return round(S, 3)


# Step 1
S_ls = []
i = 0
while sum(S_ls) < 0.99:
    S_ls.append(find_length_key(l_key=i+1))
    i += 1

len_key = S_ls.index(max(S_ls))+1  # length key corresponding to the subsequence with the higher S


# Step 2
def crack_key(len_key=len_key, ciphertext=ciphertext):

    idx_ls = []
    key = ""

    for i in range(len_key):
        n = 0
        c = ""
        while i+n*len_key < len(ciphertext):
            c = c + ciphertext[i+n*len_key]
            n += 1
        freq = crypto_freq(cryptogram=c)
        #cc_dict[i+1] = periodic_corr(english_letter_freqs, freq)
        corr = periodic_corr(freq, english_letter_freqs)
        indx = np.argmax(corr)
        idx_ls.append(indx)
        key = key + alfabet_dict[indx]
    print('Key: ', key)
    return key


key = crack_key()
text = Vigenere_decrypt(ciphertext, key)













