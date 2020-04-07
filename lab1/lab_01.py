from pathlib import Path
from collections import Counter

import matplotlib.pyplot as plt

from lab1.AISC_01 import digram_ranking, trigram_ranking

def frequency(text, sep=' '):


    dict_ = {}
    with open(text, 'r') as t:
        for line in t:
            key, value = line.split(sep)
            dict_[key] = int(value)
    N = 0
    for value in dict_.values():
        N += value
    dict_f = {}
    for key, value in dict_.items():
        dict_f[key] = round((value/N), 4)

    return dict_f


cipher_path = Path("ciphertexts")
cipher_text = cipher_path/'cryptogram01.txt'
with open(cipher_text, 'r') as text_file:
    ciphertext = text_file.read()
    c = Counter(ciphertext)

N = 0
for value in c.values():
    N += value
dict_f = {}
for key, value in c.items():
    dict_f[key] = round((value/N), 4)


digr = digram_ranking(ciphertext, 10)
t = trigram_ranking(ciphertext, 10)

d_tr = {}
for i in t:
    d_tr[i[0]] = round(i[1]/N, 4)*100

d_di = {}
for i in digr:
    d_di[i[0]] = round(i[1]/N, 4)*100

dict_ef = frequency(cipher_path/'english_frequencies.txt')

plt.bar(*zip(*dict_f.items()), width=.5, color='g')
plt.savefig('cipher_frequency_01.png', dpi=500)
plt.close()

plt.bar(*zip(*dict_ef.items()), width=.5, color='g')
plt.savefig('cipher_frequency_01_e.png', dpi=500)
plt.close()

plt.bar(*zip(*d_di.items()), width=.5, color='g')
plt.savefig('cipher_frequency_01_di.png', dpi=500)
plt.close()

plt.bar(*zip(*d_tr.items()), width=.5, color='g')
plt.savefig('cipher_frequency_01_tr.png', dpi=500)
plt.close()







print(c)
print(ciphertext)


