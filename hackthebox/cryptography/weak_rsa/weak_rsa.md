---
Title: Weak RSA
Date:   2021-04-02
Category: Crypto
Difficulty: Easy
Challenge Creator: tomtoump
---

## Overview

_(DISCLAIMER: This entire lab can be done in one line using the RSA CTF tool ([https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)), but we&#39;re trying to actually learn something, so we&#39;re going to do it without it.)_

Before attempting this challenge it helps to have a better understanding of how RSA works, what might be considered a weak key, and what might cause weak keys. We should begin by understanding how RSA generates keys. RSA defines a public key as a pair of integers {e, N} and a private key as an integer _d_. First, two distinct large co-prime numbers are generated which we&#39;ll refer to as _p_ and _q_. Let _N = p \* q_, and _N' = (p - 1) \*(q-1)._ The integer _e_ is selected such that _1 < e < N'_ and _gcd( e, N' ) = 1._ The modular multiplicative inverse of _e_ is then calculated such that _d = e^-1 mod N'_. Now that a private and public key has been generated, integers _m_ can be encrypted as _c = m^e mod N_, and cipher integers _c_ can be decrypted as _m = c^d mod N._

A key may be deemed weak due to a number of factors. If the value of _e_ is too small or if part of a secret key is known, then it may be susceptible to attacks based on the Coppersmith method, such as Hastad&#39;s broadcast attack. If there is insufficient entropy available in a system for pseudo-random number generation, then _p_ and _q_ may be generated in such a way that results in two different public keys sharing a common factor, in which case factoring can be trivially done using a calculation of the greatest common divisor between the two public keys. In worst case scenarios, insufficient entropy may even result in duplicate sets of keys being created. To avoid insufficient entropy, developers should rely on /dev/random rather than /dev/urandom, as the former blocks when sufficient entropy is not available, or on true random number generators in the form of hardware random number generators. Additionally, RSA keys may be weak if the length of the key isn&#39;t not sufficiently long, increasing the viability of brute force factoring attacks. This will be the approach taken for this challenge.

## Exploitation

Downloading the provided zip gives us _flag.enc_ and _key.pub_. Using the openssl tool we can see the hex values for the public key modulus (_N_) and the exponent (_e_). We also see the length of the key is 1026 bits.

```
$opensslrsa -pubin -in key.pub -text -noout

RSAPublic-Key: (1026 bit)
Modulus:
 03:30:3b:79:0f:b1:49:da:34:06:d4:95:ab:9b:9f:
 b8:a9:e2:93:44:5e:3b:d4:3b:18:ef:2f:05:21:b7:
 26:eb:e8:d8:38:ba:77:4b:b5:24:0f:08:f7:fb:ca:
 0a:14:2a:1d:4a:61:ea:97:32:94:e6:84:a8:d1:a2:
 cd:f1:8a:84:f2:db:70:99:b8:e9:77:58:8b:0b:89:
 12:92:55:8c:aa:05:cf:5d:f2:bc:63:34:c5:ee:50:
 83:a2:34:ed:fc:79:a9:5c:47:8a:78:e3:37:c7:23:
 ae:88:34:fb:8a:99:31:b7:45:03:ff:ea:9e:61:bf:
 53:d8:71:69:84:ac:47:83:7b
Exponent:
 61:17:c6:04:48:b1:39:45:1a:b5:b6:0b:62:57:a1:
 2b:da:90:c0:96:0f:ad:1e:00:7d:16:d8:fa:43:aa:
 5a:aa:38:50:fc:24:0e:54:14:ad:2b:a1:09:0e:8e:
 12:d6:49:5b:bc:73:a0:cb:a5:62:50:42:55:c7:3e:
 a3:fb:d3:6a:88:83:f8:31:da:8d:1b:9b:81:33:ac:
 21:09:e2:06:28:e8:0c:7e:53:ba:ba:4c:e5:a1:42:
 98:81:1e:70:b4:a2:31:3c:91:4a:2a:32:17:c0:2e:
 95:1a:ae:e4:c9:eb:39:a3:f0:80:35:7b:53:3a:6c:
 ca:95:17:cb:2b:95:bf:cd
```

We&#39;ll attempt to factor the public key modulus in order to recreate the private key, which we can then use to decrypt the cipher text. First we&#39;ll need to read in the public key. We&#39;ll use the Pycryptodome library to generate an RSA key object in Python 3. This library will automatically set the modulus and exponent values on the RSA key object.

```python
key_file = open('key.pub', 'r')
pub_key = RSA.importKey(key_file.read())
key_file.close()
```
```
Public key modulus: 573177824579630911668469272712547865443556654086190104722795509756891670023259031275433509121481030331598569379383505928315495462888788593695945321417676298471525243254143375622365552296949413920679290535717172319562064308937342567483690486592868352763021360051776130919666984258847567032959931761686072492923

Public key exponent: 68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605
```

Now that we have the public key we can begin factoring the modulus value. To simplify this, we can leverage factordb. By making a call to factordb using the requests library we get back our factors _p_ and _q_ in json format.

```python
def get_factors(n: int) -> tuple:
    r = requests.get('http://factordb.com/api', params={'query': n})
    r = r.json()
    return int(r['factors'][0][0]), int(r['factors'][1][0])

p, q = get_factors(pub_key.n)
```
```
P: 20423438101489158688419303567277343858734758547418158024698288475832952556286241362315755217906372987360487170945062468605428809604025093949866146482515539

Q: 28064707897434668850640509471577294090270496538072109622258544167653888581330848582140666982973481448008792075646342219560082338772652988896389532152684857
```

With _p_ and _q_ we can calculate _N'_; and the private key (d) outline in the previous section. Python 3.9 simplifies this process by allowing the _math.pow()_ function to accept negative exponents, but we could also calculate the modular multiplicative inverse using the Extended Euclidean algorithm.

```python
n_prime = (p-1)*(q-1)
priv_key = pow(pub_key.e, -1, n_prime)
```
```
N': 573177824579630911668469272712547865443556654086190104722795509756891670023259031275433509121481030331598569379383505928315495462888788593695945321417676249983379244330315836562552513442311464915424205045449525362729420822096204950393746030170667472908585990772529539514978818747699190354877085506007437292528

Private key: 44217944188473654528518593968293401521897205851340809945591908757815783834933
```

Next, we retrieve our cipher text and convert it to an integer. We begin by reading the file in as raw bytes, then converting it to a more cleanly formatted hexadecimal string using the binascii library. We then cast the hexadecimal string to an integer so that we can later perform calculations on it.

```python
def read_cipher_text_as_int() -> int:
    f = open('flag.enc', 'rb')
    cipher = f.read()
    cipher = binascii.hexlify(cipher)
    cipher_int = int(cipher, 16)
    f.close()
    return cipher_int
 
cipher = read_cipher_text_as_int()
```

```
Cipher text: 293792738930806473043362408865328816287441045624879757658311913421709629830459147001874022619053834436656776844217383046081493640274421712968040869174651239233039876991334823008822132067871053934110275331573032589519744166170666015147429094399160461619773963895662688636761506290931246128202368412403823287790
```

The last step is to decrypt the cipher text using the formula from the previous section then perform a little bit of string manipulation to translate our message back into bytes.

```python
m_int = pow(cipher, priv_key, pub_key.n)
m = f'0{hex(m_int)[2:]}'
message = bytes.fromhex(m)
```

```
Decrypted message:  b'\x02!\xcf\xb2\x98\x83\xb0o@\x9ag\x9aX\xa4\xe9{Dn(\xb2D\xbb\xcd\x06\x87\xd1x\xa8\xab\x87"\xbf\x86\xda\x06\xa6.\x04,\x89-)!\xb36W\x1e\x9f\xf7\xac\x9d\x89\xba\x90Q+\xacL\xfb\x8d~J9\x01\xbb\xcc\xf5\xdf\xac\x01\xb2{\xdd\xd3_\x1c\xa5SD\xa7YC\xdf\x9a\x18\xea\xdb4L\xf7\xcfU\xfa\x0b\xaap\x05\xbf\xe3/A\x00HTB{s1mpl3_Wi3n3rs_4tt4ck}'
```

Above we can see the flag embedded in the byte string of our decrypted message.

```
Flag: HTB{s1mpl3_Wi3n3rs_4tt4ck}
```

## Full Implementation (Python 3.9)
```python
#!/usr/bin/python3

import base64
import binascii
import requests
import sys

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def get_factors(n: int) -> tuple:
    r = requests.get('http://factordb.com/api', params={'query': n})
    r = r.json()
    return int(r['factors'][0][0]), int(r['factors'][1][0])

def read_cipher_text_as_int() -> int:
    f = open('flag.enc', 'rb')
    cipher = f.read()
    cipher = binascii.hexlify(cipher)
    cipher_int = int(cipher, 16)
    f.close()
    return cipher_int 

if __name__ == '__main__':
    # Import the public key 
    key_file = open('key.pub', 'r')
    pub_key = RSA.importKey(key_file.read())
    key_file.close()

    # Factor the public key modulus
    p, q = get_factors(pub_key.n)

    # Generate the private key
    n_prime = (p-1)*(q-1)
    priv_key = pow(pub_key.e, -1, n_prime) 

    # Read in the cipher text and convert to an integer
    cipher = read_cipher_text_as_int()

    # Decrypt the cipher text and convert back to bytes
    m_int = pow(cipher, priv_key, pub_key.n)
    m = f'0{hex(m_int)[2:]}'
    message = bytes.fromhex(m)

    print(f'Cipher text:  {cipher}\n')
    print(f'Public key modulus:  {pub_key.n}\n')
    print(f'Public key exponent:  {pub_key.e}\n')
    print(f'P:  {p}\n')
    print(f'Q:  {q}\n')
    print(f'N\':  {n_prime}\n')
    print(f'Private key: {priv_key}\n')
    print(f'Decrypted message:  {message}\n')
```
