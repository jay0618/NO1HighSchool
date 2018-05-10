# RSA 公開金鑰[現代密碼]

>* http://learn.angstromctf.com/crypto/modern/rsa/
>* https://en.wikipedia.org/wiki/RSA_(cryptosystem)

>* http://www.math.uchicago.edu/~may/VIGRE/VIGRE2007/REUPapers/FINALAPP/Calderbank.pdf

### 攻擊RSA 公開金鑰

>* https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA

### 量子電腦(Quantum computer)===>量子霸權

>* https://en.wikipedia.org/wiki/Quantum_computing

### 量子公司
>* [1999]https://www.dwavesys.com/quantum-computing
>* https://www.rigetti.com/

>* https://www.bnext.com.tw/article/48091/why-we-should-be-afraid-of-quantum-computing

### 量子霸權（quantum supremacy）
```
2012年，由加州理工學院物理學家焦恩·普瑞斯基爾（John Preskil）所提出的概念，意思是當量子電腦發展到50量子位元（qubit）時，
運算能力將會超越世界上所有電腦，具有解決傳統電腦所解決不了問題的能力。
https://www.bnext.com.tw/article/48091/why-we-should-be-afraid-of-quantum-computing
```
### 使用量子演算法攻擊RSA 公開金鑰

>*  https://en.wikipedia.org/wiki/Shor%27s_algorithm

### Quantum cryptography[量子密碼]

>* https://en.wikipedia.org/wiki/Quantum_cryptography

### POST Quantum cryptography[後量子密碼]

>* https://en.wikipedia.org/wiki/Post-quantum_cryptography

# 破密分析工具

### 大質因數分解
>* 使用線上工具factordb.com進行大質因數分解
>* 使用Yafu進行大質因數分解

```
wget http://sourceforge.net/projects/yafu/files/latest/download
mkdir yafu/
unzip -d yafu/ download && rm download
```
```
cd /yafu
chmod +x ./yafu
./yafu

>> factor(33)
```

### 破密分析工具gmpy2

>* https://gmpy2.readthedocs.io/en/latest/
>* https://gmpy2.readthedocs.io/en/latest/intro.html#
>* https://pypi.org/project/gmpy2/
>* https://github.com/aleaxit/gmpy

##### 安裝gmpy2
```
pip install gmpy2
sudo apt-get install python-gmpy2
```
##### 使用gmpy2
```
import gmpy2
e = 17
phi =123
d = int(gmpy2.invert(e,phi))

```

# 開始解題

"Key generation":

**1. Choose two distinct prime numbers p and q.**

* For security purposes, the integers p and q should be chosen at random, and should be of similar bit-length. Prime integers can be efficiently found using a primality test.

**2. Compute n = pq.**

* n is used as the modulus for both the public and private keys. Its length, usually expressed in bits, is the key length.

**3. Compute `φ(n) = φ(p)φ(q) = (p − 1)(q − 1) = n - (p + q -1)`, where φ is Euler's totient function.**

**4. Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1; i.e., e and φ(n) are coprime.**

* e is released as the public key exponent.
* e having a short bit-length and small Hamming weight results in more efficient encryption – most commonly 216 + 1 = 65,537. However, much smaller values of e (such as 3) have been shown to be less secure in some settings.

**5. Determine d as d ≡ e−1 (mod φ(n)); i.e., d is the multiplicative inverse of e (modulo φ(n)).**

* This is more clearly stated as: solve for d given `d*e ≡ 1 (mod φ(n))`
* This is often computed using the extended Euclidean algorithm. Using the pseudocode in the Modular integers section, inputs a and n correspond to e and φ(n), respectively.
* d is kept as the private key exponent.

# crypto 201
```
PicoCTF 2017:compute-rsa-50 20
```

# crypto 202
>* PicoCTF 2013: RSA 70
>* https://github.com/ctfs/write-ups-2013/tree/master/pico-ctf-2013/rsa

```
#!/usr/bin/python2
import gmpy2

p =  9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q =  11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e =  65537
c =  83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034
t = (p-1)*(q-1)
n = p*q

# returns d such that e * d == 1 modulo t, or 0 if no such y exists.
d = gmpy2.invert(e,t)

# Decryption
m = pow(c,d,n)
print "Solved ! m = %d" % m
```

# crypto 202_a
>* angstromCTF 2018 / INTRO TO RSA
>* [Python]https://github.com/Ascope-Team/write-ups-2018/tree/master/AngstromCTF-2018/CRYPTO50_introToRsa
>* [Ruby]https://rawsec.ml/en/angstromCTF-2018-write-ups/#50-intro-to-rsa-crypto

intro_rsa.txt

解法1:使用python
```
import gmpy
import sys
# Si n est pas de p q , p et q = factordb.com of n

p = 169524110085046954319747170465105648233168702937955683889447853815898670069828343980818367807171215202643149176857117014826791242142210124521380573480143683660195568906553119683192470329413953411905742074448392816913467035316596822218317488903257069007949137629543010054246885909276872349326142152285347048927
q = 170780128973387404254550233211898468299200117082734909936129463191969072080198908267381169837578188594808676174446856901962451707859231958269401958672950141944679827844646158659922175597068183903642473161665782065958249304202759597168259072368123700040163659262941978786363797334903233540121308223989457248267
e = 65537

c = 4531850464036745618300770366164614386495084945985129111541252641569745463086472656370005978297267807299415858324820149933137259813719550825795569865301790252501254180057121806754411506817019631341846094836070057184169015820234429382145019281935017707994070217705460907511942438972962653164287761695982230728969508370400854478181107445003385579261993625770566932506870421547033934140554009090766102575218045185956824020910463996496543098753308927618692783836021742365910050093343747616861660744940014683025321538719970946739880943167282065095406465354971096477229669290277771547093476011147370441338501427786766482964

phi = (p-1)*(q-1)
d = gmpy.invert(e, phi)
m = pow(c, d, p*q)

print(hex(m)[2:].replace('L','').decode('hex'))
```
解法2:使用ruby

```
#!/usr/bin/ruby
require 'openssl'
# Source of int2Text: http://stackoverflow.com/questions/42993763/how-to-convert-bytes-in-number-into-a-string-of-characters-character-represent#42999986
def int2Text(int)
    a = []
    while int>0
        a << (int & 0xFF)
        int >>= 8
    end
    return a.reverse.pack('C*')
end
# Source of egcd: https://gist.github.com/jsanders/6735046
def egcd(a, b)
  u_a, v_a, u_b, v_b = [ 1, 0, 0, 1 ]
  while a != 0
    q = b / a
    a, b = [ b - q*a, a ]
    u_a, v_a, u_b, v_b = [ u_b - q*u_a, v_b - q*v_a, u_a, v_a ]
    # Each time, `u_a*a' + v_a*b' = a` and `u_b*a' + v_b*b' = b`
  end
  [ b, u_b, v_b ]
end
def modinv(a, m)
    g, x, y = egcd(a, m)
    if g != 1
        raise 'modular inverse does not exist'
    else
        return x % m
    end
end
File.open('files/intro_rsa.txt', 'r') do |f|
  data = f.read()
  # Get params
  c = data.match(/^c = ([0-9]*)$/).captures[0].to_i
  e = data.match(/^e = ([0-9]*)$/).captures[0].to_i
  p_int = data.match(/^p = ([0-9]*)$/).captures[0].to_i
  q = data.match(/^q = ([0-9]*)$/).captures[0].to_i
  # Calc other params
  phi = (p_int - 1) * (q - 1)
  d = modinv(e, phi)
  n = p_int*q
  # more efficient than m_int = (c ** d) % n
  m_int = c.to_bn.mod_exp(d, n).to_i
  m_text = int2Text(m_int)
  # Display cleartext
  puts m_text
end
```


# crypto 203
>* AlexCTF2017: CR4: Poor RSA 100
>* http://www.rogdham.net/2017/02/06/alexctf-2017-write-ups.en
>* https://fadec0d3.blogspot.tw/2017/02/alexctf-2017-crypto.html

```
-----BEGIN PUBLIC KEY-----
ME0wDQYJKoZIhvcNAQEBBQADPAAwOQIyUqmeJJ7nzzwMv5Y6AJZhdyvJzfbh4/v8
bkSgel4PiURXqfgcOuEyrFaD01soulwyQkMCAwEAAQ==
-----END PUBLIC KEY-----

```
質因數分解==>factordb.com 
```
http://www.factordb.com/index.php?query=833810193564967701912362955539789451139872863794534923259743419423089229206473091408403560311191545764221310666338878019
```

863653476616376575308866344984576466644942572246900013156919 * 965445304326998194798282228842484732438457170595999523426901

>* [rsatool](https://github.com/ius/rsatool)

>* [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)

```
python ./rsatool/rsatool.py -p 863653476616376575308866344984576466644942572246900013156919 -q 965445304326998194798282228842484732438457170595999523426901 -o ./priv.key
```
```
openssl rsautl -decrypt -in flag.raw -inkey priv.key
```

>* [gmpy2](https://code.google.com/archive/p/gmpy/downloads)

```
#!/usr/bin/python2
import gmpy2

p =  9648423029010515676590551740010426534945737639235739800643989352039852507298491399561035009163427050370107570733633350911691280297777160200625281665378483
q =  11874843837980297032092405848653656852760910154543380907650040190704283358909208578251063047732443992230647903887510065547947313543299303261986053486569407
e =  65537
c =  83208298995174604174773590298203639360540024871256126892889661345742403314929861939100492666605647316646576486526217457006376842280869728581726746401583705899941768214138742259689334840735633553053887641847651173776251820293087212885670180367406807406765923638973161375817392737747832762751690104423869019034
t = (p-1)*(q-1)
n = p*q

# returns d such that e * d == 1 modulo t, or 0 if no such y exists.
d = gmpy2.invert(e,t)

# Decryption
m = pow(c,d,n)
print "Solved ! m = %d" % m
```

# crypto 204

>* ABCTF 2016 : old-rsa-70 70
>* https://kimiyuki.net/blog/2016/07/23/abctf-2016/

rsa1.txt
```
I recovered an RSA encrypted message from the 1980's. can you decrypt it?

c = 29846947519214575162497413725060412546119233216851184246267357770082463030225
n = 70736025239265239976315088690174594021646654881626421461009089480870633400973
e = 3
```
解題步驟1:使用[線上工具](factordb.com)進行質因數分解
```
p=238324208831434331628131715304428889871,q=296805874594538235115008173244022912163
```
解題步驟2:使用python求解
```
#!/usr/bin/env python3
c = 29846947519214575162497413725060412546119233216851184246267357770082463030225
p = 238324208831434331628131715304428889871
q = 296805874594538235115008173244022912163
n = p * q
e = 3
 
import gmpy2
from Crypto.PublicKey import RSA
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))
 
key = RSA.construct((n, e, d(p,q,e)))
import binascii
print(binascii.unhexlify(hex(key.decrypt(c))[2:]).decode())
```

# crypto 208
>* ABCTF 2016 : sexy-rsa-160 

abctf-2016/crypto/sexy-rsa-160/sexy_rsa.txt
```
I recovered some RSA parameters. Can you decrypt the message?

c = 293430917376708381243824815247228063605104303548720758108780880727974339086036691092136736806182713047603694090694712685069524383098129303183298249981051498714383399595430658107400768559066065231114145553134453396428041946588586604081230659780431638898871362957635105901091871385165354213544323931410599944377781013715195511539451275610913318909140275602013631077670399937733517949344579963174235423101450272762052806595645694091546721802246723616268373048438591
n = 1209143407476550975641959824312993703149920344437422193042293131572745298662696284279928622412441255652391493241414170537319784298367821654726781089600780498369402167443363862621886943970468819656731959468058528787895569936536904387979815183897568006750131879851263753496120098205966442010445601534305483783759226510120860633770814540166419495817666312474484061885435295870436055727722073738662516644186716532891328742452198364825809508602208516407566578212780807
e = 65537

```
<math xmlns="http://www.w3.org/1998/Math/MathML">
  <mi>p</mi>
  <mo>,</mo>
  <mi>q</mi>
  <mo>=</mo>
  <mo fence="false" stretchy="false">&#x230A;<!-- ⌊ --></mo>
  <msqrt>
    <mi>n</mi>
  </msqrt>
  <mo fence="false" stretchy="false">&#x230B;<!-- ⌋ --></mo>
  <mo>&#x00B1;<!-- ± --></mo>
  <mn>3</mn>
</math>

```
#!/usr/bin/env python3
c = 293430917376708381243824815247228063605104303548720758108780880727974339086036691092136736806182713047603694090694712685069524383098129303183298249981051498714383399595430658107400768559066065231114145553134453396428041946588586604081230659780431638898871362957635105901091871385165354213544323931410599944377781013715195511539451275610913318909140275602013631077670399937733517949344579963174235423101450272762052806595645694091546721802246723616268373048438591
n = 1209143407476550975641959824312993703149920344437422193042293131572745298662696284279928622412441255652391493241414170537319784298367821654726781089600780498369402167443363862621886943970468819656731959468058528787895569936536904387979815183897568006750131879851263753496120098205966442010445601534305483783759226510120860633770814540166419495817666312474484061885435295870436055727722073738662516644186716532891328742452198364825809508602208516407566578212780807
e = 65537
 
def sqrt(x):
    low = -1
    high = c+1
    while low + 1 < high:
        m = (low + high) // 2
        y = m*m
        if y < x:
            low = m
        else:
            high = m
    m = high
    return m
 
r = sqrt(n)
p = r + 3
q = r - 3
assert n == p * q
 
import gmpy2
from Crypto.PublicKey import RSA
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))
 
key = RSA.construct((n, e, d(p,q,e)))
import binascii
print(binascii.unhexlify(hex(key.decrypt(c))[2:]).decode())
```
# crypto 205

>* angstromCTF 2016 : brute-force-40 20
>* http://ipushino.blogspot.tw/2016/04/angstromctf2016-brute-force-crypto40.html

解題步驟:使用Online md5 cracker
```
https://hashkiller.co.uk/md5-decrypter.aspx
```
send : c8db257e50bc35bf721b11d333fe9fd6

flag=randomwords

# crypto 206

>* MMA CTF 2nd 2016 : twin-primes-50 50

##### Twin prime

>* https://en.wikipedia.org/wiki/Twin_prime
>* (3, 5), (5, 7), (11, 13), (17, 19), (29, 31), (41, 43), (59, 61), (71, 73), (101, 103), (107, 109), (137, 139)
>* https://github.com/TeamContagion/CTF-Write-Ups/tree/master/TokyoWesterns-2016/Twin%20Primes
>* https://www.megabeets.net/twctf-2016-crypto-twin-primes/

```
n1 = pq
n2 = (p+2)(q+2) = pq + 2p + 2q + 4
n2 - n1 = 2p + 2q + 4

let s = (n2 - n1 - 4)/2 = p + q

q = (s - p)
n1 = p(s-p) = ps - p^2
p^2 - sp + n1 = 0
解出quadratic equation that we can solve, giving us p and q
```
你會加減乘除吧~~~
```
n1 = 3*11
n2 = 5*13
```

解題步驟1:分析===>題目給四個檔案
```
encrypt.py – A Python script uses RSA algorithm to encrypt the flag
encryped – The encrypted message
key 1 – n, and e of one of the keys used in the encryption process
key 2 – n, and e of the other key used in the encryption process
```

解題步驟2:使用python求解
```
#!/usr/bin/python
from Crypto.Util.number import *
import Crypto.PublicKey.RSA as RSA
import gmpy2

with open('key1', 'r') as f:
    n1 = long(f.read().splitlines()[0])
with open('key2', 'r') as f:
    n2 = long(f.read().splitlines()[0])
with open('encrypted', 'r') as f:
    m = long(f.read().splitlines()[0])

s = (n2 - n1 - 4L) / 2L

# p^2 - sp + n1 = 0
# Apply quadratic formula:
a = 1
b = -s
c = n1

p = long((-b + gmpy2.isqrt(b*b-4*a*c))/2L)
q = n1/p

assert p*q == n1
assert (p+2)*(q+2) == n2

e = long(65537)
d1 = inverse(e, (p-1)*(q-1))
d2 = inverse(e, (p+1)*(q+1))
key1 = RSA.construct((n1, e, d1))
key2 = RSA.construct((n2, e, d2))
m = key2.decrypt(m)
m = key1.decrypt(m)
m = long_to_bytes(m)

end = m.index('}')
print m[:end+1]
```

# crypto 207
>* Pragyan CTF 2016 : RSA_Encryption 200

解題步驟1:檢查兩把key是否互質

解題步驟2:
```
from Crypto.PublicKey import RSA
from fractions import gcd
import gmpy2
import base64

# our data
N = 123948613128507245097711825164030080528129311429181946930789480629270692835124562568997437300916285601268900901495788327838386854611883075845387070635813324417496512348003686061832004434518190158084956517800098929984855603216625922341285873495112316366384741709770903928077127611563285935366595098601100940173
N2 = 122890614849300155056519159433849880305439158904289542874766496514523043027349829509818565800562562195671251134947871996792136355514373160369135263766229423623131725044925870918859304353484491601318921285331340604341809979578202817714205469839224620893418109679223753141128229197377934231853172927071087589849
e = 65537L 

ct = 'Pob7AQZZSml618nMwTpx3V74N45x/rTimUQeTl0yHq8F0dsekZgOT385Jls1HUzWCx6ZRFPFMJ1RNYR2Yh7AkQtFLVx9lYDfb/Q+SkinBIBX59ER3/fDhrVKxIN4S6h2QmMSRblh4KdVhyY6cOxu+g48Jh7TkQ2Ig93/nCpAnYQ='
ct = base64.b64decode(ct)

# find the common prime factor p from the second file, then determine q
p = gcd(N,N2)
q = N/p
r=(p-1)*(q-1)

d = long(gmpy2.divm(1, e, r))

# decrypt the message
rsa = RSA.construct((N,e,d,p,q))
pt = rsa.decrypt(ct)

print pt
```

# crypto 209

>* SECCON 2017 Quals:crypto_ps_and_qs 200
>* https://github.com/p4-team/ctf/tree/master/2017-12-09-seccon-quals/crypto_ps_and_qs


pub1.pub
```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz8+77qffFDqKwgixqh0v
hlRaxMtYjJSj+xwUrZGk8Lk2FXxaS4acGKi4ZPRya/j83AIMtBBCuslnhKt9A/k3
SUfvsLw9Zlgxl0NAFZ/8PbfI50tjkP2m7sMLgcb/Yk6NP1sXv7elx//Y7PTmUYs5
Or793Q+uukMIdGumP4EGtZ1+BYlDoAExp9TlOMRksnBXdkftvEeMwc6Vhe/odzBb
OnwufETbVHXt2tw0WiyQqUZ3HKwKRUzby0YfKEDnYTyD6c7MlAN/oJu52qPxgFYs
Ad8L5sUfDAbo8OLW4aXlDQoow4gRQHcKn0WTQUa381m5Oc4j8PpQem9ORUVxQwlS
ADwg8dl6ZxQLbl/L+zs3bk4klprrHUic/HKvTxWkeIoaqXyJdW0dTZSqR+fNOoGu
y5JEjMksd9LvV2qg28E1CGKszdrdvOgDV/DNW4VN0PjEYn/ktxiyTs/hHtJMO+Iv
AGQ7vtTuXjRa8Xblt20jovgODsbzTlcYxipw/lVwwouAe0TyLq3r2bX/kG9qhb6I
wMj25fiApR8X+E2xwu7+qK80BAREztGjffDk9fcsw/ULfkJ8jC2LYYbq12LwxESz
yjoBA+0SqTvOnK50eaIp67wKZI6qb5flBRpm6wnr1zSOkvdfEl69w2fip9Had1nU
H64uJjW/S3p/kb7Ks6x9Bb0CAwEAAQ==
-----END PUBLIC KEY-----

```

pub2.pub
```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuzPMf8yOyvO/ntlcWDeS
4exrgO6HXsIGTbzwdZXINEkjv1NlJNTgp1V0x3mMc7GX3SsbQgVLHknLRfvwTm8R
TPijZcPfNkVST3eCaAOKP6JoAunR7b+7Xt+1oMN1Nw1/EPV9q71Pdx2tNjLwG5vO
EEiZZu6ILasXozt4aqX3MWWlQFEwCx35KAOSo+3p0/ycTYpqBjUfbvNZjo3is507
Ga9koXFs0Vgmw/JMsT3rciw6A+8dK+LQpabiEP9dAYNnvjv5nqJroAblFkpN1Vqr
zUSd5c4YZIJdwWDlDVCesOb+cj7xgmge3blAhLg+yeLpQ+h8uHUJqw/Zscoiwc6v
85/Kz2cp/A4FeGcNh9fw+cy+Ccs+Es64lVcqmXnRC/2/r6JgVo2NsYS+ErPjGT4H
cpzjwdnNgoPtaYOgY4gDagpwKU8jOSlEd4KA596fYBY6gVDjD/Sk6gJ5LL6DBbqi
6Zr+UeF9r8Vr4NOEFHvNOOnRKTTscSYiIXdzpLOFGpsMbHw+AfYRGh4aVX9OKuSi
R86bdczMsYGYJfMFSqHAVb0+I0AJOuLvHQ+loXaCXv33lQcCf1EECAAJFC8NQ+Lx
DPrSIIE7u5AU1PQyXtrFOPtegrdT4q07JGB9c4CqZPy5i1nqi1pza4CTgySM7OCx
clXqVZ6QEn93ivbX6KZtrZECAwEAAQ==
-----END PUBLIC KEY-----
```
解題步驟1:檢查兩把key是否互質

```
import codecs
from Crypto.PublicKey import RSA
from crypto_commons.rsa.rsa_commons import gcd

def read_key(filename):
    with codecs.open(filename, "r") as input_file:
        data = input_file.read()
        pub = RSA.importKey(data)
        print(pub.e, pub.n)
    return pub


def main():
    pub1 = read_key("pub1.pub")
    pub2 = read_key("pub2.pub")
    p = gcd(pub1.n, pub2.n)
    print(p)
```

解題步驟2:

```
import codecs
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from crypto_commons.generic import bytes_to_long
from crypto_commons.rsa.rsa_commons import gcd, get_fi_distinct_primes, modinv


def read_ct():
    with codecs.open("cipher", "rb") as input_file:
        data = input_file.read()
        print(len(data))
        msg = bytes_to_long(data)
    return msg


def read_key(filename):
    with codecs.open(filename, "r") as input_file:
        data = input_file.read()
        pub = RSA.importKey(data)
        print(pub.e, pub.n)
    return pub


def main():
    pub1 = read_key("pub1.pub")
    pub2 = read_key("pub2.pub")
    p = gcd(pub1.n, pub2.n)
    print(p)
    q1 = pub1.n / p
    q2 = pub2.n / p
    print(p, q1)
    print(p, q2)
    msg = read_ct()

    d1 = modinv(pub1.e, get_fi_distinct_primes([p, q1]))
    d2 = modinv(pub2.e, get_fi_distinct_primes([p, q2]))

    first = pow(msg, d1, pub1.n)
    print(long_to_bytes(first))


main()
```
