import random
import unittest

class RSA:
    def __init__(self):
        self.e = 65537
        self.l = None
        self.p = None
        self.q = None
        self.n = None
        self.phi = None
        self.d = None
        self.sentence = False

    def generate(self, ll):
        self.l = ll
        halfL = self.l >> 1
        if self.l & 1 == 0:
            pLength = qLength = halfL
        else:
            pLength = halfL
            qLength = halfL + 1
        self.p = genNumber(pLength)
        while (not isPrime(self.p)) or gcd(self.p - 1, self.e) != 1:
            self.p = genNumber(pLength)
        self.q = genNumber(qLength)
        while (not isPrime(self.q)) or gcd(self.q - 1, self.e) != 1:
            self.q = genNumber(qLength)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = extendedEuclid(self.e, self.phi)

    def showKeys(self):
        print('e = {}\nd = {}\nn = {}'.format(self.e, self.d, self.n))

    def encr(self, x, e, n):
        if type(x) is str:
            x = strToInt(x)
        return modPow(x, format(e, 'b'), n)

    def decr(self, y, d, n, sentence):
        if sentence:
            return intToStr(modPow(y, format(d, 'b'), n))
        return modPow(y, format(d, 'b'), n)


def gcd(x, y):
    while y:
        x, y = y, x % y
    return x


def isPrime(n):
    s = 0
    r = n - 1
    while r % 2 == 0:
        s += 1
        r >>= 1
    for i in range(100):
        if not miller_rabin(n, r, s):
            return False
    return True


def miller_rabin(n, r, s):
    if n & 1 == 0:
        return False
    a = random.randint(1, n - 1)
    if not gcd(a, n) == 1:
        return False
    v = modPow(a, format(int(r), 'b'), n)
    if v == 1:
        return True
    for j in range(s):
        if v == n - 1:
            return True
        v = modPow(v, '10', n)
    return False


def isPrimeFerma(n):
    for i in range(100):
        if not testFerma(n):
            return False
    return True

def testFerma(n):
    a = random.randint(1, n - 1)
    if gcd(a, n) != 1:
        return False
    if modPow(a, format(n - 1, 'b'), n) != 1:
        return False
    return True

def modPow(a, bits, n):
    u = 1
    v = a
    for b in reversed(bits):
        if b == '1':
            u = (u * v) % n
        v = (v * v) % n
    return u


def genNumber(l):
    n = '1' + format(random.getrandbits(l - 2), 'b').zfill(l - 2) + '1'
    return int(n, 2)



def extendedEuclid(a, mod):
    m = mod
    x, xx = 1, 0
    while m:
        q = a // m
        a, m = m, a % m
        x, xx = xx, x - xx * q
    if x < 0:
        x += mod
    return x

def strToInt(s):
    result = ''
    for symbol in s:
        result += str(ord(symbol) + 70)
    return int(result)

def intToStr(number):
    s = str(number)
    n = int(len(s) / 3)
    result = ''
    for i in range(n):
        result += chr(int(s[i * 3: i * 3 + 3]) - 70)
    return result

if __name__ == '__main__':
    r = RSA()
    r.generate(2048)
    r.showKeys()
    print(r.decr(r.encr('qwertyuiop', r.e, r.n), r.d, r.n, True))

