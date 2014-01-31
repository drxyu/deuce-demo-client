# 2014.01.31 16:04:43 EST

def mod(n, d):
    k = d.bit_length() - 1
    d <<= 63 - k
    i = 63
    while i >= k:
        if n & 1 << i:
            n ^= d >> 63 - i
        i -= 1

    return n



def gcd(x, y):
    while True:
        if y == 0:
            return x
        x = mod(x, y)
        if x == 0:
            return y
        y = mod(y, x)




def mult(x, y):
    res = 0
    if x & 1:
        res = y
    for i in range(1, 64):
        if x & 1 << i:
            res ^= y << i

    return res



def mmult(x, y, d):
    return mod(mult(x, y), d)



+++ okay decompyling polymath.pyc 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2014.01.31 16:04:43 EST
