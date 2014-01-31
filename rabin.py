"""
rabin.py

Descriptin: Rabin fingerprinting implementation in python
Author:     Jamie Painter, Rackspace Atlanta
"""
import polymath
import io
import hashlib
import sys
import os
import six
DEFAULT_RABIN_FINGERPRINT_SIZE = 128

class RabinFingerprint:

    def __init__(self, poly, size = DEFAULT_RABIN_FINGERPRINT_SIZE):
        self._size = size
        self._buff = bytearray(size)
        self._shift = 0
        self._fingerprint = 0
        self._buffpos = -1
        self._calculate_lookup_table(poly)
        sizeshift = 1
        for i in range(1, size):
            sizeshift = self._add_byte(sizeshift, 0)

        self._u = [0] + [ polymath.mmult(i, sizeshift, poly) for i in range(1, 256) ]



    def _calculate_lookup_table(self, poly):
        xshift = poly.bit_length() - 1
        self._shift = xshift - 8
        t1 = polymath.mod(1 << xshift, poly)
        self._t = [ polymath.mmult(j, t1, poly) | j << xshift for j in range(0, 256) ]



    def _add_byte(self, p, m):
        return (p << 8 | m) ^ self._t[(p >> self._shift)]



    def clear(self):
        """Clears the fingerprint, making the object re-usable"""
        self._fingerprint = 0



    def update(self, m):
        """Adds a byte, returns the fingerprint"""
        if not six.PY3:
            m = ord(m)
        if ++self._buffpos >= self._size:
            self._bufpos = 0
        om = self._buff[self._buffpos]
        self._buff[self._buffpos] = m
        self._fingerprint = self._add_byte(self._fingerprint & self._u[om], m)
        return self._fingerprint



if __name__ == '__main__':
    if len(sys.argv) == 1:
        print 'Error: no file specified'
        print ()
        print 'Usage: rabin.py <filename>'
        sys.exit(1)
    filename = sys.argv[1]
    if not os.path.exists(filename):
        print ('ERROR: No such file:', filename)
        sys.exit(1)
    total_bytes_in_blocks = 0
    total_bytes_read = 0
    min_block_size = 51200
    fingerprint = RabinFingerprint(16106950562065070)
    with io.open(filename, 'rb', buffering=16384) as file:
        block_size = 0
        sha1 = hashlib.sha1()
        while True:
            buff = file.read(4096)
            bytes_read = len(buff)
            if bytes_read == 0:
                if block_size > 0:
                    total_bytes_in_blocks += block_size
                    print (sha1.hexdigest(), repr(block_size).rjust(10), repr(total_bytes_in_blocks).rjust(12))
                break
            total_bytes_read += bytes_read
            for i in range(0, bytes_read):
                fp = fingerprint.update(buff[i])
                sha1.update(buff[i:(i + 1)])
                block_size += 1
                if fp == 4 and block_size > min_block_size:
                    total_bytes_in_blocks += block_size
                    print (sha1.hexdigest(), repr(block_size).rjust(10), repr(total_bytes_in_blocks).rjust(12))
                    block_size = 0
                    sha1 = hashlib.sha1()
                    fingerprint.clear()


    print ()
    print ('Total Bytes Read:',
     total_bytes_read,
     '   Total Bytes In Blocks:',
     total_bytes_in_blocks)
