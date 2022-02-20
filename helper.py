"""
All implementations here are for educational purposes only!
Kudos to Andrej Karpathy for the inspiration and much of the code. You can review his blog: http://karpathy.github.io/
"""

from __future__ import annotations # PEP 563: Postponed Evaluation of Annotations
from dataclasses import dataclass # https://docs.python.org/3/library/dataclasses.html I like these a lot
from itertools import count, islice
from typing import List, Union
import math
import random
import sys
import struct

""" 
Elliptical math (ECDSA) used for Bitcoin Encryption  
"""

@dataclass
class Curve:
    p: int # the prime modulus of the finite field
    a: int
    b: int

@dataclass
class Point:
    curve: Curve
    x: int 
    y: int

@dataclass
class Generator:
    G: Point # a generator point on the curve
    n: int # the order of the generating point, so 0*G = n*G = INF 

def extended_euclidean_algorithm(a, b):
    """ Returns (gcd, x, y) such that a * x + b * y == gcd """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r  # // means integer division 
        old_r , r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t 

def inv(n, p):
    """ returns modular multiplicate inverse m such that (n*m)%p==1 """
    gcd, x, y = extended_euclidean_algorithm(n, p)
    return x % p 

def ec_addition(self, other: Point) -> Point: 

    # handle special case of P + 0 = 0 + P = 0
    if self == INF:
        return other 
    if other == INF:
        return self

    # handle special case of P + (-P) = 0 
    if self.x == other.x and self.y != other.y:
        return INF 

    # compute the "slope"
    if self.x == other.x:
        m = (3 * self.x**2 + self.curve.a) * inv(2 * self.y, self.curve.p)
    else:
        m = (self.y - other.y) * inv(self.x - other.x, self.curve.p)
    
    # compute the new point 
    rx = (m**2 - self.x - other.x) % self.curve.p
    ry = (-(m*(rx - self.x) + self.y)) % self.curve.p
    return Point(self.curve, rx, ry)

def double_and_add(self, k: int) -> Point:
    assert isinstance(k, int) and k >= 0
    result = INF 
    append = self 
    while k:
        if k & 1:
            result += append
        append += append
        k >>= 1
    return result 

class PublicKey(Point):
    """ The public key is a point on Curve, with additional encoding/decoding """

    @classmethod
    def from_point(cls, pt: Point):
        """ promote a Point to be a Public Key"""
        return cls(pt.curve, pt.x, pt.y)
    
    def encode(self, compressed, hash160=False):
        """ return the SEC bytes encoding of the Public Key Point """
        # calculate the bytes
        if compressed:
            # we can just encode x, since y can be calculated 
            # just need to add prefix, 02 or 03 depending on +/-
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            pkb = prefix + self.x.to_bytes(32, 'big')
        else:
            pkb = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
        
        # hash if desired 
        return ripemd160(sha256(pkb)) if hash160 else pkb 
    
    def address(self, net: str, compressed: bool) -> str: 
        """ return the associated bitcon address for this public key as string"""
        # encode public key into bytes and hash to get payload
        pkb_hash = self.encode(compressed=compressed, hash160=True)

        # add version byte to payload 
        version = {'main': b'\x00', 'test': b'\x6f'}
        ver_pkb_hash = version[net] + pkb_hash

        # calculate the checksum
        checksum = sha256(sha256(ver_pkb_hash))[:4]

        # append checksum to versioned payload to form the full 25-byte binary Bitcoin Address 
        byte_address = ver_pkb_hash + checksum

        # finally, base58 encode the result to get the Bitcoin Address
        base58check_address = base58encode(byte_address)

        return base58check_address

### BITCOIN CONSTANTS ####

# secp256k1 uses a = 0, b = 7, so we're dealing with the curve y^2 = x^3 + 7 (mod p)
bitcoin_curve = Curve(
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a = 0x0000000000000000000000000000000000000000000000000000000000000000, # a = 0
    b = 0x0000000000000000000000000000000000000000000000000000000000000007, # b = 7
)

G = Point(
    bitcoin_curve, 
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)

bitcoin_gen = Generator(
    G = G,
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 
)

INF = Point(None, None, None) # special point at infinity, kind of like "zero"



"""
SHA256
"""
def rotr(x, n, size=32):
    return (x >> n) | (x << size - n) & (2**size - 1)

def shr(x, n):
    return x >> n

def sig0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sig1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def capsig0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def capsig1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def ch(x, y, z):
    return (x & y)^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def b2i(b):
    return int.from_bytes(b, 'big')

def i2b(i):
    return i.to_bytes(4, 'big')

def is_prime(n):
        return not any(f for f in range(2,int(math.sqrt(n))+1) if n%f == 0)

def first_n_primes(n):
    return islice(filter(is_prime, count(start=2)), n)

def frac_bin(f, n=32):
    """ return the first n bits of fractional part of float f """
    f -= math.floor(f) # get only the fractional part
    f *= 2**n # shift left
    f = int(f) # truncate the rest of the fractional content
    return f

def genK():
    """
    Follows Section 4.2.2 to generate K

    The first 32 bits of the fractional parts of the cube roots of the first
    64 prime numbers:

    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
    27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
    a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
    19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
    748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
    """
    return [frac_bin(p ** (1/3.0)) for p in first_n_primes(64)]

def genH():
    """
    Follows Section 5.3.3 to generate the initial hash value H^0

    The first 32 bits of the fractional parts of the square roots of
    the first 8 prime numbers.

    6a09e667 bb67ae85 3c6ef372 a54ff53a 9b05688c 510e527f 1f83d9ab 5be0cd19
    """
    return [frac_bin(p ** (1/2.0)) for p in first_n_primes(8)]

def pad(b):
        """ Follows Section 5.1: Padding the message """
        b = bytearray(b) # convert to a mutable equivalent
        l = len(b) * 8 # note: len returns number of bytes not bits

        # append but "1" to the end of the message
        b.append(0b10000000) # appending 10000000 in binary (=128 in decimal)

        # follow by k zero bits, where k is the smallest non-negative solution to
        # l + 1 + k = 448 mod 512
        # i.e. pad with zeros until we reach 448 (mod 512)
        while (len(b)*8) % 512 != 448:
            b.append(0x00)

        # the last 64-bit block is the length l of the original message
        # expressed in binary (big endian)
        b.extend(l.to_bytes(8, 'big'))

        return b

def sha256(b: bytes) -> bytes:

    # Section 4.2
    K = genK()

    # Section 5: Preprocessing
    # Section 5.1: Pad the message
    b = pad(b)
    # Section 5.2: Separate the message into blocks of 512 bits (64 bytes)
    blocks = [b[i:i+64] for i in range(0, len(b), 64)]

    # for each message block M^1 ... M^N
    H = genH() # Section 5.3

    # Section 6
    for M in blocks: # each block is a 64-entry array of 8-bit bytes

        # 1. Prepare the message schedule, a 64-entry array of 32-bit words
        W = []
        for t in range(64):
            if t <= 15:
                # the first 16 words are just a copy of the block
                W.append(bytes(M[t*4:t*4+4]))
            else:
                term1 = sig1(b2i(W[t-2]))
                term2 = b2i(W[t-7])
                term3 = sig0(b2i(W[t-15]))
                term4 = b2i(W[t-16])
                total = (term1 + term2 + term3 + term4) % 2**32
                W.append(i2b(total))

        # 2. Initialize the 8 working variables a,b,c,d,e,f,g,h with prev hash value
        a, b, c, d, e, f, g, h = H

        # 3.
        for t in range(64):
            T1 = (h + capsig1(e) + ch(e, f, g) + K[t] + b2i(W[t])) % 2**32
            T2 = (capsig0(a) + maj(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + T1) % 2**32
            d = c
            c = b
            b = a
            a = (T1 + T2) % 2**32

        # 4. Compute the i-th intermediate hash value H^i
        delta = [a, b, c, d, e, f, g, h]
        H = [(i1 + i2) % 2**32 for i1, i2 in zip(H, delta)]

    return b''.join(i2b(i) for i in H)

"""
RIPEMD160
"""

# -----------------------------------------------------------------------------
# public interface

def ripemd160(b: bytes) -> bytes:
    """ simple wrapper for a simpler API to this hash function, just bytes to bytes """
    ctx = RMDContext()
    RMD160Update(ctx, b, len(b))
    digest = RMD160Final(ctx)
    return digest

# -----------------------------------------------------------------------------

class RMDContext:
    def __init__(self):
        self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] # uint32
        self.count = 0 # uint64
        self.buffer = [0]*64 # uchar

def RMD160Update(ctx, inp, inplen):
    have = int((ctx.count // 8) % 64)
    inplen = int(inplen)
    need = 64 - have
    ctx.count += 8 * inplen
    off = 0
    if inplen >= need:
        if have:
            for i in range(need):
                ctx.buffer[have+i] = inp[i]
            RMD160Transform(ctx.state, ctx.buffer)
            off = need
            have = 0
        while off + 64 <= inplen:
            RMD160Transform(ctx.state, inp[off:])
            off += 64
    if off < inplen:
        for i in range(inplen - off):
            ctx.buffer[have+i] = inp[off+i]

def RMD160Final(ctx):
    size = struct.pack("<Q", ctx.count)
    padlen = 64 - ((ctx.count // 8) % 64)
    if padlen < 1 + 8:
        padlen += 64
    RMD160Update(ctx, PADDING, padlen-8)
    RMD160Update(ctx, size, 8)
    return struct.pack("<5L", *ctx.state)

K0 = 0x00000000
K1 = 0x5A827999
K2 = 0x6ED9EBA1
K3 = 0x8F1BBCDC
K4 = 0xA953FD4E
KK0 = 0x50A28BE6
KK1 = 0x5C4DD124
KK2 = 0x6D703EF3
KK3 = 0x7A6D76E9
KK4 = 0x00000000

PADDING = [0x80] + [0]*63

def ROL(n, x):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def F0(x, y, z):
    return x ^ y ^ z

def F1(x, y, z):
    return (x & y) | (((~x) % 0x100000000) & z)

def F2(x, y, z):
    return (x | ((~y) % 0x100000000)) ^ z

def F3(x, y, z):
    return (x & z) | (((~z) % 0x100000000) & y)

def F4(x, y, z):
    return x ^ (y | ((~z) % 0x100000000))

def R(a, b, c, d, e, Fj, Kj, sj, rj, X):
    a = ROL(sj, (a + Fj(b, c, d) + X[rj] + Kj) % 0x100000000) + e
    c = ROL(10, c)
    return a % 0x100000000, c

def RMD160Transform(state, block): #uint32 state[5], uchar block[64]

    x = [0]*16
    assert sys.byteorder == 'little', "Only little endian is supported atm for RIPEMD160"
    x = struct.unpack('<16L', bytes(block[0:64]))

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    #/* Round 1 */
    a, c = R(a, b, c, d, e, F0, K0, 11,  0, x)
    e, b = R(e, a, b, c, d, F0, K0, 14,  1, x)
    d, a = R(d, e, a, b, c, F0, K0, 15,  2, x)
    c, e = R(c, d, e, a, b, F0, K0, 12,  3, x)
    b, d = R(b, c, d, e, a, F0, K0,  5,  4, x)
    a, c = R(a, b, c, d, e, F0, K0,  8,  5, x)
    e, b = R(e, a, b, c, d, F0, K0,  7,  6, x)
    d, a = R(d, e, a, b, c, F0, K0,  9,  7, x)
    c, e = R(c, d, e, a, b, F0, K0, 11,  8, x)
    b, d = R(b, c, d, e, a, F0, K0, 13,  9, x)
    a, c = R(a, b, c, d, e, F0, K0, 14, 10, x)
    e, b = R(e, a, b, c, d, F0, K0, 15, 11, x)
    d, a = R(d, e, a, b, c, F0, K0,  6, 12, x)
    c, e = R(c, d, e, a, b, F0, K0,  7, 13, x)
    b, d = R(b, c, d, e, a, F0, K0,  9, 14, x)
    a, c = R(a, b, c, d, e, F0, K0,  8, 15, x) #/* #15 */
    #/* Round 2 */
    e, b = R(e, a, b, c, d, F1, K1,  7,  7, x)
    d, a = R(d, e, a, b, c, F1, K1,  6,  4, x)
    c, e = R(c, d, e, a, b, F1, K1,  8, 13, x)
    b, d = R(b, c, d, e, a, F1, K1, 13,  1, x)
    a, c = R(a, b, c, d, e, F1, K1, 11, 10, x)
    e, b = R(e, a, b, c, d, F1, K1,  9,  6, x)
    d, a = R(d, e, a, b, c, F1, K1,  7, 15, x)
    c, e = R(c, d, e, a, b, F1, K1, 15,  3, x)
    b, d = R(b, c, d, e, a, F1, K1,  7, 12, x)
    a, c = R(a, b, c, d, e, F1, K1, 12,  0, x)
    e, b = R(e, a, b, c, d, F1, K1, 15,  9, x)
    d, a = R(d, e, a, b, c, F1, K1,  9,  5, x)
    c, e = R(c, d, e, a, b, F1, K1, 11,  2, x)
    b, d = R(b, c, d, e, a, F1, K1,  7, 14, x)
    a, c = R(a, b, c, d, e, F1, K1, 13, 11, x)
    e, b = R(e, a, b, c, d, F1, K1, 12,  8, x) #/* #31 */
    #/* Round 3 */
    d, a = R(d, e, a, b, c, F2, K2, 11,  3, x)
    c, e = R(c, d, e, a, b, F2, K2, 13, 10, x)
    b, d = R(b, c, d, e, a, F2, K2,  6, 14, x)
    a, c = R(a, b, c, d, e, F2, K2,  7,  4, x)
    e, b = R(e, a, b, c, d, F2, K2, 14,  9, x)
    d, a = R(d, e, a, b, c, F2, K2,  9, 15, x)
    c, e = R(c, d, e, a, b, F2, K2, 13,  8, x)
    b, d = R(b, c, d, e, a, F2, K2, 15,  1, x)
    a, c = R(a, b, c, d, e, F2, K2, 14,  2, x)
    e, b = R(e, a, b, c, d, F2, K2,  8,  7, x)
    d, a = R(d, e, a, b, c, F2, K2, 13,  0, x)
    c, e = R(c, d, e, a, b, F2, K2,  6,  6, x)
    b, d = R(b, c, d, e, a, F2, K2,  5, 13, x)
    a, c = R(a, b, c, d, e, F2, K2, 12, 11, x)
    e, b = R(e, a, b, c, d, F2, K2,  7,  5, x)
    d, a = R(d, e, a, b, c, F2, K2,  5, 12, x) #/* #47 */
    #/* Round 4 */
    c, e = R(c, d, e, a, b, F3, K3, 11,  1, x)
    b, d = R(b, c, d, e, a, F3, K3, 12,  9, x)
    a, c = R(a, b, c, d, e, F3, K3, 14, 11, x)
    e, b = R(e, a, b, c, d, F3, K3, 15, 10, x)
    d, a = R(d, e, a, b, c, F3, K3, 14,  0, x)
    c, e = R(c, d, e, a, b, F3, K3, 15,  8, x)
    b, d = R(b, c, d, e, a, F3, K3,  9, 12, x)
    a, c = R(a, b, c, d, e, F3, K3,  8,  4, x)
    e, b = R(e, a, b, c, d, F3, K3,  9, 13, x)
    d, a = R(d, e, a, b, c, F3, K3, 14,  3, x)
    c, e = R(c, d, e, a, b, F3, K3,  5,  7, x)
    b, d = R(b, c, d, e, a, F3, K3,  6, 15, x)
    a, c = R(a, b, c, d, e, F3, K3,  8, 14, x)
    e, b = R(e, a, b, c, d, F3, K3,  6,  5, x)
    d, a = R(d, e, a, b, c, F3, K3,  5,  6, x)
    c, e = R(c, d, e, a, b, F3, K3, 12,  2, x) #/* #63 */
    #/* Round 5 */
    b, d = R(b, c, d, e, a, F4, K4,  9,  4, x)
    a, c = R(a, b, c, d, e, F4, K4, 15,  0, x)
    e, b = R(e, a, b, c, d, F4, K4,  5,  5, x)
    d, a = R(d, e, a, b, c, F4, K4, 11,  9, x)
    c, e = R(c, d, e, a, b, F4, K4,  6,  7, x)
    b, d = R(b, c, d, e, a, F4, K4,  8, 12, x)
    a, c = R(a, b, c, d, e, F4, K4, 13,  2, x)
    e, b = R(e, a, b, c, d, F4, K4, 12, 10, x)
    d, a = R(d, e, a, b, c, F4, K4,  5, 14, x)
    c, e = R(c, d, e, a, b, F4, K4, 12,  1, x)
    b, d = R(b, c, d, e, a, F4, K4, 13,  3, x)
    a, c = R(a, b, c, d, e, F4, K4, 14,  8, x)
    e, b = R(e, a, b, c, d, F4, K4, 11, 11, x)
    d, a = R(d, e, a, b, c, F4, K4,  8,  6, x)
    c, e = R(c, d, e, a, b, F4, K4,  5, 15, x)
    b, d = R(b, c, d, e, a, F4, K4,  6, 13, x) #/* #79 */

    aa = a
    bb = b
    cc = c
    dd = d
    ee = e

    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    #/* Parallel round 1 */
    a, c = R(a, b, c, d, e, F4, KK0,  8,  5, x)
    e, b = R(e, a, b, c, d, F4, KK0,  9, 14, x)
    d, a = R(d, e, a, b, c, F4, KK0,  9,  7, x)
    c, e = R(c, d, e, a, b, F4, KK0, 11,  0, x)
    b, d = R(b, c, d, e, a, F4, KK0, 13,  9, x)
    a, c = R(a, b, c, d, e, F4, KK0, 15,  2, x)
    e, b = R(e, a, b, c, d, F4, KK0, 15, 11, x)
    d, a = R(d, e, a, b, c, F4, KK0,  5,  4, x)
    c, e = R(c, d, e, a, b, F4, KK0,  7, 13, x)
    b, d = R(b, c, d, e, a, F4, KK0,  7,  6, x)
    a, c = R(a, b, c, d, e, F4, KK0,  8, 15, x)
    e, b = R(e, a, b, c, d, F4, KK0, 11,  8, x)
    d, a = R(d, e, a, b, c, F4, KK0, 14,  1, x)
    c, e = R(c, d, e, a, b, F4, KK0, 14, 10, x)
    b, d = R(b, c, d, e, a, F4, KK0, 12,  3, x)
    a, c = R(a, b, c, d, e, F4, KK0,  6, 12, x) #/* #15 */
    #/* Parallel round 2 */
    e, b = R(e, a, b, c, d, F3, KK1,  9,  6, x)
    d, a = R(d, e, a, b, c, F3, KK1, 13, 11, x)
    c, e = R(c, d, e, a, b, F3, KK1, 15,  3, x)
    b, d = R(b, c, d, e, a, F3, KK1,  7,  7, x)
    a, c = R(a, b, c, d, e, F3, KK1, 12,  0, x)
    e, b = R(e, a, b, c, d, F3, KK1,  8, 13, x)
    d, a = R(d, e, a, b, c, F3, KK1,  9,  5, x)
    c, e = R(c, d, e, a, b, F3, KK1, 11, 10, x)
    b, d = R(b, c, d, e, a, F3, KK1,  7, 14, x)
    a, c = R(a, b, c, d, e, F3, KK1,  7, 15, x)
    e, b = R(e, a, b, c, d, F3, KK1, 12,  8, x)
    d, a = R(d, e, a, b, c, F3, KK1,  7, 12, x)
    c, e = R(c, d, e, a, b, F3, KK1,  6,  4, x)
    b, d = R(b, c, d, e, a, F3, KK1, 15,  9, x)
    a, c = R(a, b, c, d, e, F3, KK1, 13,  1, x)
    e, b = R(e, a, b, c, d, F3, KK1, 11,  2, x) #/* #31 */
    #/* Parallel round 3 */
    d, a = R(d, e, a, b, c, F2, KK2,  9, 15, x)
    c, e = R(c, d, e, a, b, F2, KK2,  7,  5, x)
    b, d = R(b, c, d, e, a, F2, KK2, 15,  1, x)
    a, c = R(a, b, c, d, e, F2, KK2, 11,  3, x)
    e, b = R(e, a, b, c, d, F2, KK2,  8,  7, x)
    d, a = R(d, e, a, b, c, F2, KK2,  6, 14, x)
    c, e = R(c, d, e, a, b, F2, KK2,  6,  6, x)
    b, d = R(b, c, d, e, a, F2, KK2, 14,  9, x)
    a, c = R(a, b, c, d, e, F2, KK2, 12, 11, x)
    e, b = R(e, a, b, c, d, F2, KK2, 13,  8, x)
    d, a = R(d, e, a, b, c, F2, KK2,  5, 12, x)
    c, e = R(c, d, e, a, b, F2, KK2, 14,  2, x)
    b, d = R(b, c, d, e, a, F2, KK2, 13, 10, x)
    a, c = R(a, b, c, d, e, F2, KK2, 13,  0, x)
    e, b = R(e, a, b, c, d, F2, KK2,  7,  4, x)
    d, a = R(d, e, a, b, c, F2, KK2,  5, 13, x) #/* #47 */
    #/* Parallel round 4 */
    c, e = R(c, d, e, a, b, F1, KK3, 15,  8, x)
    b, d = R(b, c, d, e, a, F1, KK3,  5,  6, x)
    a, c = R(a, b, c, d, e, F1, KK3,  8,  4, x)
    e, b = R(e, a, b, c, d, F1, KK3, 11,  1, x)
    d, a = R(d, e, a, b, c, F1, KK3, 14,  3, x)
    c, e = R(c, d, e, a, b, F1, KK3, 14, 11, x)
    b, d = R(b, c, d, e, a, F1, KK3,  6, 15, x)
    a, c = R(a, b, c, d, e, F1, KK3, 14,  0, x)
    e, b = R(e, a, b, c, d, F1, KK3,  6,  5, x)
    d, a = R(d, e, a, b, c, F1, KK3,  9, 12, x)
    c, e = R(c, d, e, a, b, F1, KK3, 12,  2, x)
    b, d = R(b, c, d, e, a, F1, KK3,  9, 13, x)
    a, c = R(a, b, c, d, e, F1, KK3, 12,  9, x)
    e, b = R(e, a, b, c, d, F1, KK3,  5,  7, x)
    d, a = R(d, e, a, b, c, F1, KK3, 15, 10, x)
    c, e = R(c, d, e, a, b, F1, KK3,  8, 14, x) #/* #63 */
    #/* Parallel round 5 */
    b, d = R(b, c, d, e, a, F0, KK4,  8, 12, x)
    a, c = R(a, b, c, d, e, F0, KK4,  5, 15, x)
    e, b = R(e, a, b, c, d, F0, KK4, 12, 10, x)
    d, a = R(d, e, a, b, c, F0, KK4,  9,  4, x)
    c, e = R(c, d, e, a, b, F0, KK4, 12,  1, x)
    b, d = R(b, c, d, e, a, F0, KK4,  5,  5, x)
    a, c = R(a, b, c, d, e, F0, KK4, 14,  8, x)
    e, b = R(e, a, b, c, d, F0, KK4,  6,  7, x)
    d, a = R(d, e, a, b, c, F0, KK4,  8,  6, x)
    c, e = R(c, d, e, a, b, F0, KK4, 13,  2, x)
    b, d = R(b, c, d, e, a, F0, KK4,  6, 13, x)
    a, c = R(a, b, c, d, e, F0, KK4,  5, 14, x)
    e, b = R(e, a, b, c, d, F0, KK4, 15,  0, x)
    d, a = R(d, e, a, b, c, F0, KK4, 13,  3, x)
    c, e = R(c, d, e, a, b, F0, KK4, 11,  9, x)
    b, d = R(b, c, d, e, a, F0, KK4, 11, 11, x) #/* #79 */

    t = (state[1] + cc + d) % 0x100000000
    state[1] = (state[2] + dd + e) % 0x100000000
    state[2] = (state[3] + ee + a) % 0x100000000
    state[3] = (state[4] + aa + b) % 0x100000000
    state[4] = (state[0] + bb + c) % 0x100000000
    state[0] = t % 0x100000000

"""
Base58 Encoding
"""
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(b: bytes) -> str:
    assert len(b) == 25 # version(1) + pkb_hash(20) + checksum(4)
    n = int.from_bytes(b, 'big')
    chars = []
    while n:
        n, i = divmod(n, 58)
        chars.append(alphabet[i])
    
    # special case handle the leading 0 bytes 
    num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    res = num_leading_zeros * alphabet[0] + ''.join(reversed(chars))
    return res 


"""
Functionality for Bitcoin Transaction
"""

@dataclass
class Script:
    cmds: List[Union[int, bytes]]

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            elif isinstance(cmd, bytes):
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                assert length < 75 # any longer than this requires tedious handling outside scope 
                out += [encode_int(length, 1), cmd]
        ret = b''.join(out)
        return encode_varint(len(ret)) + ret 

@dataclass
class TxIn:
    prev_tx: bytes # prev TxID: hash256 of prev tx contents 
    prev_index: int # UTXO output index in the tx
    script_sig: Script = None # unlocking script 
    sequence: int = None # used for locktime 

@dataclass
class TxOut:
    amount: int # in units of satoshis
    script_pubkey: Script = None # locking script 

@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0

    def encode(self, sig_index = -1) -> bytes:
        """ Encode transaction as bytes. 
            If sig_index is given then return the modified transaction encoding of this tx wrt the single input index. 
            This result then constitutes the "message" that gets signed by the aspiring transaction of this input 
        """
        out = []
        # encode version metadata 
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index 
            out += [tx_in.encode(script_override=(sig_index == i)) for i, tx_in in enumerate(self.tx_ins)]
        # encode outputs
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        # encode other metadata
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b''] # 1 = SIGHASH_ALL

        return b''.join(out)

@dataclass
class Signature:
    r: int 
    s: int 

def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes bytes using given byte ordering """
    return i.to_bytes(nbytes, encoding)

def encode_varint(i):
    """ encode an integer into bytes with a simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("Integer too large: %d" % (i, ))

def txin_encode(self, script_override=None):
    out = []
    out += [self.prev_tx[::-1]] # little endian vs big endian encoding 
    out += [encode_int(self.prev_index, 4)]

    if script_override is None: 
        # None = just use the actual script 
        out += [self.script_sig.encode()]
    elif script_override is True:
        # True = override the script with the script_pubkey of the associated input
        out += [self.prev_tx_script_pubkey.encode()]
    elif script_override is False:
        # False = override with an empty script
        out += [Script([]).encode()]
    else:
        raise ValueError("Script_override must be one of None|True|False")

    out += [encode_int(self.sequence, 4)]
    return b''.join(out)

TxIn.encode = txin_encode # monkey path into the class

def txout_encode(self):
    out = []
    out += [encode_int(self.amount, 8)]
    out += [self.script_pubkey.encode()]
    return b''.join(out)

TxOut.encode = txout_encode # monkey path into the class

def sign(secret_key: int, message: bytes) -> Signature: 
    # the order of the elliptic curve used in bitcoin
    n = bitcoin_gen.n 

    # double hash the message and convert to inger
    z = int.from_bytes(sha256(sha256(message)), 'big')

    # generate a new secret/public key pair at random 
    sk = random.randrange(1, n)
    P = sk * bitcoin_gen.G 

    # calculate the signature
    r = P.x
    s = inv(sk, n) * (z + secret_key * r) % n
    if s > n / 2:
        s = n - s 
    
    sig = Signature(r, s)
    return sig 


def signature_encode(self) -> bytes:
    """ return the DER encoding of this signature """
    def dern(n):
        nb = n.to_bytes(32, byteorder="big")
        nb = nb.lstrip(b'\x00') # strip leading 0s
        nb = (b'\x00' if nb[0] >= 0x80 else b'') + nb # prepend 0x00 if first byte >= 0x80
        return nb 
    rb = dern(self.r)
    sb = dern(self.s)
    content = b''.join([bytes([0x02, len(rb)]), rb, bytes([0x02, len(sb)]), sb])
    frame = b''.join([bytes([0x30, len(content)]), content])
    return frame 

Signature.encode = signature_encode # monkey patch into the class


def tx_id(self) -> str:
    return sha256(sha256(self.encode()))[::-1].hex() # little/big endian requires byte order swap

Tx.id = tx_id # monkey patch into class 

