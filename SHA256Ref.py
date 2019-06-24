# -*- coding: utf-8 -*-
import numpy as np
import struct
import time
np.set_printoptions(formatter={'int':hex})
#Test Vector
testVector = {'msg': '', 'sha': 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}

def rotr(x, y):
    return ((x >> y) | (x << (32-y))) & 0xFFFFFFFF


def pad(m):
    mdi = len(m) & 0x3F
    print(len(m)<<3)
    length = struct.pack('!Q', len(m)<<3)
    if mdi < 56:
        padlen = 55-mdi
    else:
        padlen = 119-mdi
    #Pre-processing:
    #append the bit '1' to the message
    #append k bits '0', where k is the minimum number >= 0 such that the resulting message
    #    length (modulo 512 in bits) is 448.
    #print(len(msg))
    #append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer
    #    (this will make the entire post-processed length a multiple of 512 bits)
    #print(padlen)
    #print("$", m)
    #print("$", b'\x80')
    #print("$", (b'\x00'*padlen))
    #print("$", len(m), hex(len(m)))
    print(length)
    return m + b'\x80' + b'\x00'*padlen + length

def toBigEndian(digest):
    return ''.join([struct.pack('!L', i) for i in digest])

#        return ''.join([struct.pack('!L', i) for i in r._h[:self._output_size]])
'''Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380'''

def sha256(msg):
    #Initialize hash values:
    #(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    hc = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    #Initialize array of round constants:
    #(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    msg = pad(msg)
    #print("#", msg, len(msg))
    msglen = len(msg)
    blocks = int(msglen/64)
    msgBlocks = []
    msgchunks = []
    #print(blocks, msglen/64)
    for i in range(blocks):
        msgBlocks.append(msg[i*64:(i+1)*64])
        msgchunks.append(np.array(struct.unpack('!16L', msg[i*64:(i+1)*64]), dtype=np.uint32)) 
        
    #msgcode = np.array(struct.unpack('!16L', msg), dtype=np.uint32)
    #print(msgcode)

    #print(msgcode)
    #Process the message in successive 512-bit chunks:
    #break message into 512-bit chunks
    #msgchunks = np.array_split(msgcode, len(msgcode)/16)
    #print(msgchunks)

    for chunk in msgchunks:
        #print('#############################')
        #create a 64-entry message schedule array w[0..63] of 32-bit words
        #(The initial values in w[0..63] don't matter, so many implementations zero them here)
        w = np.zeros(64, dtype=np.uint32)
        #copy chunk into first 16 words w[0..15] of the message schedule array
        for i in range(16):
            w[i] = chunk[i]
            #print(hex(w[i]))
        #Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in range(16, 64):
            s0 = rotr(w[i-15],  7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>  3)
            s1 = rotr(w[i- 2], 17) ^ rotr(w[i- 2], 19) ^ (w[i- 2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
            #print('w[i] : ' , hex(w[i]))
        #Initialize working variables to current hash value:
        a, b, c, d, e, f, g, h = hc
        #print('###', np.array([a, b, c, d, e, f, g, h]))

        #Compression function main loop:
        for i in range(0, 64):
            #print("@", np.array([a, b, c, d, e, f, g, h], dtype=np.uint32))
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = S0 + maj
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF            
            #print(np.array([a, b, c, d, e, f, g, h]))

        #Add the compressed chunk to the current hash value:
        #print("@", np.array([a, b, c, d, e, f, g, h], dtype=np.uint32))
        #print("$", np.array(hc, dtype=np.uint32))
        #print('%%', hex(hc[0]), hex(a), hex(hc[0]+a))
        hc = [(i + j) & 0xFFFFFFFF for i,j in zip(hc, [a, b, c, d, e, f, g, h])] 
        #print('hc:', np.array(hc))

    #Produce the final hash value (big-endian):
    #print(hc)
    #digest =  np.array(hc, dtype=np.uint32)
    #digest = toBigEndian(digest)
    #print digest.encode('hex')
    return np.array(hc, dtype=np.uint32)


def setBlockHeader(Version, hashPrevBlock, hashMerkleRoot, Time, Bits, Nonce = 0):
    header = np.zeros(20, dtype=np.uint32)
    header[0] = Version
    for i in range(8):
        header[i+1] = hashPrevBlock >> (i*32) & 0xFFFFFFFF
        header[i+9] = hashMerkleRoot >> (i*32) & 0xFFFFFFFF
    header[17] = Time
    header[18] = Bits
    header[19] = Nonce
    return bytes([i for i in reversed(bytearray(bytes(header)))])