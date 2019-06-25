from myhdl import *
import random
from random import randrange
import numpy as np
import modregistry


PKTSYNCPTR     = 0
SOURCEPTR      = 16
DESTENPTR      = 24
LENPTR         = 32
ALGOPTR        = 48
MODEPTR        = 56
PKTIDPTR       = 64

SYNC           = 0xAFAF

np.set_printoptions(formatter={'int':hex})

DATA = 512

def includeElement(header, data, pos):
    header[int(pos/64)]   = int(header[int(pos/64)] ) ^ (data << int(     pos%64)) & 0xFFFFFFFFFFFFFFFF
    header[int(pos/64)+1] = int(header[int(pos/64)+1]) ^ (data >> int(64 - pos%64)) & 0xFFFFFFFFFFFFFFFF
    return header
    
def addHeader(data, src, dest, algo, mode, pktid, DATA = DATA):
    header = np.zeros(int(DATA/64), dtype=np.uint64)
    header = includeElement(header, SYNC, PKTSYNCPTR)
    header = includeElement(header, src , SOURCEPTR)
    header = includeElement(header, dest, DESTENPTR)
    header = includeElement(header, int(len(data)*64//DATA), LENPTR)
    header = includeElement(header, algo, ALGOPTR)
    header = includeElement(header, mode, MODEPTR)
    header = includeElement(header, pktid, PKTIDPTR)
    pkt = np.append(header, data)
    return pkt

def toModbv(data, DATA = DATA):
    i = 0
    vector = 0
    vectors = []
    for d in data:
        #print(d, ' : ', i)
        vector ^= int(d) << (i * 64)
        i += 1
        if i == int(DATA/64):
            i = 0
            vectors.append(modbv(vector)[DATA:])
            vector = 0
    return vectors
