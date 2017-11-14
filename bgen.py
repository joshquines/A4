#!/usr/bin/env python3
import numpy, sys

try:
    size = int(sys.argv[1])
    seed = int(sys.argv[2])
except:
    print("bgen.py size seed")
    sys.exit(-1)

numpy.random.seed(seed)
buffsize = 1024 * 10
remaining = size

while remaining > 0 :
    chunk = min( buffsize, remaining)
    buff = numpy.random.bytes(chunk)
    sys.stdout.buffer.write( buff)
    remaining = remaining - chunk

