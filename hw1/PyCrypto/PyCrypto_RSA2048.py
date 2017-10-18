# PyCrypto_RSA2048.py
#===============================================================================
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto import Random
import os
import time
#===============================================================================
def en_RSA():
    file = open("publicKey.txt","r")
    key = file.read()
    file.close()
    rsakey = RSA.importKey(key)
    cipher = PKCS1_v1_5.new(rsakey)
    addnum = rsakey.size()/8-10  #256-11
    file1 = open("temp.txt","w")
    file = open("random.txt","r")
    while 1:
        text = file.read(addnum)
        if len(text)==0:
            break
        file1.write(cipher.encrypt(text))
    file1.close()
    file.close()
#===============================================================================
def de_RSA():
    file = open("privateKey.txt","r")
    key = file.read()
    file.close()
    rsakey =  RSA.importKey(key)
    cipher = PKCS1_v1_5.new(rsakey)
    dsize = SHA512.digest_size
    file = open("temp.txt","r")
    file1 = open("ans.txt","w")
    while 1:
        text = file.read(256)
        if len(text)==0:
            break
        sentinel = Random.new().read(15 + dsize)
        file1.write(cipher.decrypt(text, sentinel))
    file.close()
    file1.close()
#===============================================================================
#RSA2048
print "RSA_2048    encode:",
startTime = time.time()
en_RSA()
print time.time()-startTime

print "RSA_2048    decode:",
startTime = time.time()
de_RSA()
print time.time()-startTime
#===============================================================================
