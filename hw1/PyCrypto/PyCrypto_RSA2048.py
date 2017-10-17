# PyCrypto_RSA2048.py
#===============================================================================
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto import Random
import os
import time
#===============================================================================
def start():
    file = open("random1.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_RSA(text):
    file = open("publicKey.txt","r")
    key = file.read()
    file.close()
    rsakey = RSA.importKey(key)
    cipher = PKCS1_v1_5.new(rsakey)
    addnum = rsakey.size()/8-10  #256-11
    global encrypted
    encrypted = ''
    input_text = text[:addnum]
    while input_text:
        encrypted += cipher.encrypt(input_text)
        text = text[addnum:]
        input_text = text[:addnum]
#===============================================================================
def de_RSA(encrypted):
    file = open("privateKey.txt","r")
    key = file.read()
    file.close()
    rsakey =  RSA.importKey(key)
    cipher = PKCS1_v1_5.new(rsakey)
    dsize = SHA512.digest_size
    input_text = encrypted[:256]
    decrypted = ''
    while input_text:
        sentinel = Random.new().read(15 + dsize)
        decrypted += cipher.decrypt(input_text, sentinel)
        encrypted = encrypted[256:]
        input_text = encrypted[:256]
#===============================================================================
start()
#RSA2048
print "RSA_2048    encode:",
startTime = time.time()
en_RSA(text)
print time.time()-startTime

print "RSA_2048    decode:",
startTime = time.time()
de_RSA(encrypted)
print time.time()-startTime
#===============================================================================
