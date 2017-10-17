# PyCrypto_SHA512.py
#===============================================================================
from Crypto.Hash import SHA512
import os
import time
#===============================================================================
def start():
    file = open("random.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_SHA512(text):
    h = SHA512.new()
    h.update(text)
    encrypted = h.hexdigest()
#===============================================================================
start()
#SHA512
print "SHA_512  hsah_func:",
startTime = time.time()
en_SHA512(text)
print time.time()-startTime
#===============================================================================
