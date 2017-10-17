# Cryptography_SHA512
#===============================================================================
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
#===============================================================================
def start():
    file = open("random.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_SHA_512(text):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(text)
    ans = digest.finalize().encode('hex')
#===============================================================================
start()
#SHA512
print "SHA_2_512   encode:",
startTime = time.time()
en_SHA_512(text)
print time.time()-startTime
#===============================================================================


