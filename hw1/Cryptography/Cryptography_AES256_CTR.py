# Cryptography_AES256_CTR
#===============================================================================
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
#===============================================================================
def start():
    global key,ctr
    key = os.urandom(32)    #AES256
    ctr = os.urandom(16)    #block size
    file = open("random.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_AES_CTR(key,text,ctr):
    global encrypted
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text)
    padded_data += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
#===============================================================================
def de_AES_CTR(key,encrypted,ctr):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=backend)
    decryptor = cipher.decryptor()
    tdata = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(tdata)+ unpadder.finalize()
#===============================================================================
start()
#AES256CTR
print "AES_256_CTR encode:",
startTime = time.time()
en_AES_CTR(key,text,ctr)
print time.time()-startTime

print "AES_256_CTR decode:",
startTime = time.time()
de_AES_CTR(key,encrypted,ctr)
print time.time()-startTime
#===============================================================================


