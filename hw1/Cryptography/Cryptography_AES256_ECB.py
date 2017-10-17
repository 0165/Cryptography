# Cryptography_AES256_ECB
#===============================================================================
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
#===============================================================================
def start():
    global key
    key = os.urandom(32)    #AES256
    file = open("random.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_AES_ECB(key,text):
    global encrypted
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text)
    padded_data += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
#===============================================================================
def de_AES_ECB(key,encrypted):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    tdata = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(tdata)+ unpadder.finalize()
#===============================================================================
start()
#AES256ECB
print "AES_256_ECB encode:",
startTime = time.time()
en_AES_ECB(key,text)
print time.time()-startTime

print "AES_256_ECB decode:",
startTime = time.time()
de_AES_ECB(key,encrypted)
print time.time()-startTime
#===============================================================================


