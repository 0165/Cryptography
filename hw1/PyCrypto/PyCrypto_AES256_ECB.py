# PyCrypto_AES256_ECB
#===============================================================================
from Crypto.Cipher import AES
import os
import time
#===============================================================================
def start():
    global key
    key = os.urandom(32) #AES 256 bits = 32 bytes
    file = open("random.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_AES_ECB(key,text):
    padString = ''
    temp = 16-len(text)%16
    for i in range(0,temp):
        padString = padString+chr(temp)
    text = text+padString

    cipher = AES.new(key)
    global encrypted 
    encrypted = cipher.encrypt(text)
#===============================================================================
def de_AES_ECB(key,encrypted):
    cipher = AES.new(key)
    decrypted = cipher.decrypt(encrypted)
    decrypted = decrypted[:len(decrypted)-int(decrypted[-1].encode('hex'),16)]
#===============================================================================
start()
#AES256EBC
print "AES_256_ECB encode:",
startTime = time.time()
en_AES_ECB(key,text)
print time.time()-startTime

print "AES_256_ECB decode:",
startTime = time.time()
de_AES_ECB(key,encrypted)
print time.time()-startTime
#===============================================================================
