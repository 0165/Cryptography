# PyCrypto_AES256_CTR
#===============================================================================
from Crypto.Cipher import AES
from Crypto.Util import Counter
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
def en_AES_CTR(key,text):
    padString = ''
    temp = 16-len(text)%16
    for i in range(0,temp):
        padString = padString+chr(temp)
    text = text+padString

    ctr = Counter.new(128)
    cipher = AES.new(key,AES.MODE_CTR,counter=ctr)
    global encrypted 
    encrypted = cipher.encrypt(text)
#===============================================================================
def de_AES_CTR(key,encrypted):
    ctr = Counter.new(128)
    cipher = AES.new(key,AES.MODE_CTR,counter=ctr)
    decrypted = cipher.decrypt(encrypted)
    decrypted = decrypted[:len(decrypted)-int(decrypted[-1].encode('hex'),16)]
#===============================================================================
start()
#AES256CTR
print "AES_256_CTR encode:",
startTime = time.time()
en_AES_CTR(key,text)
print time.time()-startTime

print "AES_256_CTR decode:",
startTime = time.time()
de_AES_CTR(key,encrypted)
print time.time()-startTime
#===============================================================================
