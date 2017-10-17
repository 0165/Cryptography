# PyCrypto_AES256_CBC
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
    global iv
    iv = os.urandom(16) #block size is 16byte
#===============================================================================
def en_AES_CBC(key,text,iv):
    padString = ''
    temp = 16-len(text)%16
    for i in range(0,temp):
        padString = padString+chr(temp)
    text = text+padString

    cipher = AES.new(key,AES.MODE_CBC,iv)
    global encrypted 
    encrypted = cipher.encrypt(text)
#===============================================================================
def de_AES_CBC(key,encrypted,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    decrypted = cipher.decrypt(encrypted)
    decrypted = decrypted[:len(decrypted)-int(decrypted[-1].encode('hex'),16)]
#===============================================================================
start()
#AES256CBC
print "AES_256_CBC encode:",
startTime = time.time()
en_AES_CBC(key,text,iv)
print time.time()-startTime

print "AES_256_CBC decode:",
startTime = time.time()
de_AES_CBC(key,encrypted,iv)
print time.time()-startTime
#===============================================================================
