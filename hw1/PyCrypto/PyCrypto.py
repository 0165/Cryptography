#aes block size >8 byte, so need using pkcs7 when padding
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto import Random
import os
import time
#===============================================================================
def start():
    global key
    key = os.urandom(32) #AES 256
    file = open("random.txt","r")
    global text 
    text = file.read()
    global iv
    iv = os.urandom(16) #block size is 16byte
    file.close()
#===============================================================================
def changetext():
    file = open("random1.txt","r")
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
def en_SHA512(text):
    h = SHA512.new()
    h.update(text)
    encrypted = h.hexdigest()
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
#AES256CBC
print "AES_256_CBC encode:",
startTime = time.time()
en_AES_CBC(key,text,iv)
print time.time()-startTime
print "AES_256_CBC decode:",
startTime = time.time()
de_AES_CBC(key,encrypted,iv)
print time.time()-startTime
#AES256CTR
print "AES_256_CTR encode:",
startTime = time.time()
en_AES_CTR(key,text)
print time.time()-startTime
print "AES_256_CTR decode:",
startTime = time.time()
de_AES_CTR(key,encrypted)
print time.time()-startTime
#SHA512
print "SHA_512  hsah_func:",
startTime = time.time()
en_SHA512(text)
print time.time()-startTime
#RSA2048
print "RSA is using 1M+7byte data"
changetext()
print "RSA_2048    encode:",
startTime = time.time()
en_RSA(text)
print time.time()-startTime
print "RSA_2048    decode:",
startTime = time.time()
de_RSA(encrypted)
print time.time()-startTime
#===============================================================================