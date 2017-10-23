#===============================================================================
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
#===============================================================================
def start():
    global key,iv,ctr
    key = os.urandom(32)    #AES256
    iv = os.urandom(16)     #block size
    ctr = os.urandom(16)    #block size
    file = open("random.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def changetext():
    file = open("random1.txt","r")
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
def en_AES_CBC(key,text,iv):
    global encrypted
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text)
    padded_data += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
#===============================================================================
def de_AES_CBC(key,encrypted,iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    tdata = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(tdata)+ unpadder.finalize()
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
def en_SHA_512(text):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(text)
    ans = digest.finalize().encode('hex')
#===============================================================================
def en_RSA():
    file = open("publicKey.txt","r")
    public_key = serialization.load_pem_public_key(
        file.read(),
        backend=default_backend()
    )
    file.close()
    addnum = 245
    file1 = open("temp.txt","w")
    file = open("random.txt","r")
    while 1:
        text = file.read(addnum)
        if len(text)==0:
            break
        file1.write(public_key.encrypt(text,apadding.PKCS1v15()))
    file1.close()
    file.close()
#===============================================================================
def de_RSA():
    file = open("privateKey.txt","r")
    private_key = serialization.load_pem_private_key(
        file.read(),
        password=None,
        backend=default_backend()
    )
    file.close()
    file = open("temp.txt","r")
    file1 = open("ans.txt","w")
    while 1:
        text = file.read(256)
        if len(text)==0:
            break
        file1.write(private_key.decrypt(text,apadding.PKCS1v15()))
    file.close()
    file1.close()
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
en_AES_CTR(key,text,ctr)
print time.time()-startTime
print "AES_256_CTR decode:",
startTime = time.time()
de_AES_CTR(key,encrypted,ctr)
print time.time()-startTime
#SHA512
print "SHA_2_512   encode:",
startTime = time.time()
en_SHA_512(text)
print time.time()-startTime
#RSA2048
encrypted = ''
text = ''
print "RSA_2048    encode:",
startTime = time.time()
en_RSA()
print time.time()-startTime
print "RSA_2048    decode:",
startTime = time.time()
de_RSA()
print time.time()-startTime
#===============================================================================
