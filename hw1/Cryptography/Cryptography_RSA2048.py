# Cryptography_RSA2048
#===============================================================================
import os
import time
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
#===============================================================================
def en_RSA():
    global encrypted
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
#RSA2048
print "RSA_2048    encode:",
startTime = time.time()
en_RSA()
print time.time()-startTime

print "RSA_2048    decode:",
startTime = time.time()
de_RSA()
print time.time()-startTime
#===============================================================================
