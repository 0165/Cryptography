# Cryptography_RSA2048
#===============================================================================
import os
import time
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
#===============================================================================
def start():
    file = open("random1.txt","r")
    global text 
    text = file.read()
    file.close()
#===============================================================================
def en_RSA(text):
    global encrypted
    file = open("publicKey.txt","r")
    public_key = serialization.load_pem_public_key(
        file.read(),
        backend=default_backend()
    )
    file.close()
    addnum = 214
    encrypted = ''
    input_text = text[:addnum]
    while input_text:
        encrypted += public_key.encrypt(
            input_text,
            apadding.OAEP(
                mgf=apadding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        text = text[addnum:]
        input_text = text[:addnum]
#===============================================================================
def de_RSA(encrypted):
    file = open("privateKey.txt","r")
    private_key = serialization.load_pem_private_key(
        file.read(),
        password=None,
        backend=default_backend()
    )
    file.close()

    input_text = encrypted[:256]
    dncrypted = ''
    while input_text:
        dncrypted += private_key.decrypt(
            input_text,
            apadding.OAEP(
                mgf=apadding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        encrypted = encrypted[256:]
        input_text = encrypted[:256]
#===============================================================================
start()
#RSA2048
print "RSA_2048    encode:",
startTime = time.time()
en_RSA(text)
print time.time()-startTime

print "RSA_2048    decode:",
startTime = time.time()
de_RSA(encrypted)
print time.time()-startTime
#===============================================================================
