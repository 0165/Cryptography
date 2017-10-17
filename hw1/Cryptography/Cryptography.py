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
