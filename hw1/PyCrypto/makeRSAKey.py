from Crypto.PublicKey import RSA

key = RSA.generate(2048)
f = open('privateKey.txt','w')
f.write(key.exportKey())
f.close()
f = open('publicKey.txt','w')
f.write(key.publickey().exportKey())
f.close()
print key.exportKey()
print key.publickey().exportKey()
