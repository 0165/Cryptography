#make up a random.txt with 512,000,007B
#if cut 512,000,007B in every 16B, will have 7B left behind
import sys
import string
import random

file = open("random.txt","w")
i = 512*1000*1000+7
random.seed()
mystr = ''
while i>0:
    mystr+=random.choice(string.printable).encode('ascii')
    i-=1
file.write(mystr)
file.close()

file = open("random1.txt","w")
i = 1000*1000+7
mystr = ''
while i>0:
    mystr+=random.choice(string.printable).encode('ascii')
    i-=1
file.write(mystr)
file.close()