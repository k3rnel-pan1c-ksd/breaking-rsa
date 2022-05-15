from math import ceil, floor, log10
import random
from sympy import *
import gmpy2
#cd breaking-rsa/bin; source activate; cd ..;cd code;
#pip3 install sympy
#pip3 install gmpy2
#python3 index.py

# Note: if the final results returns gibberish, try running the code multiple times, there seems to be an error sometimes in decoding from bytes to utf8 that I'm missing 

def printHorizontalLine():
    print("----------------------------\n")

def extendedEuclidianAlgorithm(a, b):
    if a == 0 : 
        return b, 0, 1            
    gcd, x1, y1 = extendedEuclidianAlgorithm(b%a, a)
    s = y1 - (b//a) * x1
    t = x1
    return gcd, s, t

def log2(x):
    return log10(x)/log10(2)
 
def isPowerOfTwo(num):
    return ceil(log2(num)) == floor(log2(num))


rand = random.getrandbits(1024)
print("Huuge RANDOM number that will help us choose p and q as the next and previous prime numbers:\n")
print(rand)
print(f"\nNumber of bits of randomly generated number: {gmpy2.bit_length(rand)}")
printHorizontalLine()

print("p (next prime number):\n")
p = nextprime(rand)
print(p)
print(f"\nNumber of bits of prime number p: {gmpy2.bit_length(p)}")
printHorizontalLine()

print("q (previous prime number):\n")
q = prevprime(rand)
print(q)
print(f"\nNumber of bits of prime number q: {gmpy2.bit_length(q)}")
printHorizontalLine()

print("Calculating n (public after calc) as p*q:\n")
n = p*q
print(n)
print(f"\nNumber of bits of n: {gmpy2.bit_length(n)}")
printHorizontalLine()

print("Calculating phi(n) (must stay super secret) as (p-1)*(q-1):\n")
phi = (p-1)*(q-1)
print(phi)
print(f"\nNumber of bits of phi(n): {gmpy2.bit_length(phi)}")
printHorizontalLine()

print("Choosing public key e from set \{1,2,...,phi(n)-1\}, s.t. gcd(e,phi(n))=1\n")
e = 65537
print(f"e (public):\n-----BEGIN RSA PUBLIC KEY-----")
print(e)
print("-----END RSA PUBLIC KEY-----\n")

print("Computing private key d, s.t. d is an inverse of e (e*d=1mod(phi(n)) using EEA\n")
EEA = extendedEuclidianAlgorithm(phi,e)
# Assert that gcd is 1
assert(EEA[0]==1)
# EEA -> EEA(n,a) => t in linear combination is a^(-1)
d = abs(EEA[2])
print("d (private key):\n-----BEGIN RSA PRIVATE KEY-----")
print(d)
print("-----END RSA PRIVATE KEY-----")
print(f"\nNumber of bits of private key d: {gmpy2.bit_length(d)}")
printHorizontalLine()

print("------TIME TO SAFELY DELETE p,q and phi(n) FOR SAFETY REASONS------")
p = 0
q = 0
phi = 0

print("\n\n##### ENCRYPTION on Alice's side #####")
ptxt = "Google uses Chuck Norris as a search engine."
print(f"Plaintext: {ptxt}\n")
ptxt = int.from_bytes(bytes(ptxt, 'UTF-8'), byteorder='big', signed=False)
print("Getting ciphertext as ctxt=pxt**e(mod n)\n")
ctxt = gmpy2.powmod(ptxt, e, n)
print(f"Ciphertext: {ctxt}")
print("####################\n\n")

print("##### HACKING TIME >> Fermat's factorization algorithm #####\n")
a = gmpy2.isqrt(n)+1

iterations = 0
while(iterations<100):
    b2 = pow(a,2)-n
    if(gmpy2.is_square(b2)):
        b=gmpy2.isqrt(b2)
        break
    a+=1
    iterations+=1

assert(iterations<100)
print(f"Successfully hacked in just {iterations+1} iterations")

print("Found a and b (check README for more info on them)\n")
print(f"a --> {a}")
print(f"b --> {b}\n")
printHorizontalLine()

print("Per algorithm, setting p as a+b and q as a-b\n")
p=a+b
q=a-b
print(f"p=>>{p}\n")
print(f"q=>>{q}\n")
printHorizontalLine()

print("Asserting that both p and q are prime")
assert(isprime(p))
print("p is prime!")
assert(isprime(q))
print("q is prime!")

print("Asserting that n == p*q")
assert(n==(p*q))
print("true => We got p and q!!!")

print("Calculating phi(n) (HAD TO stay super secret) as (p-1)*(q-1):\n")
phi = (p-1)*(q-1)
print(phi)
printHorizontalLine()

print("Calculating private key d !!!\n")
EEA = extendedEuclidianAlgorithm(phi,e)
# Assert that gcd is 1
assert(EEA[0]==1)
# EEA -> EEA(n,a) => t in linear combination is a^(-1)
d = abs(EEA[2])
print("d (HACKED private key):\n-----BEGIN RSA PRIVATE KEY-----")
print(d)
print("-----END RSA PRIVATE KEY-----")

print("\n\n##### DECRYPTION #####\n")
print("Getting plaintext as ptxt=ctxt**d(mod n)\n")

ptxt = int(gmpy2.powmod(ctxt, d, n))
ptxt = ptxt.to_bytes(ptxt.bit_length(), byteorder='big')
ptxt = ptxt.decode("utf-8",errors="replace")
print(f"Hacked plaintext: {ptxt}")
print("####################")