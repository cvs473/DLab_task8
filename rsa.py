from Crypto.Util import number
from math import gcd
import hashlib

  
def modInverse(A, M): 
    m0 = M 
    y = 0
    x = 1
  
    if (M == 1): 
        return 0
  
    while (A > 1): 
        q = A // M 
  
        t = M 
  
        M = A % M 
        A = t 
        t = y 
  
        y = x - q * y 
        x = t 
  
    if (x < 0): 
        x = x + m0 
  
    return x 


def setKeys(size):
    P = number.getPrime(size)
    Q = number.getPrime(size)
    global n
    n = P * Q
    phi = (P - 1) * (Q - 1)
    e = 2
    
    while (e < phi):
        if gcd(e, phi) == 1:
            break
        e += 1
    
    public_key = e
    
    d = modInverse(e, phi)
    private_key = d
    return public_key, private_key

def encrypt(message, key, block_size = 2):
    encrypted_blocks = []
    ciphertext = -1
    e = key

    if len(message) > 0:
        ciphertext = ord(message[0])

    for i in range(1, len(message)):
        if (i % block_size == 0):
            encrypted_blocks.append(ciphertext)
            ciphertext = 0
        ciphertext = ciphertext * 1000 + ord(message[i])

    encrypted_blocks.append(ciphertext)

    for i in range(len(encrypted_blocks)):
        encrypted_blocks[i] = str(pow(encrypted_blocks[i], e, n))

    encrypted_message = " ".join(encrypted_blocks)

    return encrypted_message

def decrypt(blocks, key, block_size = 2):
    list_blocks = blocks.split(' ')
    int_blocks = []
    d = key
 
    for s in list_blocks:
        int_blocks.append(int(s))
    message = ""
    
    for i in range(len(int_blocks)):
        int_blocks[i] = pow(int_blocks[i], d, n)
        
        tmp = ""
        for _ in range(block_size):
            if int_blocks[i] % 1000 == 0:
                continue
            tmp = chr(int_blocks[i] % 1000) + tmp
            int_blocks[i] //= 1000
        message += tmp
    return message


def digital_sign(og_message, private_key):
    message_digest = hashlib.sha256(og_message.encode('utf-8')).hexdigest()
    digital_signature = encrypt(message_digest, private_key)
    return digital_signature

def verify_auth(og_message, digital_sign, public_key):
    message_digest1 = hashlib.sha256(og_message.encode('utf-8')).hexdigest()
    message_digest2 = decrypt(digital_sign, public_key)
    if message_digest1 == message_digest2:
        return True
    else:
        return False
