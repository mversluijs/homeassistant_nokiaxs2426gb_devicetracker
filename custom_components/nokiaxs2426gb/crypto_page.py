from base64 import b64decode
from base64 import b64encode
from base64 import urlsafe_b64decode
from base64 import urlsafe_b64encode

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import os

__version__ = "1.0.0"

def base64url_escape(b64):
    out = ""
    for c in b64:
        if c == "+":
            out += "-"
        elif c == "/":
            out += "_"
        elif c == "=":
            out += "."
        else:
            out += str(c)
    return out

class AESCipher:
    def __init__(self):
        self.key = os.urandom(16)
        self.aesinfo = None
        self.cipher = None
        self.ck = None

    def encrypt_orig(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def rsa_encrypt(self, pubkey, plaintext):
        rsa_key = RSA.importKey(b64decode(pubkey))
        # print(pubkey)
        rsa = PKCS1_v1_5.new(rsa_key)
        # rsa = PKCS1_OAEP.new(rsa_key)
        self.ck = rsa.encrypt(plaintext.encode('utf-8'))
        self.ck = urlsafe_b64encode(self.ck).decode('ascii')
        self.ck = base64url_escape(self.ck)
        # self.ck = self.ck.rstrip('=')
        return self.ck

    def rsa_decrypt(self, privkey, ciphertext):
        # rsa_key = RSA.importKey(urlsafe_b64decode(privkey))
        rsa_key = RSA.importKey(b64decode(privkey))
        # print(privkey)
        rsa = PKCS1_v1_5.new(rsa_key)
        ciphertext = ciphertext + '=' * (4 - len(ciphertext) % 4)
        ciphertext = urlsafe_b64decode(ciphertext.encode('ascii'))
        plaintext = rsa.decrypt(ciphertext, b'DECRYPTION FAILED')
        return plaintext.decode('utf8')
    
    def encrypt(self, pubkey, data):
        iv = os.urandom(16)

        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)

        print(self.key)
        print(iv)
        self.aesinfo = b64encode(self.key).decode('utf-8') + " "  + b64encode(iv).decode('utf-8')
        print(self.aesinfo)
        print(len(self.aesinfo))
        print(self.aesinfo.encode('utf-8'))

        self.ck = self.rsa_encrypt(pubkey, self.aesinfo)

        # rsa_key = RSA.importKey(urlsafe_b64decode(pubkey))
        # print(pubkey)
        # rsa = PKCS1_v1_5.new(rsa_key)
        # # rsa = PKCS1_OAEP.new(rsa_key)
        # self.ck = urlsafe_b64encode(rsa.encrypt(b64decode(self.aesinfo))).decode('utf-8').rstrip('=')
        # self.ck = rsa.encrypt(self.aesinfo.encode('utf-8'))
        # self.ck = urlsafe_b64encode(self.ck).decode('utf-8')
        # self.ck = self.ck.rstrip('=')

        ciphertext = self.encrypt_w_key(urlsafe_b64encode(self.key).decode('utf-8'), data, urlsafe_b64encode(iv).decode('utf-8'))

        # ciphertext = data.encode('utf-8')
        # ciphertext = pad(ciphertext, AES.block_size)
        # ciphertext = self.cipher.encrypt(ciphertext)
        # ciphertext = urlsafe_b64encode(ciphertext).decode('utf-8').rstrip('=')

        # return urlsafe_b64encode(self.cipher.encrypt(pad(data.encode('utf-8'), 
        #     AES.block_size))).decode('utf-8').rstrip('=')
        return ciphertext

    def decrypt(self, data, iv):
        raw = b64decode(data)
        raw = iv + raw
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)

    def encrypt_w_key(self, key, data, iv):
        
        rawkey = urlsafe_b64decode(key)
        rawiv = urlsafe_b64decode(iv)
        
        self.cipher = AES.new(rawkey, AES.MODE_CBC, rawiv)

        return urlsafe_b64encode(self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size))).decode('utf-8').rstrip('=')

    def decrypt_w_key(self, key, data, iv):
        # rawdata = b64decode(data)
        rawdata = urlsafe_b64decode(data + '=' * (4 - len(data) % 4))
        # print(rawdata)
        # rawdata = urlsafe_b64decode(data)
        rawkey = urlsafe_b64decode(key)
        rawiv = urlsafe_b64decode(iv)
        rawdata = rawiv + rawdata


        self.cipher = AES.new(rawkey, AES.MODE_CBC, rawiv)
        # print(self.cipher.decrypt(rawdata[AES.block_size:]), AES.block_size)
        return unpad(self.cipher.decrypt(rawdata[AES.block_size:]), AES.block_size)


if __name__ == '__main__':
    print('TESTING ENCRYPTION')
    msg = input('Message...: ')
    pwd = input('Password..: ')
    print('Ciphertext:', AESCipher(pwd).encrypt(msg).decode('utf-8'))

    print('\nTESTING DECRYPTION')
    cte = input('Ciphertext: ')
    pwd = input('Password..: ')
    print('Message...:', AESCipher(pwd).decrypt(cte).decode('utf-8'))