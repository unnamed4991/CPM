#!/usr/bin/env python3

import sys
import argparse
from sys import getsizeof
from pbkdf2 import PBKDF2
from hashlib import sha256
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

class cpm:
    MODE_SHA = 1
    MODE_PBKDF2 = 2
    def genkey(self, passphrase: str, mode=MODE_SHA, salt=None):
        if mode == self.MODE_SHA:
            # Deprecated method.
            return sha256(passphrase.encode()).digest() 
        elif mode == self.MODE_PBKDF2:
            if not salt:
                salt = get_random_bytes(8)
            return PBKDF2(passphrase, salt).read(32), salt
        else:
            raise TabError()

    def encrypt(self, data: bytes, key: bytes, key_salt=None):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        if not key_salt:
            return cipher.nonce + tag + ciphertext
        return key_salt + cipher.nonce + tag + ciphertext

    def decrypt(self, data: bytes, key: bytes, mode=MODE_SHA):
        if mode == self.MODE_SHA:
            cipher = AES.new(key, AES.MODE_EAX, data[:16])
            return cipher.decrypt_and_verify(data[32:], data[16:32])
        elif mode == self.MODE_PBKDF2:
            cipher = AES.new(key, AES.MODE_EAX, data[8:24])
            return cipher.decrypt_and_verify(data[40:], data[24:40])

    def b2a(self, data: bytes):
        return b64encode(data).decode()

    def a2b(self, data: bytes):
        return b64decode(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt (default)", default=True)
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt", default=False)
    parser.add_argument("-p", "--pbkdf2", action="store_true", help="Use password-based key derivation function 2")
    args = parser.parse_args()

    if args.decrypt:
        try:
            encrypted = cpm().a2b(input("Encrypted message: "))
            passphrase = input("Passphrase: ")
        except KeyboardInterrupt:
            print()
            exit(0)

        if args.pbkdf2:
            key = cpm().genkey(passphrase, cpm().MODE_PBKDF2, encrypted[:8])[0]
            print(f"Key: {cpm().b2a(key)}")
            decrypted = cpm().decrypt(encrypted, key, cpm().MODE_PBKDF2).decode()
        else:
            key = cpm().genkey(passphrase)
            decrypted = cpm().decrypt(encrypted, key).decode()
            print("*** WARNING : deprecated key derivation used.")
            print("Using --pbkdf2 would be better.")
        print(f"Decrypted: {decrypted}")
        exit(0)

    elif args.encrypt:
        try:
            message = input("Message: ").encode()
            passphrase = input("Passphrase: ")
        except KeyboardInterrupt:
            print()
            exit(0)

        if args.pbkdf2:
            key, key_salt = cpm().genkey(passphrase, cpm().MODE_PBKDF2)
            print(f"Key: {cpm().b2a(key)}")
            encrypted = cpm().b2a(cpm().encrypt(message, key, key_salt))
        else:
            key = cpm().genkey(passphrase, cpm().MODE_SHA)
            encrypted = cpm().b2a(cpm().encrypt(message, key))
            print("*** WARNING : deprecated key derivation used.")
            print("Using --pbkdf2 would be better.")
        print(f"Encrypted: {encrypted}")
        exit(0)
    
    #try:
    #    file = str(sys.argv[1])
    #    passphrase = input("Passphrase: ")
    #except KeyboardInterrupt:
    #    print()
    #    exit(0)

    #try:
    #    f = open(file, "rb")
    #except FileNotFoundError:
    #    print(f"{sys.argv[0]}: cannot access '{file}': No such file")
    #    exit(2)
    #data = f.read()
    #f.close()
    #salt = urandom(8)
    #key = PBKDF2(passphrase, salt).read(32)
    #cipher = AES.new(key, AES.MODE_EAX)
    #ciphertext, tag = cipher.encrypt_and_digest(data)
    #f = open(file + ".enc", "wb")
    #[ f.write(x) for x in (salt, cipher.nonce, tag, ciphertext) ]
    #f.close()
