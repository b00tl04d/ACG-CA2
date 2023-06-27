import datetime
import sys              # handle system error
import socket
import time
import os
import hmac, hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import PKCS1_OAEP, AES 
from Cryptodome.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

with open("../../deployment/aes.key", "rb") as aes:
    session_aes_key = aes.read()
with open("../../deployment/iv.dat", "rb") as rand_iv:
    iv = rand_iv.read()

def decryption(file, aes_key, iv):
    with open(file, "rb") as f:
        dat = f.read()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypt = cipher.decrypt(dat)
    decrypt = unpad(decrypt, 16)
    decrypted = decrypt.decode()
    return decrypted

# IT WORKS
print(decryption("result-192.168.50.227-2023-02-11_0003", session_aes_key, iv))