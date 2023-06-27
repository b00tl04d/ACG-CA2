#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please start the tcp server first before running this client

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
global host, port

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_REQUEST_CERT = b"CERT"
cmd_GET_PUBLIC_KEY = b"GET_PUB_KEY"
cmd_AES_SESSION = b"AES_SESSION"
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"
hmac_key = b"Secret"


# Need to re-write
# Might need to encrypt the hmac_key in order to ensure integrity, or use a known HMAC key on the client and server
def verify_menu(encrypted_menu: bytes, received_md5hmac_hash: bytes):
    # Verify integrity of the menu
    md5_hash = hashlib.md5
    #using the hmac key to md5 hash the plaintext
    menu_md5hmac = hmac.new(hmac_key, encrypted_menu, md5_hash).hexdigest()
    print(f"Client-side generated hmac_md5 hash: {menu_md5hmac}")

    if menu_md5hmac.encode() == received_md5hmac_hash:
        return True
    return False


# Encrypts the day_end info with AES 256 Bits using the session AES key
def encryption(arg, aes_key, iv):
    block_size = 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv) # AES Cipher in CBC Mode
    encrypt_bytes = pad(arg.encode(), 16)
    encrypted = cipher.encrypt(encrypt_bytes)
    return encrypted


def decryption(encrypted, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypt = cipher.decrypt(encrypted)
    decrypt = unpad(decrypt, 16)
    decrypted = decrypt.decode()
    return decrypted


# Simulate writing of keys to PKI
def generate_client_keys():
    if not os.path.exists("../../deployment/client_public.pem") and not os.path.exists("../../deployment/client_private.pem"):
        client_rsakey_pair = RSA.generate(2048)
        client_public_key = client_rsakey_pair.public_key()
        client_private_key = client_rsakey_pair

        with open('../../deployment/client_public.pem', 'wb') as f:
            f.write(client_public_key.export_key('PEM'))

        with open('../../deployment/client_private.pem', 'wb') as f:
            f.write(client_private_key.export_key('PEM'))


# Outputs Certificate Details
def certificate_details(server_certificate, server_public_key):
    server_certificate = x509.load_pem_x509_certificate(server_certificate, default_backend())
    def get_pubkey_id(pubkey_object):
        if isinstance(pubkey_object, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(pubkey_object, ec.EllipticCurvePublicKey):
            return "ECC"
        elif isinstance(pubkey_object, dsa.DSAPublicKey):
            return "DSA"
        else:
            return None

    def getNameStr(subj):
        ans = []
        l = [('CN', NameOID.COMMON_NAME)]
        l.append(('OU', NameOID.ORGANIZATIONAL_UNIT_NAME))
        l.append(('O', NameOID.ORGANIZATION_NAME))
        l.append(('L', NameOID.LOCALITY_NAME))
        l.append(('ST', NameOID.STATE_OR_PROVINCE_NAME))
        l.append(('C', NameOID.COUNTRY_NAME))
        for e in l:
            att = subj.get_attributes_for_oid(e[1])
            if att:
                ans.append("{0}={1}".format(e[0], att[0].value))
        return ",".join(ans)
    
    print("Version: {0}".format(str(server_certificate.version)))
    print("Serial No: {0:x}".format(server_certificate.serial_number))
    subjStr = getNameStr(server_certificate.subject)
    print("Subject: {0}".format(subjStr))
    signature_algo_oid = server_certificate.signature_algorithm_oid
    # updated due to change in Cyrptography API change
    print("Signature Algorithm: {0}".format(signature_algo_oid._name))
    print("Key {0} public key, {1} bits".format(
        get_pubkey_id(server_public_key), server_public_key.key_size))
    
    print("Public Numbers:", end=" ")
    nstr = str(server_public_key.public_numbers().n)
    while len(nstr) > 0:
        print(nstr[:80])
        nstr = nstr[80:]

    print('Public exponent: {0}'.format(server_public_key.public_numbers().e))
    # insert your codes to display the validity info of the cert
    print("Validity:")
    print("From: {0}".format(
        server_certificate.not_valid_before.strftime("%a %b %d %H:%M:%S %Y")))
    print("To: {0}".format(server_certificate.not_valid_after.strftime("%a %b %d %H:%M:%S %Y")))
    issuerStr = getNameStr(server_certificate.issuer)
    print("Issuer: {0}".format(issuerStr))
    return


# For receiving the digital certificate
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cert_socket:
    print("Getting Cert\n")
    cert_socket.connect((host, port))
    cert_socket.sendall(cmd_REQUEST_CERT)
    server_cert = cert_socket.recv(4096)
    cert_socket.close()


# Exchange public key of client and server if the server public key is verified
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as pub_key_socket:
    print("Performing RSA public key exchange\n")
    pub_key_socket.connect((host, port))
    pub_key_socket.sendall(cmd_GET_PUBLIC_KEY)
    server_pub_key = pub_key_socket.recv(4096)

    generate_client_keys()

    server_pub_key = serialization.load_pem_public_key(server_pub_key, backend=default_backend())

    print("---Cert Details---")
    certificate_details(server_cert, server_pub_key)

    extracted_server_cert = x509.load_pem_x509_certificate(server_cert, default_backend())
    extracted_server_pub_key = extracted_server_cert.public_key()

    # Ensure public key and public key from cert matches
    if server_pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) == extracted_server_pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):
        with open('../../deployment/client_public.pem', 'rb') as f:
            client_pub_key = f.read()
        pub_key_socket.send(client_pub_key)
    pub_key_socket.close()


# For exchanging the AES session key 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as aes_socket:
    print("\nEstablishing AES session")
    aes_socket.connect((host, port))
    aes_socket.sendall(cmd_AES_SESSION)
    aes_key = aes_socket.recv(4096)
    aes_iv = aes_socket.recv(4096)
    private_key_bytes = open("../../deployment/client_private.pem", "rb").read()
    server_private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(server_private_key)
    decrypted_aes_key = cipher.decrypt(aes_key)
    aes_socket.close()


# Receive menu of the day
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU )
    encrypted_menu_data = my_socket.recv(4096)
    md5hmac = my_socket.recv(4096)
    #hints : need to apply a scheme to verify the integrity of data.  
    if verify_menu(encrypted_menu_data, md5hmac):
        print("Menu of the day validated.")
        menu_file = open(menu_file, "wb")
        decrypted_menu = decryption(encrypted=encrypted_menu_data, aes_key=decrypted_aes_key, iv=aes_iv)
        menu_file.write(decrypted_menu.encode())
        menu_file.close()
    else:
        print("Menu has been tempered with, invalid menu.")
        my_socket.send(b"Tempered menu sent over to the client")
        my_socket.close()
    my_socket.close()
print('Menu today received from server')


# Send day_end info
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
        out_file = open(return_file,"rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    file_bytes = out_file.read(1024)
    sent_bytes=b''
    while file_bytes != b'':
        # hints: need to protect the file_bytes in a way before sending out.
        encrypted_day_end = encryption(file_bytes.decode(), aes_key=decrypted_aes_key, iv=aes_iv)
        my_socket.send(encrypted_day_end)
        sent_bytes+=file_bytes
        file_bytes = out_file.read(1024) # read next block from file
    out_file.close()
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
