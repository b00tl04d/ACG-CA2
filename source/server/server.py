#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------
from threading import Thread, Lock    # for handling task in separate jobs we need threading
import socket           # tcp protocol
import datetime         # for composing date/time stamp
import sys              # handle system error
import traceback        # for print_exc function
import time             # for delay purpose
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
import hashlib, hmac
global host, port

cmd_REQUEST_CERT = "CERT"
cmd_GET_PUBLIC_KEY = "GET_PUB_KEY"
cmd_AES_SESSION = "AES_SESSION"
cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
default_save_base = "result-"
hmac_key = "Secret"

host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server

# This takes in the menu of the day, then performs Encrypt then MAC  
def md5hmac_menu(menu_of_the_day: bytes, aes_key: bytes, iv: bytes):
    aes_encrypted_menu = encryption(menu_of_the_day, aes_key=aes_key, iv=iv)
    md5_hash = hashlib.md5

    #using the hmac key to md5 hash the plaintext
    menu_md5hmac = hmac.new(hmac_key.encode(), aes_encrypted_menu, md5_hash).hexdigest()
    print(f"hmac_md5 hash: {menu_md5hmac}")
    return aes_encrypted_menu, menu_md5hmac.encode()


# Generate a self-signed cert if it does not exist, otherwise return it
def get_cert():
    if not os.path.exists("../../deployment/server_cert.crt"):

        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate a public key from the private key
        public_key = private_key.public_key()

        # Create a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SG"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Singapore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPAM2"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SPAM2"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # our certificate will be valid for a year
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Write the certificate to disk, use .crt to specify its the certificate
        with open("../../deployment/server_cert.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Write the public key to disk
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("../../deployment/server_public.pem", "wb") as f:
            f.write(public_key)

        # Write the private key to disk
        with open("../../deployment/server_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return cert.public_bytes(serialization.Encoding.PEM)
    else:
        with open("../../deployment/server_cert.crt", "rb") as f:
            cert = f.read()
            return cert 


# Use a static AES key per session
def get_aes_session_key():
    # Generate it if it does not exist, else return it
    global iv
    if not os.path.exists("../../deployment/aes.key"):
        session_aes_key = get_random_bytes(AES.block_size)
        iv = get_random_bytes(AES.block_size)
        # Output AES Session Key and IV
        print(f"[AES SESSION KEY]")
        # Outputs AES Session Key bytes
        print(f"Key: {session_aes_key.hex()}")
        # Outputs IV bytes)
        print(f"Initialization Factor: {iv.hex()}")
        with open("../../deployment/aes.key", "wb") as aes:
            aes.write(session_aes_key)
        
        with open("../../deployment/iv.dat", "wb") as rand_iv:
            rand_iv.write(iv)
        return session_aes_key
    else:
        with open("../../deployment/aes.key", "rb") as aes:
            session_aes_key = aes.read()
        with open("../../deployment/iv.dat", "rb") as rand_iv:
            iv = rand_iv.read()
        return session_aes_key


# Signs AES Key using client's public RSA key 
def encrypt_aes_key(aes_key, public_key):
    # Encrypt the AES key with the RSA public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key


# Encrypts the menu with AES 256 Bits using the session AES key
def encryption(data, aes_key, iv):
    block_size = 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv) # AES Cipher in CBC Mode
    data_bytes = pad(data, 16)
    encrypted = cipher.encrypt(data_bytes)
    return encrypted


# Function to decrypt eod info 
def decryption(encrypted_data, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypt = cipher.decrypt(encrypted_data)
    decrypt = unpad(decrypt, 16)
    decrypted = decrypt.decode()
    return decrypted


def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        try:
            if blk_count == 0: #  1st block
                usr_cmd = net_bytes[0:15].decode("utf8", errors="ignore").rstrip()
                if cmd_REQUEST_CERT in usr_cmd:  # ask for digital cert
                    global self_signed_cert
                    try:
                        self_signed_cert = get_cert()
                    except Exception as e:
                        print(e)
                        print("Cert file not found: server_cert.crt")
                        sys.exit(0)
                    conn.send(self_signed_cert)
                    print("Sent self-signed cert to the client")
                    return
                elif cmd_GET_PUBLIC_KEY in usr_cmd:  # Exchange public key of client and server
                    global client_public_key
                    time.sleep(2) # Delay to handle this thread separately
                    try:
                        with open("../../deployment/server_public.pem", "rb") as f:
                            server_pub_key = f.read()
                    except:
                        print("file not found: server_public.pem")
                    conn.send(server_pub_key)
                    print("Sent over server's public key") 
                    client_pub_key = conn.recv(4096)
                    client_public_key = RSA.import_key(client_pub_key)
                    print("Received client's public key")
                    return
                elif cmd_AES_SESSION in usr_cmd:  # Initiate AES session 
                    time.sleep(2) # Delay to handle this thread separately
                    try:
                        global aes_key
                        aes_key = get_aes_session_key()
                    except Exception as e:
                        print(e)
                        print("Error in starting an AES session")
                        sys.exit(0)
                    encrypted_aes_key = encrypt_aes_key(aes_key=aes_key, public_key=client_public_key)
                    conn.send(encrypted_aes_key)
                    conn.send(iv)
                    return
                elif cmd_GET_MENU in usr_cmd: # ask for menu
                    try:
                        with open(default_menu,"rb") as f:
                            src_file = f.read()
                    except:
                        print("file not found : " + default_menu)
                        sys.exit(0)
                    #hints: you may apply a scheme (hashing/encryption) to read_bytes before sending to client.
                    encrypted_menu_data, md5hmac = md5hmac_menu(src_file, aes_key, iv)
                    conn.send(encrypted_menu_data)
                    conn.send(md5hmac)
                    print("Processed SENDING menu") 
                    return
                elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                    #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                    now = datetime.datetime.now()
                    filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                    with open(filename,"wb") as dest_file:
                        # Hints: net_bytes may be an encrypted block of message.
                        # AES Encrypted data sent over from the client, decryptable via the infrastructure AES key and IV
                        dest_file.write( net_bytes[ len(cmd_END_DAY): ] ) # remove the CLOSING header    
                        blk_count = blk_count + 1
                        print("saving file as " + filename)
                        print("Processed CLOSING done") 
        except:  # Just save end of day data
            # Hints: net_bytes may be an encrypted block of message. 
            # AES Encrypted data sent over from the client, decryptable via the infrastructure AES key and IV
            print("Saving end of day info")
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    time.sleep(3)
    dest_file.close()
    return


def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + " ended")
    return


def start_server():
    global host, port
    # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')
    
    try:
        soc.bind((host, port))
        print('Socket bind complete')
    except socket.error as msg:
        
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket and can accept 10 connection
    soc.listen(10)
    print('Socket now listening')

    # this will make an infinite loop needed for 
    # not reseting server for every client
    try:
        while True:
            conn, addr = soc.accept()
            # assign ip and port
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port)
            try:
                Thread(target=client_thread, args=(conn, ip, port)).start()
            except:
                print("Terrible error!")
                traceback.print_exc()
    except:
        pass
    soc.close()
    return

start_server()  
