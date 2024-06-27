from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20
import os
import secrets
import magic
from sqlite_persistence import *
import zipfile
from flask import Flask, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import resource
from timeout_decorator import timeout, TimeoutError

#Folder where the files to cipher are saved
CIPHER_FOLDER = os.path.join(os.getcwd(), "cipher-folder")

#Folder where the keys to be exported to the user are saved
EXPORT_FOLDER = os.path.join(os.getcwd(), "export-folder")

#Global variables
global username
username=None

global file_to_download
file_to_download=None


global operation_speed
operation_speed=None

#Global constants
AES_KEY_LENGTH=256
AES_IV_LENGTH= 128

TRIPLEDES_KEY_LENGTH=192
TRIPLEDES_IV_LENGTH=128

CHACHA_KEY_LENGTH=256
CHACHA_NONCE_LENGTH=96

MAX_EXECUTION_TIME=13

#Global setters
def set_username(name):
    global username
    username=name

def set_file(file):
    global file_to_download
    file_to_download=file

def set_speed(speed):
    global operation_speed
    if speed:
        operation_speed="{:.6f}".format(speed)


def security_flush():
    for filename in os.listdir(CIPHER_FOLDER):
        os.remove(os.path.join(app.config["CIPHER_FOLDER"],filename))
    for filename in os.listdir(EXPORT_FOLDER):
        os.remove(os.path.join(app.config["EXPORT_FOLDER"],filename))
    set_file(None)

def speed_flush():
    set_speed(None)

def isPEMfile(filename):
    file_extension=key_extension(filename)
    return file_extension == '.pem'

def file_extension(filename):
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(filename)
    print(file_type)
    extension = os.path.splitext('.' + file_type.split('/')[-1])[0]
    print(extension)
    if extension == ".octet-stream":
        extension ='.cyp'
    return extension

def decrypt_rename(filename):
    extension = file_extension(filename)
    try:
        os.rename(filename,filename+extension)
    except FileExistsError:
        os.remove(filename+extension)
        os.rename(filename,filename+extension)
    return(filename+extension)


def get_filename(filename):
    return os.path.splitext(filename)[0]
    

def key_extension(keyfile):
    return os.path.splitext(keyfile)[1]


def encrypt_rename(filename):
    try:
        os.rename(filename,filename+'.cyp')
    except FileExistsError:
        os.remove(filename+'.cyp')
        os.rename(filename,filename+'.cyp')
    return(filename+'.cyp')


def AES_encrypt(input_file, username):
    try:
        #Starting time to encrypt to calculate the duration
        AES_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        #Get the user AES key and iv to encrypt
        key = get_AES_key(username)
        iv = get_AES_iv(username)

        AES_cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
        with open(input_file, 'rb') as AES_file:
            AES_plaintext = AES_file.read()
        AES_file.close()
        AES_plaintext_length = 16 - (len(AES_plaintext) % 16)
        AES_plaintext += bytes([AES_plaintext_length]) * AES_plaintext_length # Adding to AES its length * 16
        AES_ciphertext, AES_tag = AES_cipher.encrypt_and_digest(AES_plaintext)
        AES_output_file=get_filename(input_file)
        with open(AES_output_file, 'wb') as AES_file:
            [ AES_file.write(x) for x in (AES_tag, AES_ciphertext) ]
        AES_file.close()
        os.remove(input_file)
        AES_output_file=encrypt_rename(AES_output_file)
        AES_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        AES_encryption_time= AES_end_time - AES_start_time
        set_speed(AES_encryption_time)
        return AES_output_file
    except:
        return None


def AES_decrypt(input_file, username):
    try:
        #Starting time to decrypt to calculate the duration
        AES_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        #Get the user AES key and iv to decrypt
        key = get_AES_key(username)
        iv = get_AES_iv(username)

        with open(input_file, 'rb') as AES_file:
            AES_tag, AES_ciphertext = [ AES_file.read(x) for x in (16, -1) ]
        AES_file.close()
        AES_cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
        AES_padded_plaintext = AES_cipher.decrypt_and_verify(AES_ciphertext, AES_tag)
        AES_plaintext = AES_padded_plaintext[:-AES_padded_plaintext[-1]]
        AES_output_file=get_filename(input_file)
        with open(AES_output_file, 'wb') as AES_file:
            AES_file.write(AES_plaintext)
        AES_file.close()
        os.remove(input_file)
        AES_output_file=decrypt_rename(AES_output_file)
        AES_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        AES_decryption_time= AES_end_time - AES_start_time
        set_speed(AES_decryption_time)
        return AES_output_file
    except:
        return None

def import_AES_keys(username, key, iv):
    if(key_extension(key)=='.pem' and key_extension(iv)=='.pem'):
        with open(key,'rb') as AES_key_file:
            AES_key=AES_key_file.read()
            AES_key_file.close()
        with open(iv,'rb') as AES_iv_file:
            AES_iv=AES_iv_file.read()
            AES_iv_file.close()
        if(verify_AES_length(AES_key,AES_iv)):
            insert_AES_keys(username, AES_key, AES_iv)
            return True
        else:
            print("AES import keys error due to the length")
            return False
    else:
        print("AES import keys error due to the extension")
        return False

def verify_AES_length(key,iv):
    if(len(key)== AES_KEY_LENGTH//8  and len(iv)==AES_IV_LENGTH//8):
        return True
    else:
        return False
    
def RSA_encrypt(input_file, username, chunk_size=190):
    try:
        #Starting time to encrypt to calculate the duration
        RSA_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        # Load public key and generate a new cipher objetc
        public_key=get_RSA_public_key(username)
        RSA_public_key = RSA.import_key(public_key)
        RSA_cipher = PKCS1_OAEP.new(RSA_public_key)
        RSA_output_file=get_filename(input_file)
        
        # Open input/output files
        with open(input_file, 'rb') as RSA_plaintext, open(RSA_output_file, 'wb') as RSA_ciphertext:
            while True:
                # Read in a chunk of the input file
                chunk = RSA_plaintext.read(chunk_size)
                if len(chunk) == 0:
                    break
                # Encrypt the chunk and write it to the output file
                encrypted_chunk = RSA_cipher.encrypt(chunk)
                RSA_ciphertext.write(encrypted_chunk)
        RSA_plaintext.close()
        RSA_ciphertext.close()
        os.remove(input_file)
        RSA_output_file=encrypt_rename(RSA_output_file)
        RSA_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        RSA_encryption_time=RSA_end_time - RSA_start_time
        set_speed(RSA_encryption_time)
        return RSA_output_file
    except:
        return None
    
    
def RSA_decrypt(input_file, username, chunk_size=256):
    try:
        #Starting time to decrypt to calculate the duration
        RSA_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        # Load private key and generate a new cipher objetc
        private_key= get_RSA_private_key(username)
        RSA_private_key = RSA.import_key(private_key)
        RSA_cipher = PKCS1_OAEP.new(RSA_private_key)
        RSA_output_file=get_filename(input_file)
        
        # Open input/output files
        with open(input_file, 'rb') as RSA_ciphertext,open(RSA_output_file, 'wb') as RSA_plaintext:
            while True:
                # Read in a chunk of the input file
                chunk = RSA_ciphertext.read(chunk_size)
                if len(chunk) == 0:
                    break
                # Decrypt the chunk and write it to the output file
                decrypted_chunk = RSA_cipher.decrypt(chunk) #MIRAR ESTO PARA CIFRADO
                RSA_plaintext.write(decrypted_chunk)
        RSA_ciphertext.close()
        RSA_plaintext.close()
        os.remove(input_file)
        RSA_output_file=decrypt_rename(RSA_output_file)
        RSA_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        RSA_decryption_time=RSA_end_time - RSA_start_time
        set_speed(RSA_decryption_time)
        return RSA_output_file
    except:
        return None
    
    
def import_RSA_keys(username, private_key, public_key):
    
    if(key_extension(private_key)=='.pem' and key_extension(public_key)=='.pem'):
        
        with open(private_key,'rb') as RSA_private_key_file:
            RSA_private_key=RSA_private_key_file.read()
            RSA_private_key_file.close()
            
        with open(public_key,'rb') as RSA_public_key_file:
            RSA_public_key=RSA_public_key_file.read()
            RSA_public_key_file.close()
        insert_RSA_keys(username,RSA_public_key,RSA_private_key)
        return True
    else:
        print("RSA import fail")
        return False
        

def TripleDES_encrypt(input_file, username):
    try:
        #Starting time to encrypt to calculate the duration
        TripleDES_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        #Initialize the TripleDES cipher object in EAX mode of operation
        key = get_TripleDES_key(username)
        iv = get_TripleDES_iv(username)
        TripleDES_cipher = DES3.new(key, DES3.MODE_EAX, nonce=iv)
        TripleDES_output_file=get_filename(input_file)

        #Encrypt the input file and write the ciphertext to the output file
        with open(input_file, 'rb') as TripleDES_plaintext, open(TripleDES_output_file, 'wb') as TripleDES_ciphertext:
            data = TripleDES_plaintext.read(1024)  # Read the input file in 1KB blocks
            while data:
                ciphertext = TripleDES_cipher.encrypt(data)
                TripleDES_ciphertext.write(ciphertext)
                data = TripleDES_plaintext.read(1024)
        TripleDES_plaintext.close()
        TripleDES_ciphertext.close()
        os.remove(input_file)
        TripleDES_output_file=encrypt_rename(TripleDES_output_file)
        TripleDES_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        TripleDES_encryption_time= TripleDES_end_time - TripleDES_start_time
        set_speed(TripleDES_encryption_time)
        return TripleDES_output_file
    except:
        return None

def TripleDES_decrypt(input_file, username):
    try:
        #Starting time to decrypt to calculate the duration
        TripleDES_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        #Initialize the TripleDES cipher object in EAX mode of operation
        key = get_TripleDES_key(username)
        iv = get_TripleDES_iv(username)
        TripleDES_cipher = DES3.new(key, DES3.MODE_EAX, nonce=iv)  # Create a new cipher object with the same key and iv
        TripleDES_output_file=get_filename(input_file)
        
        #Decrypt the output file and write the plaintext to a new file
        with open(input_file, 'rb') as TripleDES_ciphertext, open(TripleDES_output_file, 'wb') as TripleDES_plaintext:
            data = TripleDES_ciphertext.read(1024)  # Read the output file in 1KB blocks
            while data:
                plaintext = TripleDES_cipher.decrypt(data)
                TripleDES_plaintext.write(plaintext)
                data = TripleDES_ciphertext.read(1024)
        TripleDES_ciphertext.close()
        TripleDES_plaintext.close()
        os.remove(input_file)
        TripleDES_output_file=decrypt_rename(TripleDES_output_file)
        TripleDES_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        TripleDES_decryption_time= TripleDES_end_time - TripleDES_start_time
        set_speed(TripleDES_decryption_time)
        return TripleDES_output_file
    except:
        return None

def import_TripleDES_keys(username, key, iv):
    if(key_extension(key)=='.pem' and key_extension(iv)=='.pem'):
        with open(key,'rb') as TripleDES_key_file:
            TripleDES_key=TripleDES_key_file.read()
            TripleDES_key_file.close()
        with open(iv,'rb') as TripleDES_iv_file:
            TripleDES_iv=TripleDES_iv_file.read()
            TripleDES_iv_file.close()
        if(verify_TripleDES_length(TripleDES_key,TripleDES_iv)):
            insert_TripleDES_keys(username, TripleDES_key, TripleDES_iv)
            return True
        else:
            print("TripleDES import keys error")
            return False
    else:
        print("TripleDES import keys error 2")
        return False

def verify_TripleDES_length(key,iv):
    if(len(key)== TRIPLEDES_KEY_LENGTH//8  and len(iv)==TRIPLEDES_IV_LENGTH//8):
        return True
    else:
        return False

def ChaCha_encrypt(input_file, username):
    try:
        #Starting time to encrypt to calculate the duration
        ChaCha_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        # Create the cipher object
        key= get_ChaCha20_key(username)
        nonce= get_ChaCha20_nonce(username)
        ChaCha_cipher = ChaCha20.new(key=key, nonce=nonce)
        ChaCha_output_file=get_filename(input_file)
        
        with open(input_file, 'rb') as ChaCha_plaintext, open(ChaCha_output_file, 'wb') as ChaCha_ciphertext:
            # Read and encrypt the input file in chunks
            chunk_size = 1024 * 1024
            while True:
                chunk = ChaCha_plaintext.read(chunk_size)
                if len(chunk) == 0:
                    break
                ciphertext = ChaCha_cipher.encrypt(chunk)
                ChaCha_ciphertext.write(ciphertext)
        ChaCha_plaintext.close()
        ChaCha_ciphertext.close()
        os.remove(input_file)
        ChaCha_output_file=encrypt_rename(ChaCha_output_file)
        ChaCha_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        ChaCha_encryption_time= ChaCha_end_time - ChaCha_start_time
        set_speed(ChaCha_encryption_time)
        return ChaCha_output_file
    except:
        return None

def ChaCha_decrypt(input_file, username):
    try:
        #Starting time to decrypt to calculate the duration
        ChaCha_start_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime

        # Create the cipher object
        key= get_ChaCha20_key(username)
        nonce= get_ChaCha20_nonce(username)
        ChaCha_cipher = ChaCha20.new(key=key, nonce=nonce)
        ChaCha_output_file=get_filename(input_file)
        
        with open(input_file, 'rb') as ChaCha_ciphertext, open(ChaCha_output_file, 'wb') as ChaCha_plaintext:
            # Read and decrypt the input file in chunks
            chunk_size = 1024 * 1024
            while True:
                chunk = ChaCha_ciphertext.read(chunk_size)
                if len(chunk) == 0:
                    break
                plaintext = ChaCha_cipher.decrypt(chunk)
                ChaCha_plaintext.write(plaintext)
        ChaCha_ciphertext.close()
        ChaCha_plaintext.close()
        os.remove(input_file)
        ChaCha_output_file=decrypt_rename(ChaCha_output_file)
        ChaCha_end_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        ChaCha_decryption_time= ChaCha_end_time - ChaCha_start_time
        set_speed(ChaCha_decryption_time)
        return ChaCha_output_file
    except:
        return None

def import_ChaCha20_keys(username, key, nonce):
    if(key_extension(key)=='.pem' and key_extension(nonce)=='.pem'):
        with open(key,'rb') as ChaCha20_key_file:
            ChaCha20_key=ChaCha20_key_file.read()
            ChaCha20_key_file.close()
        with open(nonce,'rb') as ChaCha20_nonce_file:
            ChaCha20_nonce=ChaCha20_nonce_file.read()
            ChaCha20_nonce_file.close()
        if(verify_ChaCha_length(ChaCha20_key,ChaCha20_nonce)):
            insert_ChaCha20_keys(username, ChaCha20_key, ChaCha20_nonce)
            return True
        else:
            print("ChaCha import error 1")
            return False
    else:
        print("ChaCha import keys error 2")
        return False

def verify_ChaCha_length(key,nonce):
    if(len(key)== CHACHA_KEY_LENGTH//8  and len(nonce)==CHACHA_NONCE_LENGTH//8):
        return True
    else:
        return False

def encrypt_file(input_file, username, cipher):
    file_decrypted=None
    if cipher ==1:
        try:
            file_decrypted= AES_encrypt(input_file, username)
        except:
            return None
    elif cipher ==2:
        try:
            file_decrypted= RSA_encrypt(input_file, username)
        except:
            return None
    elif cipher ==3:
        try:
            file_decrypted= TripleDES_encrypt(input_file, username)
        except:
            return None
    elif cipher ==4:
        try:
            file_decrypted= ChaCha_encrypt(input_file, username)
        except:
            return None
    return file_decrypted

def decrypt_file(input_file, username, cipher):
    file_decrypted=None
    if cipher ==1:
        try:
            file_decrypted= AES_decrypt(input_file, username)
        except:
            return None
    elif cipher ==2:
        try:
            file_decrypted= RSA_decrypt(input_file, username)
        except:
            return None
    elif cipher ==3:
        try:
            file_decrypted= TripleDES_decrypt(input_file, username)
        except:
            return None
    elif cipher ==4:
        try:
            file_decrypted= ChaCha_decrypt(input_file, username)
        except:
            return None
    return file_decrypted

def create_keys(username, cipher):
    if cipher ==1: #Creates AES keys
        AES_key = secrets.token_bytes(32) # Generates a 32-byte (256-bit) random secure value for the AES key
        AES_iv = secrets.token_bytes(16) # Generates a 16-byte (128-bit) random secure value for the AES IV
        insert_AES_keys(username, AES_key,AES_iv)

    elif cipher ==2: #Creates RSA keys
        RSA_key = RSA.generate(2048)  #Generate a RSA key pair secure with 2048 bits
        RSA_private_key= RSA_key.export_key()
        RSA_public_key= RSA_key.publickey().export_key()   
        insert_RSA_keys(username,RSA_public_key,RSA_private_key)     

    elif cipher ==3: #Creates TripleDES keys
        TripleDES_key = secrets.token_bytes(24) # Generates a 24-byte (192-bit) random secure value for the TripleDES key
        TripleDES_iv = secrets.token_bytes(16) # Generates a 16-byte (128-bit) random secure value for the TripleDES iv
        insert_TripleDES_keys(username, TripleDES_key,TripleDES_iv)

    elif cipher ==4: #Creates ChaCha20 keys
        ChaCha20_key = secrets.token_bytes(32) # Generates a 32-byte (256-bit) random secure value for the ChaCha20 key
        ChaCha_nonce = secrets.token_bytes(12) # Generates a 12-byte (96-bit) random secure value for the ChaCha20 nonce
        insert_ChaCha20_keys(username, ChaCha20_key,ChaCha_nonce)

def create_keys_zip(zip_filename, first_file, second_file):
    with zipfile.ZipFile(zip_filename, 'w') as zipf:
        zipf.write(first_file)
        zipf.write(second_file)
    os.remove(first_file)
    os.remove(second_file)
    return zip_filename

def export_keys(username, cipher):
    keys_zip=None
    if cipher ==1: #Get AES keys
        AES_key = get_AES_key(username)
        with open('AES_key.pem', 'wb') as AES_key_file:
            AES_key_file.write(AES_key)
            AES_key_file.close()
        AES_iv = get_AES_iv(username)
        with open('AES_iv.pem', 'wb') as AES_iv_file:
            AES_iv_file.write(AES_iv)
            AES_iv_file.close()
        file_path='AES_keys.zip'
        zip_path= os.path.join(app.config["EXPORT_FOLDER"],file_path)
        keys_zip=create_keys_zip(zip_path,'AES_key.pem','AES_iv.pem')

    elif cipher ==2: #Get RSA keys
        RSA_private_key= get_RSA_private_key(username)
        with open('RSA_private_key.pem', 'wb') as RSA_private_key_file:
            RSA_private_key_file.write(RSA_private_key)
            RSA_private_key_file.close()
        RSA_public_key= get_RSA_public_key(username)
        with open('RSA_public_key.pem', 'wb') as RSA_public_key_file:
            RSA_public_key_file.write(RSA_public_key)
            RSA_public_key_file.close()
        file_path='RSA_keys.zip'
        zip_path= os.path.join(app.config["EXPORT_FOLDER"],file_path)
        keys_zip=create_keys_zip(zip_path,'RSA_private_key.pem','RSA_public_key.pem')

    elif cipher ==3: #Get TripleDES keys
        TripleDES_key = get_TripleDES_key(username)
        with open('TripleDES_key.pem', 'wb') as TripleDES_key_file:
            TripleDES_key_file.write(TripleDES_key)
            TripleDES_key_file.close()
        TripleDES_iv = get_TripleDES_iv(username)
        with open('TripleDES_iv.pem', 'wb') as TripleDES_iv_file:
            TripleDES_iv_file.write(TripleDES_iv)
            TripleDES_iv_file.close()
        file_path='TripleDES_keys.zip'
        zip_path= os.path.join(app.config["EXPORT_FOLDER"],file_path)
        keys_zip=create_keys_zip(zip_path,'TripleDES_key.pem','TripleDES_iv.pem')


    elif cipher ==4: #Get ChaCha20 keys
        ChaCha20_key = get_ChaCha20_key(username)
        with open('ChaCha20_key.pem', 'wb') as ChaCha20_key_file:
            ChaCha20_key_file.write(ChaCha20_key)
            ChaCha20_key_file.close()
        ChaCha_nonce = get_ChaCha20_nonce(username)
        with open('ChaCha20_nonce.pem', 'wb') as ChaCha_nonce_file:
            ChaCha_nonce_file.write(ChaCha_nonce)
            ChaCha_nonce_file.close()
        file_path='ChaCha20_keys.zip'
        zip_path= os.path.join(app.config["EXPORT_FOLDER"],file_path)
        keys_zip=create_keys_zip(zip_path,'ChaCha20_key.pem','ChaCha20_nonce.pem')
    return keys_zip

app = Flask(__name__)
app.config["CIPHER_FOLDER"] = CIPHER_FOLDER
app.config["EXPORT_FOLDER"] = EXPORT_FOLDER

# Principal page with all the options
@app.route('/')
def principal():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    return render_template("principal.html")

# Project general information
@app.route('/about')
def about():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    return render_template("about.html")

@app.route('/login', methods=['GET','POST'])
def login():
    security_flush()
    speed_flush()
    if username:
        return redirect(url_for('principal'))
    if request.method == "POST":
        name=request.form.get('username')
        password=request.form.get('password')
        if(exists_username(name) and verify_credentials(name,password)):
            set_username(name)
            return redirect(url_for('principal'))
        else:
            return render_template('login.html',errorMessage="Username or password incorrect, please try again")
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    security_flush()
    speed_flush()
    if username:
        return redirect(url_for('principal'))
    if request.method == "POST":
        name=request.form.get('username')
        password=request.form.get('password')
        nickname=request.form.get('nickname')
        if(is_strong_password(password)==False):
            return render_template('register.html',errorMessage="Password is so weak, please try again")
        if(exists_username(name) or exists_nickname(nickname)):
            return render_template('register.html',errorMessage="Error in register process, please try again")
        else:
            insert_user(name, password, nickname)
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    set_username(None)
    return redirect(url_for('login'))


# Key manager page
@app.route('/keymanager')
def keymanager():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    return render_template('key-manager.html')

# Cipher page
@app.route('/cipher', methods=['GET','POST'])

def cipher():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    if request.method == "POST":

        #Get the file to encrypt/decrypt
        file= request.files["cipherfile"]
        if not file:
            return render_template("cipher.html", errorMessage="Please, choose a file")
        
        #Get the cryptographic operation
        selected_operation=request.form.get('cipheroperation')
        if not selected_operation:
            return render_template("cipher.html",  errorMessage="Please, choose an operation")
        
        #Get the algorithm
        selected_algorithm=request.form.get('algorithm')
        if not selected_algorithm:
            return render_template("cipher.html",  errorMessage="Please, choose an algorithm")
        
        #Store the file into the server
        cipherfile=os.path.join(app.config["CIPHER_FOLDER"], secure_filename(file.filename))
        file.save(cipherfile)
        
        if selected_operation=='Encrypt': #Encryption operation selected
            if selected_algorithm=='AES': 
                new_file=encrypt_file(cipherfile, username, 1) #AES encrypt
            elif selected_algorithm=='RSA':
                new_file=encrypt_file(cipherfile, username, 2) #RSA encrypt
            elif selected_algorithm=='TripleDES':
                new_file=encrypt_file(cipherfile, username, 3) #TripleDES encrypt
            elif selected_algorithm=='ChaCha':
                new_file=encrypt_file(cipherfile, username, 4) #ChaCha encrypt
            else: #If the algorithm is not correct
                return render_template('cipher.html',  errorMessage="Algorithm unknown, please choose a real algorithm")
            
        elif(selected_operation=='Decrypt'):#Decryption operation selected
            if selected_algorithm=='AES': 
                new_file=decrypt_file(cipherfile, username, 1) #AES decrypt
            elif selected_algorithm=='RSA':
                new_file=decrypt_file(cipherfile, username, 2) #RSA decrypt
            elif selected_algorithm=='TripleDES':
                new_file=decrypt_file(cipherfile, username, 3) #TripleDES decrypt
            elif selected_algorithm=='ChaCha':
                new_file=decrypt_file(cipherfile, username, 4) #ChaCha decrypt
            else: #If the algorithm is not correct
                return render_template('cipher.html',  errorMessage="Algorithm unknown, please choose a real algorithm")
            
        else: #If the operation is no correct
            return render_template('cipher.html',  errorMessage="Operation unknown, please try again")
        if not new_file:
            return render_template('cipher.html',  errorMessage="Unknown error in cryptographic operation")
        set_file(new_file)
        return redirect(url_for('prepare'))

    return render_template('cipher.html')


# Cipher preparation page
@app.route('/prepare', methods=['GET','POST'])
def prepare():
    if not username:
        return redirect(url_for('login'))
    if not file_to_download or not operation_speed:
        return redirect(url_for('principal'))
    if request.method == "POST":
        return send_file(file_to_download,as_attachment=True)
    return render_template('prepare.html')

@app.route('/results')
def results():
    print("Holawaaa")
    if not username:
        return redirect(url_for('login'))
    if not file_to_download or not operation_speed:
        return redirect(url_for('principal'))
    return render_template('results.html',speed_value=operation_speed)


# Import keys page
@app.route('/import', methods=['GET','POST'])

def import_key():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    if request.method == "POST":
        #Verify if the attributes are correct added
        key_file= request.files["keyfile"]
        iv_nonce_file= request.files["ivnoncefile"]
        if not key_file or not iv_nonce_file:
            return render_template('import.html', errorMessage="Please choose the key files")
         #Get the algorithm selected by the user
        selected_algorithm=request.form.get('algorithm')
        if not selected_algorithm: #If user does not choose any algorithm
            return render_template('import.html', errorMessage="Please, choose an algorithm to export the keys")
        #Store the key components
        key=key_file.filename
        ivnonce=iv_nonce_file.filename
        key_file.save(key)
        iv_nonce_file.save(ivnonce)
        if isPEMfile(key) and isPEMfile(ivnonce):
            if selected_algorithm=='AES': 
                correct_import=import_AES_keys(username,key,ivnonce) #Import new AES keys for the user
            elif selected_algorithm=='RSA':
                correct_import=import_RSA_keys(username,key,ivnonce) #Import new RSA keys for the user
            elif selected_algorithm=='TripleDES':
                correct_import=import_TripleDES_keys(username,key,ivnonce) #Import TripleDES keys for the user
            elif selected_algorithm=='ChaCha':
                correct_import=import_ChaCha20_keys(username,key,ivnonce) #Import ChaCha keys for the user
            else: #If the algorithm is not correct            #Delete the files from the server
                os.remove(key)
                os.remove(ivnonce)
                return render_template('import.html',  errorMessage="Algorithm unknown, please choose a real algorithm")
            if(correct_import):
                print("Holiwii")
                return redirect(url_for('principal'))
            else:
                return render_template('import.html',  errorMessage="Something went wrong, please try again")
            
        else:
            os.remove(key)
            os.remove(ivnonce)
            return render_template('import.html',  errorMessage="Please, the keys must be.pem")
    return render_template('import.html')

# Export keys page
@app.route('/export', methods=['GET','POST'])

def export_key():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    if request.method == "POST":
        #Get the algorithm selected by the user
        selected_algorithm=request.form.get('algorithm')
        if not selected_algorithm: #If user does not choose any algorithm
            return render_template('export.html',  errorMessage="Please, choose an algorithm to export the keys")
        if selected_algorithm=='AES': 
            export_zip=export_keys(username,1) #Export new AES keys for the user
        elif selected_algorithm=='RSA':
            export_zip=export_keys(username,2) #Export new RSA keys for the user
        elif selected_algorithm=='TripleDES':
            export_zip=export_keys(username,3) #Export TripleDES keys for the user
        elif selected_algorithm=='ChaCha':
            export_zip=export_keys(username,4) #Export ChaCha keys for the user
        else: #If the algorithm is not correct
            return render_template('export.html',  errorMessage="Algorithm unknown, please choose a real algorithm")
        return send_file(export_zip, as_attachment=True)
    return render_template('export.html')

# Create keys page
@app.route('/create', methods=['GET','POST'])

def create_key():
    security_flush()
    speed_flush()
    if not username:
        return redirect(url_for('login'))
    if request.method == "POST":
        #Get the algorithm selected by the user
        selected_algorithm=request.form.get('algorithm')
        if not selected_algorithm: #If user does not choose any algorithm
            return render_template('create.html',  errorMessage="Please, choose an algorithm to create the keys")
        if selected_algorithm=='AES': 
            create_keys(username,1) #Create new AES keys for the user
        elif selected_algorithm=='RSA':
            create_keys(username,2) #Create new RSA keys for the user
        elif selected_algorithm=='TripleDES':
            create_keys(username,3) #Create new TripleDES keys for the user
        elif selected_algorithm=='ChaCha':
            create_keys(username,4) #Create new ChaCha keys for the user
        else: #If the algorithm is not correct
            return render_template('create.html',  errorMessage="Algorithm unknown, please choose a real algorithm")
        return redirect(url_for('principal'))
    return render_template('create.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4270, debug=True, ssl_context=('certificate/cert.pem', 'certificate/key.pem'))