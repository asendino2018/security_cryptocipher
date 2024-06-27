import hashlib
import re
from pysqlcipher3 import dbapi2 as sqlite


def get_keys_key():
    with open('database-keys/keys_key.txt', 'r') as key_file:
        key = key_file.read()
    key_file.close()
    return key

def get_user_key():
    with open('database-keys/user_key.txt', 'r') as key_file:
        key = key_file.read()
    key_file.close()
    return key

def insert_AES_keys(username, AES_key, AES_iv):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    nick=get_user_nickname(username)
    cursor = conn.cursor()
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('UPDATE cipher_keys SET AES_key=?, AES_iv=? WHERE username = ?;',(AES_key, AES_iv, nick))
    conn.commit()
    conn.close()

def get_AES_key(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT AES_key from cipher_keys WHERE username = ?;',(nick,))
    AES_key = cursor.fetchone()
    conn.close()
    return AES_key[0]


def get_AES_iv(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT AES_iv from cipher_keys WHERE username = ?;',(nick,))
    AES_iv = cursor.fetchone()
    conn.close()
    return AES_iv[0]

def insert_RSA_keys(username,RSA_public_key,RSA_private_key):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('UPDATE cipher_keys SET RSA_public_key=?, RSA_private_key=? WHERE username = ?;',(RSA_public_key, RSA_private_key, nick))
    conn.commit()
    conn.close()

def get_RSA_public_key(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT RSA_public_key from cipher_keys WHERE username = ?;',(nick,))
    RSA_public_key = cursor.fetchone()
    conn.close()
    return RSA_public_key[0]


def get_RSA_private_key(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT RSA_private_key from cipher_keys WHERE username = ?;',(nick,))
    RSA_private_key = cursor.fetchone()
    conn.close()
    return RSA_private_key[0]

def insert_TripleDES_keys(username, TripleDES_key, TripleDES_iv):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('UPDATE cipher_keys SET TripleDES_key=?, TripleDES_iv=? WHERE username = ?;',(TripleDES_key, TripleDES_iv, nick))
    conn.commit()
    conn.close()

def get_TripleDES_key(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT TripleDES_key from cipher_keys WHERE username = ?;',(nick,))
    TripleDES_key = cursor.fetchone()
    conn.close()
    return TripleDES_key[0]


def get_TripleDES_iv(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT TripleDES_iv from cipher_keys WHERE username = ?;',(nick,))
    TripleDES_iv = cursor.fetchone()
    conn.close()
    return TripleDES_iv[0]

def insert_ChaCha20_keys(username, ChaCha20_key, ChaCha20_nonce):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('UPDATE cipher_keys SET ChaCha20_key=?, ChaCha20_nonce=? WHERE username = ?;',(ChaCha20_key, ChaCha20_nonce, nick))
    conn.commit()
    conn.close()

def get_ChaCha20_key(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT ChaCha20_key from cipher_keys WHERE username = ?;',(nick,))
    ChaCha20_key = cursor.fetchone()
    conn.close()
    return ChaCha20_key[0]


def get_ChaCha20_nonce(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    nick=get_user_nickname(username)
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('SELECT ChaCha20_nonce from cipher_keys WHERE username = ?;',(nick,))
    ChaCha20_nonce = cursor.fetchone()
    conn.close()
    return ChaCha20_nonce[0]

def exists_username(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_users.db')
    cursor = conn.cursor()
    user_key=get_user_key()
    cursor.execute(f"PRAGMA key = '{user_key}';")
    username_hashed = hashlib.sha256(username.encode('utf-8')).hexdigest()
    cursor.execute('SELECT COUNT(*) FROM cipher_users WHERE username =?;',(username_hashed,))
    result = cursor.fetchone()
    conn.close()
    return result[0] > 0

def exists_nickname(nickname):
    conn = sqlite.connect('cryptocipher-databases/cipher_users.db')
    cursor = conn.cursor()
    user_key=get_user_key()
    cursor.execute(f"PRAGMA key = '{user_key}';")
    nickname_hashed = hashlib.sha256(nickname.encode('utf-8')).hexdigest()
    cursor.execute('SELECT COUNT(*) FROM cipher_users WHERE nickname =?;',(nickname_hashed,))
    result = cursor.fetchone()
    conn.close()
    return result[0] > 0

def verify_credentials(username, password):
    conn = sqlite.connect('cryptocipher-databases/cipher_users.db')
    cursor = conn.cursor()
    user_key=get_user_key()
    cursor.execute(f"PRAGMA key = '{user_key}';")
    username_hashed = hashlib.sha256(username.encode('utf-8')).hexdigest()
    password_hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
    cursor.execute('SELECT COUNT(*) FROM cipher_users WHERE username = ? AND password = ?;',(username_hashed,password_hashed))
    result = cursor.fetchone()
    conn.close()
    return result[0] > 0


def get_user_nickname(username):
    conn = sqlite.connect('cryptocipher-databases/cipher_users.db')
    cursor = conn.cursor()
    user_key=get_user_key()
    cursor.execute(f"PRAGMA key = '{user_key}';")
    username_hashed = hashlib.sha256(username.encode('utf-8')).hexdigest()
    cursor.execute('SELECT nickname from cipher_users WHERE username = ?;',(username_hashed,))
    nickname = cursor.fetchone()
    conn.close()
    return nickname[0]

def insert_user(username, password, nickname):
    conn = sqlite.connect('cryptocipher-databases/cipher_users.db')
    cursor = conn.cursor()
    user_key=get_user_key()
    cursor.execute(f"PRAGMA key = '{user_key}';")
    username_hashed = hashlib.sha256(username.encode('utf-8')).hexdigest()
    password_hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
    nickname_hashed = hashlib.sha256(nickname.encode('utf-8')).hexdigest()
    cursor.execute('INSERT INTO cipher_users (username,password,nickname) VALUES (?,?,?);',(username_hashed,password_hashed,nickname_hashed))
    conn.commit()
    conn.close()
    
    conn = sqlite.connect('cryptocipher-databases/cipher_keys.db')
    cursor = conn.cursor()
    keys_key=get_keys_key()
    cursor.execute(f"PRAGMA key = '{keys_key}';")
    cursor.execute('INSERT INTO cipher_keys (username) VALUES (?);',(nickname_hashed,))
    conn.commit()
    conn.close()
    

def is_strong_password(password):
        # Check if the password is at least 8 characters long
    if len(password) < 8:
        return False

    # Check if the password contains at least one uppercase letter
    if not any(char.isupper() for char in password):
        return False

    # Check if the password contains at least one lowercase letter
    if not any(char.islower() for char in password):
        return False

    # Check if the password contains at least one digit
    if not any(char.isdigit() for char in password):
        return False
    
    # Check for at least one special character using a regular expression
    special_char_pattern = r'[!@#$%^&*(),.?":{}|<>]'
    if not re.search(special_char_pattern, password):
        return False
    # Check if the password passes any additional criteria here (if needed)

    # If all criteria are met, the password is strong
    return True
    