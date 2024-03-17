import sqlite3
import hashlib
import os
# Connect to the database

def hash256(data):
        # Convert the data string to bytes
    data_bytes = data.encode('utf-8')

    # Create a new SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the data
    sha256_hash.update(data_bytes)

    # Get the hexadecimal representation of the hash
    hash_result = sha256_hash.hexdigest()

    return hash_result
    
if __name__ == "__main__":

    first_key = os.urandom(32)
    print(first_key)
    second_key= os.urandom(32)
    print(second_key)
    conn = sqlite3.connect('users.db')

    cursor = conn.cursor()

    # Create a table in the database
    cursor.execute('''CREATE TABLE cipher_users
                    (username TEXT PRIMARY KEY NOT NULL,
                    password TEXT NOT NULL, 
                    nick TEXT NOT NULL,
                    UNIQUE(username, nick)
                    );''')

    cursor.execute('''PRAGMA foreign_keys=ON''')

    username=hash256("al.sendino")
    password=hash256("aragones123")
    nick=hash256("Rauru")


    cursor.execute('INSERT INTO cipher_users (username, password, nick) VALUES (?,?,?);',(username,password,nick))

    conn.commit()

    conn = sqlite3.connect('keys.db')

    cursor = conn.cursor()

    # Create a table in the database
    cursor.execute('''CREATE TABLE cipher_keys 
                    (username TEXT PRIMARY KEY NOT NULL UNIQUE,
                    AES_key TEXT,
                    AES_iv TEXT,
                    RSA_public_key TEXT,
                    RSA_private_key TEXT,
                    TripleDES_key TEXT,
                    TripleDES_iv TEXT,
                    ChaCha20_key TEXT,
                    ChaCha20_nonce TEXT
                    );''')

    cursor.execute('''PRAGMA foreign_keys=ON''')

    cursor.execute('INSERT INTO cipher_keys (username) VALUES (?);',(nick,))

    conn.commit()