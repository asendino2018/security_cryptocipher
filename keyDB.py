import sqlite3

# Connect to the database
conn = sqlite3.connect('keys.db')

cursor = conn.cursor()

# Create a table in the database
cursor.execute('''CREATE TABLE cipher_keys 
                (username TEXT PRIMARY KEY UNIQUE,
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

cursor.execute('''INSERT INTO cipher_keys (username) VALUES ("25ef0038628c1b49788726df52baf087aeb16b6cbaea058511b8ce7790a96358");''')

conn.commit()