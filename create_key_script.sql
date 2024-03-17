PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE cipher_keys 
                    (username TEXT PRIMARY KEY NOT NULL UNIQUE,
                    AES_key TEXT,
                    AES_iv TEXT,
                    RSA_public_key TEXT,
                    RSA_private_key TEXT,
                    TripleDES_key TEXT,
                    TripleDES_iv TEXT,
                    ChaCha20_key TEXT,
                    ChaCha20_nonce TEXT
                    );
INSERT INTO cipher_keys VALUES('25ef0038628c1b49788726df52baf087aeb16b6cbaea058511b8ce7790a96358',X'554de4f47e8fea113b6f0cb68760841bd3fb8eaf4e5338e0beb6f6a8f743ad2f',X'f5a6740edb78162a84fbd1039749e137',NULL,NULL,NULL,NULL,NULL,NULL);
COMMIT;
