PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE cipher_users
                    (username TEXT PRIMARY KEY NOT NULL,
                    password TEXT NOT NULL, 
                    nickname TEXT NOT NULL,
                    UNIQUE(username, nickname)
                    );
INSERT INTO cipher_users VALUES('2e3388e3cb7c696bc3ba4efe1c8c1edf5b705f91cd19400a6c2cbe4c461f9015','e6994e3e34d6e88376c68859c261ff1e4f8d4d5f96a92eaa9de4bfdc727937eb','25ef0038628c1b49788726df52baf087aeb16b6cbaea058511b8ce7790a96358');
COMMIT;
al.sendino, Tidus1234~, Rauru


