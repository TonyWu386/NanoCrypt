#-----------------------------------------------------------------------------
# NanoCrypt v0.2
# 
# NanoCrypt.py
# 
# Repo: https://github.com/TonyWu386/NanoCrypt
# 
# License: GNU GPL v3.0
#
# Copyright (c) 2017 [Tony Wu], All Right Reserved
#-----------------------------------------------------------------------------

from sys import argv
from os import urandom
from hashlib import pbkdf2_hmac
from subprocess import call, Popen, PIPE
from binascii import hexlify

ENFORCEPASSLEN = 8
KDFITER = 262144

if __name__ == "__main__":

    if (len(argv) != 2 or (argv[1] != "encrypt" and argv[1] != "decrypt")):
        print("usage: NanoCrypt.py [encrypt | decrypt]")
        quit()

    encrypt = argv[1] == "encrypt"

    fileName = input("File:")
    passphrase = bytes(input("Passphrase:"), encoding="ascii")

    if (len(passphrase) < ENFORCEPASSLEN):
        print("Passphrase is too short")
        quit()

    if (encrypt):
        salt = bytes(urandom(16))

        key = pbkdf2_hmac("sha512", passphrase, salt, KDFITER, 32)

        returnCode = call(["./NanoCryptCore", fileName, hexlify(key)])
        if (returnCode != 0):
            print("Encryption failed")
            quit()

        print("Encryption successful")

        returnCode = call(["./SaltMaster", "add", fileName, hexlify(salt)])
        if (returnCode != 0):
            print("Salt appending failed")
            quit()

        print("Salt appending successful")

    else:
        process = Popen(["./SaltMaster", "remove", fileName], stdout=PIPE)

        salt = bytes.fromhex(process.communicate()[0].decode("ascii"))

        if (process.returncode != 0):
            print("Error getting salt")
            quit()

        print("Getting salt successful")

        key = pbkdf2_hmac("sha512", passphrase, salt, KDFITER, 32)

        returnCode = call(["./NanoCryptCore", fileName, hexlify(key)])
        if (returnCode != 0):
            print("Decryption failed")
            quit()

        print("Decryption successful")
