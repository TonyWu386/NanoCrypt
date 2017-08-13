#-----------------------------------------------------------------------------
# NanoCrypt v0.4
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
import hmac

ENFORCEPASSLEN = 8
KDFITER = 262144
BUFFERSIZE = 4096

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

        key = pbkdf2_hmac("sha512", passphrase, salt, KDFITER, 64)

        returnCode = call(["./NanoCryptCore", fileName, hexlify(key[0:32]),
                           hexlify(key[32:64])])
        if (returnCode != 0):
            print("Encryption failed")
            quit()
        print("Encryption successful")

        print("Generating HMAC, stand by")

        hmacGenerator = hmac.new(key, digestmod="sha256")
        f = open(fileName, 'rb')

        try:
          while True:
            buf = f.read(BUFFERSIZE)
            if not buf:
              break
            hmacGenerator.update(buf)
        finally:
          f.close()

        returnCode = call(["./SaltMaster", "add", "hmac", fileName,
                           hmacGenerator.hexdigest()])
        if (returnCode != 0):
            print("HMAC appending failed")
            quit()
        print("HMAC appending successful")

        returnCode = call(["./SaltMaster", "add", "salt", fileName,
                           hexlify(salt)])
        if (returnCode != 0):
            print("Salt appending failed")
            quit()
        print("Salt appending successful")
    else:
        process = Popen(["./SaltMaster", "remove", "salt", fileName],
                        stdout=PIPE)
        salt = bytes.fromhex(process.communicate()[0].decode("ascii"))
        if (process.returncode != 0):
            print("Error getting salt")
            quit()
        print("Getting salt successful")

        process = Popen(["./SaltMaster", "remove", "hmac", fileName],
                        stdout=PIPE)
        fileHmac = process.communicate()[0].decode("ascii")  
        if (process.returncode != 0):
            print("Error getting HMAC")
            quit()
        print("Getting HMAC successful")

        key = pbkdf2_hmac("sha512", passphrase, salt, KDFITER, 64)

        print("Checking HMAC, stand by")

        hmacGenerator = hmac.new(key, digestmod="sha256")
        f = open(fileName, 'rb')

        try:
          while True:
            buf = f.read(BUFFERSIZE)
            if not buf:
              break
            hmacGenerator.update(buf)
        finally:
          f.close()

        if not (hmac.compare_digest(hmacGenerator.hexdigest(), fileHmac)):
            print("!WARNING HMAC does not match!")
        else:
            print("HMAC appears good")

        returnCode = call(["./NanoCryptCore", fileName, hexlify(key[0:32]),
                           hexlify(key[32:64])])
        if (returnCode != 0):
            print("Decryption failed")
            quit()

        print("Decryption successful")
