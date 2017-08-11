# NanoCrypt
A fast in-place file encryption tool implemented without 3rd-party libraries 

Copyright (c) 2017 [Tony Wu], All Right Reserved

License: GNU GPL v3.0

Version 0.3

This tool encrypts a specified file in-place, using VMPC-drop3072 AEAD with 256-bit keys. Authentication is provided by HMAC-SHA256 in EtM mode. Key stretching is provided by PBKDF2-HMAC-SHA512 with 2^18 iterations. A 32-byte hmac and a 16-byte random salt is located in the footer of a NanoCrypt file.

If compiled using g++ -O3, speeds exceeding 250 MB/s can be achieved on a ULV Kaby Lake i7 and SSD.

Use NanoCrypt.py (Python3) to use this tool in an interactive manner.

usage: NanoCrypt.py [encrypt | decrypt]

NanoCrypt.py derives keys from user passphrases and generates salts. It automatically invokes NanoCrypt's C++ sub-tools to complete the encryption and decryption process. This is the recommended way to use NanoCrypt.

To use the sub-tools manually, note:

usage: NanoCryptCore file key

"key" must be a hexadecimal string of length 64 (32-bytes/256-bit). Ensure it comes from a properly salted key derivation function.

usage: usage: SaltMaster [add | remove] [salt | hmac] file [salt]

"salt" must be a hexadecimal string of length 32 (16-bytes/128-bit). "hmac" must be a hexadecimal string of length 64 (32-bytes/256-bit)
