/* 
 * NanoCrypt v0.4
 * 
 * NanoCryptCore.cpp
 * 
 * Core cryptography and file manipulation
 * 
 * Repo: https://github.com/TonyWu386/NanoCrypt
 * 
 * License: GNU GPL v3.0
 * 
 * Copyright (c) 2017 [Tony Wu], All Right Reserved
 */

#include <iostream>
#include <fstream>
#include <array>
#include <string.h>

using namespace std;


// This class implements the VMPC stream cipher
class CryptoCore
{
  private:
    array<unsigned char, 256> ksa(unsigned char * key, unsigned char * iv, short keyLength, short ivLength);
    array<unsigned char, 256> mS;
    short mi;
    short mj;
    unsigned char mHold;

  public:
    unsigned char nextByte();

    CryptoCore(unsigned char * key, unsigned char * iv, short keyLength, short ivLength)
    {
      mi = 0;
      mj = 0;
      mS = ksa(key, iv, keyLength, ivLength);
    }
};


/**
 * Sets the internal VMPC state array from a key and iv.
 * 
 * @param key A key between 16 and 64 bytes
 * @param iv An iv between 16 and 64 bytes
 * @param keyLength The number of bytes in the key
 * @param ivLength The number of bytes in the iv
 * @return The initialized state array
 */
array<unsigned char, 256> CryptoCore::ksa(unsigned char * key, unsigned char * iv, short keyLength, short ivLength)
{
  array<unsigned char, 256> S;

  for (short i = 0; i < 256; i++)
  {
    S[i] = i;
  }

  short n;

  for (short m = 0; m < 768; m++)
  {
    n = m % 256;
    mj = S[(mj + S[n] + key[m % keyLength]) % 256];
    swap(S[n], S[mj]);
  }
  
  for (short m = 0; m < 768; m++)
  {
    n = m % 256;
    mj = S[(mj + S[n] + iv[m % ivLength]) % 256];
    swap(S[n], S[mj]);
  }

  return S;
}


/**
 * Cycles the PRGA one round and returns the next keystream byte.
 * 
 * @return The next byte in the keystream
 */
unsigned char CryptoCore::nextByte()
{
  mj = mS[(mj + mS[mi]) % 256];
  
  mHold = mS[(mS[mS[mj]] + 1) % 256];

  swap(mS[mi], mS[mj]);
  
  mi = (mi + 1) % 256;

  return mHold;
}


/**
 * Transforms a hexadecimal string to a char array
 * 
 * @param hexPos A pointer to the hexadecimal string
 * @param outArr A pointer to the output array that will be mutated by this function
 * @param outArrLength Expected number of chars in the output
 */
void hexStringToCharArray(char *hexPos, unsigned char *outArr, short outArrLength)
{
  for(short i = 0; i < outArrLength; i++)
  {
    sscanf(hexPos, "%2hhx", &outArr[i]);
    hexPos += 2;
  }
}


int main( int argc, char *argv[])
{
  int bufferSize = 4096;
  short keyLength;
  short ivLength;

  // Validate parameters
  if ( argc != 4)
  {
    cerr << "usage: NanoCryptCore file key iv" << endl;
    return 1;
  }
  
  // Length is in bytes
  keyLength = (short)strlen(argv[2]) / 2;
  ivLength = (short)strlen(argv[3]) / 2;

  if (keyLength < 16 || keyLength > 64)
  {
    cerr << "key is invalid number of bytes: " << keyLength << endl;
    return 1;
  }
  
  if (ivLength < 16 || ivLength > 64)
  {
    cerr << "iv is invalid number of bytes: " << ivLength << endl;
    return 1;
  }

  fstream toEncrypt(argv[1], ios::binary|ios::out|ios::in|ios::ate);

  if (toEncrypt.fail())
  {
    cerr << "cannot open file: " << argv[1] << endl;
    return 1;
  }

  unsigned char key[keyLength];
  unsigned char iv[ivLength];

  // Convert the key and iv from a hexstring to a char array  
  hexStringToCharArray(argv[2], key, keyLength);
  hexStringToCharArray(argv[3], iv, ivLength);

  CryptoCore core = CryptoCore(key, iv, keyLength, ivLength);

  // Drop the first 3072-bytes to prevent FMS attacks
  for (short i = 0; i < 3072; i++)
  {
    core.nextByte();
  }

  // Start encrypting file  
  long fileSize = toEncrypt.tellg();
  int marker = 0;
  char* buffer = new char [bufferSize];

  while (marker < fileSize)
  {
    toEncrypt.seekp(marker, ios::beg);
    toEncrypt.read(buffer, bufferSize);

    for (int i = 0; i < bufferSize; i++)
    {
      buffer[i] = buffer[i] ^ core.nextByte();
    }

    toEncrypt.seekp(marker, ios::beg);
    toEncrypt.write(buffer, bufferSize);

    marker += bufferSize;

    // Handles the last partial buffer
    if ((fileSize - marker) < bufferSize)
    {
      bufferSize = fileSize - marker;
      buffer = new char [bufferSize];
    }
  }

  return 0;
}
