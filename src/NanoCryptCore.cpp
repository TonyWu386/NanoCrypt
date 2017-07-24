/* 
 * NanoCrypt v0.3
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

class CryptoCore
{
  private:
  array<unsigned char, 256> ksa(unsigned char * key);
  array<unsigned char, 256> mS;
  short mi;
  short mj;

  public:
  unsigned char nextByte();

  CryptoCore(unsigned char * key)
  {
    mi = 0;
    mj = 0;
    mS = ksa(key);
  }
};

//Sets the internal state from the key provided as a char array of length 32
array<unsigned char, 256> CryptoCore::ksa(unsigned char * key)
{
  array<unsigned char, 256> S;

  for (short i = 0; i < 256; i++)
  {
    S[i] = i;
  }

  short j = 0;
  for (short i = 0; i < 256; i++)
  {
    j = (j + S[i] + key[i % 32]) % 256;
    swap(S[i], S[j]);
  }

  return S;
}


//Cycles the PRGA one round and returns the next keystream byte
unsigned char CryptoCore::nextByte()
{
  mi = (mi + 1) % 256;
  mj = (mj + mS[mi]) % 256;

  swap(mS[mi], mS[mj]);

  return mS[(mS[mi] + mS[mj]) % 256];
}


int main( int argc, char *argv[])
{
  int bufferSize = 4096;

  if ( argc != 3)
  {
    cerr << "usage: NanoCryptCore file key" << endl;
    return 1;
  }

  if (strlen(argv[2]) != 64)
  {
    cerr << "key is wrong size: " << strlen(argv[2]) << endl;
    return 1;
  }

  fstream toEncrypt(argv[1], ios::binary|ios::out|ios::in|ios::ate);

  if (toEncrypt.fail())
  {
    cerr << "cannot open file: " << argv[1] << endl;
    return 1;
  }

  unsigned char key[32];

  //Convert the key from a hexstring to a char array
  char *pos = argv[2];
  for(short i = 0; i < 32; i++)
  {
    sscanf(pos, "%2hhx", &key[i]);
    pos += 2;
  }

  CryptoCore core = CryptoCore(key);

  //Drop the first 3072-bytes to prevent FMS attacks
  for (short i = 0; i < 3072; i++)
  {
    core.nextByte();
  }

  //Start encrypting file  
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

    //Handles the last partial buffer
    if ((fileSize - marker) < bufferSize)
    {
      bufferSize = fileSize - marker;
      buffer = new char [bufferSize];
    }
  }

  return 0;
}
