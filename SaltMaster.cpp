/* 
 * NanoCrypt v0.3
 * 
 * SaltMaster.cpp
 * 
 * A helper to add/remove the salt or HMAC from the footer of a NanoCrypt file
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
#include <sstream>
#include <string.h>
#include <iomanip>
#include <unistd.h>

using namespace std;

int main( int argc, char *argv[])
{
  //128-bit
  short SALTSIZE = 16;

  //256-bit
  short HMACSIZE = 32;

  if ( argc != 4 && argc != 5)
  {
    cerr << "usage: SaltMaster [add | remove] [salt | hmac] file [salt]" << endl;
    return 1;
  }

  if (strcmp(argv[1], "add") != 0 && strcmp(argv[1], "remove") != 0)
  {
    cerr << "invalid operation flag: " << argv[1] << endl;
  }

  if (strcmp(argv[2], "salt") != 0 && strcmp(argv[2], "hmac") != 0)
  {
    cerr << "invalid type flag: " << argv[2] << endl;
  }

  short dataSize = ((strcmp(argv[2], "salt") == 0) ? SALTSIZE : HMACSIZE );

  if (strcmp(argv[1], "add") == 0)
  {
    if (argc != 5)
    {
      cerr << "salt/hmac must be provided for adding" << endl;
      return 1;
    }

    if (strlen(argv[4]) != (dataSize * 2))
    {
      cerr << "salt/hmac is wrong size, should be " << (dataSize * 2) << ": " << strlen(argv[4]) << endl;
      return 1;
    }
  }

  fstream toModify(argv[3], ios::binary|ios::out|ios::in|ios::ate);

  if (toModify.fail())
  {
    cerr << "cannot open file: " << argv[3] << endl;
    return 1;
  }

  char* data = new char [dataSize];

  long fileSize = toModify.tellg();

  if (strcmp(argv[1], "add") == 0)
  {
    //Convert the salt/hmac from a hexstring to a char array
    char *pos = argv[4];
    for(short i = 0; i < dataSize; i++)
    {
      sscanf(pos, "%2hhx", &data[i]);
      pos += 2;
    }

    //Append salt/hmac to the end of the file
    toModify.seekp(fileSize, ios::beg);
    toModify.write(data, dataSize);
  }
  else
  {
    //Get salt/hmac from file and output it
    toModify.seekp(fileSize - dataSize, ios::beg);
    toModify.read(data, dataSize);
    stringstream ss;
    for(short i = 0; i < dataSize; i++)
    {
      ss << setfill('0') << setw(2) << hex << (int)(unsigned char)data[i];
    }

    //Remove the salt/hmac from the end of the file
    if (truncate(argv[3], fileSize - dataSize) != 0)
    {
      return 1;
    }

    cout << ss.str();
  }

  return 0;
}
