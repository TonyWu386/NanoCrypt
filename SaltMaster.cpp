/* 
 * NanoCrypt v0.2
 * 
 * SaltMaster.cpp
 * 
 * A helper to add/remove the salt from the newly encrypted/decrypted file
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
  if ( argc != 3 && argc != 4)
  {
    cerr << "usage: SaltMaster [add | remove] file [salt]" << endl;
    return 1;
  }

  if (strcmp(argv[1], "add") != 0 && strcmp(argv[1], "remove") != 0)
  {
    cerr << "invalid flag: " << argv[1] << endl;
  }

  if (strcmp(argv[1], "add") == 0)
  {
    if (argc != 4)
    {
      cerr << "salt must be provided for adding" << endl;
      return 1;
    }

    if (strlen(argv[3]) != 32)
    {
      cerr << "salt is wrong size: " << strlen(argv[3]) << endl;
      return 1;
    }
  }

  fstream toModify(argv[2], ios::binary|ios::out|ios::in|ios::ate);

  if (toModify.fail())
  {
    cerr << "cannot open file: " << argv[2] << endl;
    return 1;
  }

  char* salt = new char [16];

  long fileSize = toModify.tellg();

  if (strcmp(argv[1], "add") == 0)
  {
    //Convert the salt from a hexstring to a char array
    char *pos = argv[3];
    for(short i = 0; i < 16; i++)
    {
      sscanf(pos, "%2hhx", &salt[i]);
      pos += 2;
    }

    //Append salt to the end of the file
    toModify.seekp(fileSize, ios::beg);
    toModify.write(salt, 16);
  }
  else
  {
    //Get salt from file and output it
    toModify.seekp(fileSize - 16, ios::beg);
    toModify.read(salt, 16);
    stringstream ss;
    for(short i = 0; i < 16; i++)
    {
      ss << setfill('0') << setw(2) << hex << (int)(unsigned char)salt[i];
    }

    //Remove the salt from the end of the file
    if (truncate(argv[2], fileSize - 16) != 0)
    {
      return 1;
    }

    cout << ss.str();
  }

  return 0;
}
