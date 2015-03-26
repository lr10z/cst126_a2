
//
// CST 126 - Assignment #2
//
// Leander Rodriguez
//
// File: vigenere.cpp
//
// Encryption and decryption routines for the vigenere
// algorithm.
//

#include  <string.h>
#include  <math.h>
#include  "algorithms.h"


#define  NOT_FOUND  (-1)


//
// Encryption
//
void  vigenereEncrypt( const char  src[], char  dest[], const char  key[] )
{
  int  keyIdx  =  0;  // index into key string

  size_t  srcIdx;


  //
  // Process each character
  //
  for( srcIdx = 0;  srcIdx < strlen(src);  ++srcIdx, ++keyIdx )
  {
    //
    // Handle running out of characters in the index string
    //
    if  ( ! key[keyIdx] )
      keyIdx = 0;


    //
    // Skip out of range characters
    //
    if  ( CHAR_OUT_OF_RANGE(src[srcIdx]) )
    {
      dest[srcIdx]  =  src[srcIdx];
      continue;
    }


    //
    // Determine the ascii offset value of the key character
    //
    int  asciiOffset  =  key[keyIdx] - MIN_ASCII_VALUE;


    //
    // Add the ascii offset to the plaintext value to determine
    // the cipher character
    //
    int  newChar  =  src[srcIdx] + asciiOffset;


    //
    // Handle wrap-around of the cipher character if needed
    //
    if  (newChar > MAX_ASCII_VALUE)
      newChar  =  MIN_ASCII_VALUE + (newChar - MAX_ASCII_VALUE - 1);

    dest[srcIdx]  =  newChar;
  }

  dest[srcIdx]  =  0;
}


//
// Decryption
//
void  vigenereDecrypt( const char  src[], char  dest[], const char  key[] )
{
  int  keyIdx  =  0;

  size_t  srcIdx;


  //
  // Process each character
  //
  for( srcIdx = 0;  srcIdx < strlen(src);  ++srcIdx, ++keyIdx )
  {
    //
    // Handle running out of characters in the index string
    //
    if  ( ! key[keyIdx] )
      keyIdx = 0;


    //
    // Skip out of range characters
    //
    if  ( CHAR_OUT_OF_RANGE(src[srcIdx]) )
    {
      dest[srcIdx]  =  src[srcIdx];
      continue;
    }


    //
    // Determine the ascii offset value from the cipher
    // character and the key character
    //
    int  asciiOffset  =  src[srcIdx] - key[keyIdx];


    //
    // Convert the ascii offset to a plaintext character
    //
    char  newChar  =  MIN_ASCII_VALUE + asciiOffset;


    //
    // Handle wrap-around of the plaintext character if needed
    //
    if  ( asciiOffset < 0 )
      newChar  +=  NUM_CHARACTERS;

    dest[srcIdx]  =  newChar;
  }

  dest[srcIdx]  =  0;
}
