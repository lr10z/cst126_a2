
//
// CST 126 - Assignment #2
//
// Leander Rodriguez
//
// File: caesar.cpp
//
// Encryption and decryption routines for the caesar
// algorithm.
//


#include  <string.h>
#include  <math.h>
#include  "algorithms.h"


//
// Convert the key value to number within the range
// of valid characters.
//
static int  normalizeKey( int  origKey )
{
  int  normKey  =  abs(origKey);

  normKey  %=  NUM_CHARACTERS;

  if  (origKey < 0)
    normKey  =  NUM_CHARACTERS - normKey;

  return  normKey;
}


//
// Encryption
//
void  caesarEncrypt( const char  src[], char  dest[], int  key )
{
  key  =  normalizeKey(key);

  size_t  len  =  strlen(src);

  size_t  idx;

  //
  // Process each character
  //
  for( idx=0;  idx < len;  ++idx )
  {
    //
    // Out of range characters are just transfered to
    // the ciphertext
    //
    if  ( CHAR_OUT_OF_RANGE( src[idx] ) )
    {
      dest[idx]  =  src[idx];
      continue;
    }


    //
    // Determine the alphabet index of the plaintext character
    //
    char  c  =  src[idx] - MIN_ASCII_VALUE;


    //
    // Add the key to the alphabet index to get the ciphertext
    // character. Handle the wrap-around past the last valid
    // character.
    //
    c  +=  key % NUM_CHARACTERS;
    c  %=  NUM_CHARACTERS;

    dest[idx]  =  c + MIN_ASCII_VALUE;
  }

  dest[idx] = 0;
}


//
// Decryption
//
void  caesarDecrypt( const char  src[], char  dest[], int  key )
{
  //
  // Decryption is accomplished with encryption using a negated key.
  //

  caesarEncrypt( src, dest, -key );
}
