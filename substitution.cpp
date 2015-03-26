
//
// CST 126 - Assignment #2
//
// Leander Rodriguez
//
// File: substitution.cpp
//
// Encryption and decryption routines for the substitution
// algorithm.
//


#include  <string.h>
#include  <math.h>
#include  "algorithms.h"


#define  NOT_FOUND  (-1)


//
// Returns the index of the first occurance of a character
// within a string. Returns NOT_FOUND if the character is
// not in the string.
//
static int  findIndexOf( const char  str[], char  c )
{
  for( unsigned  idx = 0;  idx < strlen(str);  ++idx )
  {
    if  (str[idx] == c)  return  idx;
  }

  return  NOT_FOUND;
}


//
// Encryption
//
void  substitutionEncrypt( const char  src[], char  dest[], const char  key[] )
{
  size_t  srcIdx;


  //
  // Process each character
  //
  for( srcIdx = 0;  srcIdx < strlen(src);  ++srcIdx )
  {
    //
    // If the plaintext character is in range, then the plaintext
    // character number as the index into the key string to find
    // the cipher character. Otherwise, the ciphertext character
    // is the plaintext character.
    //
    if  ( ! CHAR_OUT_OF_RANGE( src[srcIdx] ) )
    {
      //
      // Determine the character number of the plaintext character
      //
      int  keyIdx  =  src[srcIdx] - MIN_ASCII_VALUE;

      dest[srcIdx]  =  key[keyIdx];
    }
    else
    {
      dest[srcIdx]  =  src[srcIdx];
    }
  }

  dest[srcIdx]  =  0;
}


//
// Decryption
//
void  substitutionDecrypt( const char  src[], char  dest[], const char  key[] )
{
  size_t  srcIdx;


  //
  // Process each character
  //
  for( srcIdx = 0;  srcIdx < strlen(src);  ++srcIdx )
  {
    //
    // Determine the index of the ciphertext character within the
    // key
    //
    int  keyIdx  =  findIndexOf( key, src[srcIdx] );


    //
    // If the key index was not found, the plaintext character is
    // the ciphertext character. Otherwise, use the key index
    // as the alphabet offset to determine the plaintext character.
    //
    if  ( keyIdx == NOT_FOUND )
      dest[srcIdx]  =  src[srcIdx];
    else
      dest[srcIdx]  =  MIN_ASCII_VALUE + keyIdx;
  }

  dest[srcIdx]  =  0;
}
