

//
// CST 126 - Assignment #2
//
// Leander Rodriguez
//
// File: transposition.cpp
//
// Encryption and decryption routines for the transposition
// algorithm.
//


#define  _CRT_SECURE_NO_DEPRECATE
  //
  // This define is needed to eliminate Microsoft compiler
  // warnings about deprecated functions


#include  <string.h>
#include  <math.h>
#include  <stdlib.h>
#include  <iostream>
#include  "algorithms.h"


using  namespace  std;


#define  PAD_CHAR  "z"


//
// Function to add pad characters to the end of
// a string.
//
static void  addPad( char  *str, int  numPadChars )
{
  for( int  i=0;  i < numPadChars;  ++i )
  {
    strcat( str, PAD_CHAR );
  }
}


//
// Function to strip pad characters from the end
// of a string.
//
static void  stripPad( char  *str )
{
  size_t  idx;

  for( idx = strlen(str) - 1;  str[idx] == PAD_CHAR[0];  --idx )
    ;

  str[idx+1]  =  0;
}


//
// Encryption
//
void  transpositionEncrypt( const char  src[], char  dest[], unsigned  key )
{
  char  paddedSrc[MAX_MSG_SIZE];

  //
  // Make a copy of the plaintext string so we can modify it if needed
  //

  size_t  len  =  strlen(src);

  strcpy( paddedSrc, src );


  //
  // Added pad characters if necessary so that the string length is
  // an even multiple of the key.
  //
  if  (len % key)
    addPad( paddedSrc, key - len % key );


  //
  // Determine the length of the string and the number
  // of transposition rows.
  //
  len  =  strlen(paddedSrc);


  unsigned  numRows  =  key;
  unsigned  row = 0;
  unsigned  col = 0;
  unsigned  idx;

  //
  // Process each character
  //
  for( idx=0;  idx < len;  ++idx )
  {
    //
    // Places the plaintext character in the
    // ciphertext position based on the row/col
    // values calculated from the plaintext index.
    //


    dest[idx]  =  paddedSrc[ key * row + col ];


    //
    // Advanced to the next row, or move to the top of
    // the next column if there are no more rows.

    if  (++row == len/key)
    {
      row = 0;
      col++;
    }
  }


  //
  // Put a zero-terminator on the send of the encrypted message
  //
  dest[idx]  =  0;
}


//
// Decryption
//
void  transpositionDecrypt( const char  src[], char  dest[], unsigned key )
{
  size_t  len  =  strlen(src);

  //
  // Note, for the transposition algorithm, it is illegal to have
  // a ciphertext string whose length is not an even multiple of
  // the key.
  //

  if  ( len % key )
  {
    cout  <<  "Invalid src string to decrypt"  <<  endl;
    exit(EXIT_FAILURE);
  }

  //
  // Transposition decryption is just encryption with
  // a key value equal to the number of transposition rows.
  // So, we'll just use the encryption algorithm to decrypt.
  //

  transpositionEncrypt( src, dest, (unsigned) strlen(src) / key );


  //
  // Strip any trailing pad characters that are in the
  // resulting plaintext string.
  //
  stripPad( dest );
}
