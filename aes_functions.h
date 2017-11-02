#ifndef _AES_FUNC_H_
#define _AES_FUNC_H_

#include "MatLibAES.h"

extern const int Nb;
extern const uint8_t SBOX[16][16];
extern const uint8_t INVSBOX[16][16];

void MixColumns(ByteArray* state);
void InvMixColumns(ByteArray* state);

void AddRoundKey(ByteArray* state, ByteArray* keys, int round);
void InvAddRoundKey(ByteArray* state, ByteArray* keys, int round);

void SubBytes(ByteArray* state);
void InvSubBytes(ByteArray* state);

void ShiftRows(ByteArray* state);
void InvShiftRows(ByteArray* state);

void keyExpansion(ByteArray key, ByteArray &expandedKey, int Nk, int words);
Word subWord(Word input);
Word rotWord(Word input);
Word rcon(int val);

#endif
