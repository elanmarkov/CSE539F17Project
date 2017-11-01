#ifndef _AES_FUNC_H_
#define _AES_FUNC_H_

#include "MatLibAES.h"

extern ByteArray* state;
extern const int Nb;

void MixColumns();
void InvMixColumns();
void AddRoundKey(const ByteArray* keys, int round);
void InvAddRoundKey(const ByteArray* keys, int round);

#endif
