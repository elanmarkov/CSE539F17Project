#include "MatLibAES.h"
#include <stdint.h>
#include <stdlib.h>
#include <iostream>

void keyExpansion(ByteArray key, Word* wordArray, int Nk, int words);
Word subWord(Word input);
Word rotWord(Word input);
Word rcon(int val);
extern const uint8_t SBOX[16][16];
