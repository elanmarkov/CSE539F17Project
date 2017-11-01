#include "KeyExpansion.h"

void keyExpansion(ByteArray key, Word* wordArray, int Nk, int words) {
    Word temp = Word();
    for(int i = 0; i < Nk; i++) {
        wordArray[i] = Word(key.byteArray[0][4*i].byte, key.byteArray[0][4*i+1].byte, key.byteArray[0][4*i+2].byte, key.byteArray[0][4*i+3].byte);
    }
    for(int i = Nk; i < words; i++) {
        temp = wordArray[i-1];
        if(i % Nk == 0) {
            temp = subWord(rotWord(temp)) ^ rcon(i/Nk);
        }
        else if (Nk > 6 && (i % Nk) == 4) {
            temp = subWord(temp);
        }
        wordArray[i] = wordArray[i-Nk] ^ temp;
    }
}

Word subWord(Word input) {
    uint8_t word1 = input.word >> 24;
    uint8_t word2 = input.word >> 16;
    uint8_t word3 = input.word >> 8;
    uint8_t word4 = input.word;
    uint8_t word1_upper = word1 & 0xf0;
    uint8_t word1_lower = word1 & 0x0f;
    uint8_t word2_upper = word2 & 0xf0;
    uint8_t word2_lower = word2 & 0x0f;
    uint8_t word3_upper = word3 & 0xf0;
    uint8_t word3_lower = word3 & 0x0f;
    uint8_t word4_upper = word4 & 0xf0;
    uint8_t word4_lower = word4 & 0x0f;
    word1_upper = word1_upper >> 4;
    word2_upper = word2_upper >> 4;
    word3_upper = word3_upper >> 4;
    word4_upper = word4_upper >> 4;
    word1 = SBOX[word1_upper][word1_lower];
    word2 = SBOX[word2_upper][word2_lower];
    word3 = SBOX[word3_upper][word3_lower];
    word4 = SBOX[word4_upper][word4_lower];
    return Word(word1, word2, word3, word4);
}

Word rotWord(Word input) {
    uint8_t lowest = input.word >> 24;
    Word retWord = Word(input.word);
    retWord.word = retWord.word << 8;
    retWord.word = retWord.word + lowest;
    return retWord;
}

Word rcon(int val) {
    Byte maxBit(0x01);
    Byte multVal(0x02);
    for(int i = 0; i < val - 1; i++) {
        maxBit = maxBit * multVal;
    }
    return Word(maxBit.byte, 0x00, 0x00, 0x00);
}
