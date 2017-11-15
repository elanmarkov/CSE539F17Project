#include "aes_functions.h"

//#include "MatLibAES.h"

void MixColumns(ByteArray* state) {
	Byte o1(0x01);
	Byte o2(0x02);
	Byte o3(0x03);

    Byte tmp1, tmp2, tmp3, tmp4;
	for(int i = 0; i < Nb; ++i) {
		tmp1 =	(o2 * state->byteArray[0][i]) + \
									(o3 * state->byteArray[1][i]) + \
									state->byteArray[2][i] + \
									state->byteArray[3][i];

		tmp2 =	state->byteArray[0][i] + \
									(o2 * state->byteArray[1][i]) + \
									(o3 * state->byteArray[2][i]) + \
									state->byteArray[3][i];

		tmp3 =	state->byteArray[0][i] + \
									state->byteArray[1][i] + \
									(o2 * state->byteArray[2][i]) + \
									(o3 * state->byteArray[3][i]);

		tmp4 =	(o3 * state->byteArray[0][i]) + \
									state->byteArray[1][i] + \
									state->byteArray[2][i] + \
									(o2 * state->byteArray[3][i]);

        state->byteArray[0][i] = tmp1;
        state->byteArray[1][i] = tmp2;
        state->byteArray[2][i] = tmp3;
        state->byteArray[3][i] = tmp4;
	}
}

void InvMixColumns(ByteArray* state) {
	Byte o9(0x09);
	Byte ob(0x0b);
	Byte od(0x0d);
	Byte oe(0x0e);

    Byte tmp1, tmp2, tmp3, tmp4;
	for(int i = 0; i < Nb; ++i) {
		tmp1 =	(oe * state->byteArray[0][i]) + \
									(ob * state->byteArray[1][i]) + \
									(od * state->byteArray[2][i]) + \
									(o9 * state->byteArray[3][i]);

		tmp2 =	(o9 * state->byteArray[0][i]) + \
									(oe * state->byteArray[1][i]) + \
									(ob * state->byteArray[2][i]) + \
									(od * state->byteArray[3][i]);

		tmp3 =	(od * state->byteArray[0][i]) + \
									(o9 * state->byteArray[1][i]) + \
									(oe * state->byteArray[2][i]) + \
									(ob * state->byteArray[3][i]);

		tmp4 =	(ob * state->byteArray[0][i]) + \
									(od * state->byteArray[1][i]) + \
									(o9 * state->byteArray[2][i]) + \
									(oe * state->byteArray[3][i]);

        state->byteArray[0][i] = tmp1;
        state->byteArray[1][i] = tmp2;
        state->byteArray[2][i] = tmp3;
        state->byteArray[3][i] = tmp4;
	}
}

void AddRoundKey(ByteArray* state, ByteArray* keys, int round) {
	for (int i = 0; i < Nb; ++i) {
        state->byteArray[0][i] = state->byteArray[0][i] + keys->byteArray[0][round*4 + i];
		state->byteArray[1][i] = state->byteArray[1][i] + keys->byteArray[1][round*4 + i];
		state->byteArray[2][i] = state->byteArray[2][i] + keys->byteArray[2][round*4 + i];
		state->byteArray[3][i] = state->byteArray[3][i] + keys->byteArray[3][round*4 + i];
	}
}

void InvAddRoundKey(ByteArray* state, ByteArray* keys, int round) {
	AddRoundKey(state, keys, round);
}


void SubBytes(ByteArray* state)
{
	uint8_t low;
	uint8_t hi;

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			low = state->byteArray[i][j].byte & 0x0f;
			hi = (state->byteArray[i][j].byte & 0xf0) >> 4;

			state->byteArray[i][j] = Byte(SBOX[hi][low]);
		}
	}
}

void InvSubBytes(ByteArray* state)
{

	uint8_t low;
	uint8_t hi;

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			low = state->byteArray[i][j].byte & 0x0f;
			hi = (state->byteArray[i][j].byte & 0xf0) >> 4;

			state->byteArray[i][j] = Byte(INVSBOX[hi][low]);
		}
	}
}

void ShiftRows(ByteArray* state)
{
	for (int i = 1; i < 4; i++)
	{

		Byte iRow[] = {state->byteArray[i][0], state->byteArray[i][1], state->byteArray[i][2], state->byteArray[i][3]};

		for (int j = 0; j < 4; j++)
		{
			state->byteArray[i][j] = iRow[modulo(j+i, 4)];
		}
	}
}

void InvShiftRows(ByteArray* state)
{
	for (int i = 1; i < 4; i++)
	{

		Byte iRow[] = {state->byteArray[i][0], state->byteArray[i][1], state->byteArray[i][2], state->byteArray[i][3]};

		for (int j = 0; j < 4; j++)
		{
			state->byteArray[i][j] = iRow[modulo(j-i, 4)];
		}
	}
}

void keyExpansion(ByteArray key, ByteArray &expandedKey, int Nk, int words) {
// Implementation of AES NIST standard document key expansion
// words is the value Nb*(Nr+1) that gives the size of wordArray
    Word temp = Word();
    Word wordArray[words];

// Load key into first Nk words of the wordArray
    for(int i = 0; i < Nk; i++) {
        wordArray[i] = Word(key.byteArray[0][4*i].byte, key.byteArray[0][4*i+1].byte, key.byteArray[0][4*i+2].byte, key.byteArray[0][4*i+3].byte);
    }
// Perform key expansion
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

    //set expandedKey from wordArray
    for(int i = 0; i < words; i++)
    {
        expandedKey.byteArray[3][i] = Byte(wordArray[i].word & 0xff);
        expandedKey.byteArray[2][i] = Byte((wordArray[i].word >> 8) & 0xff);
        expandedKey.byteArray[1][i] = Byte((wordArray[i].word >> 16) & 0xff);
        expandedKey.byteArray[0][i] = Byte(wordArray[i].word >> 24);
    }
}

Word subWord(Word input) {
// Need bitwise SBOX transform on word
    uint8_t word1 = input.word >> 24;
    uint8_t word2 = input.word >> 16;
    uint8_t word3 = input.word >> 8;
    uint8_t word4 = input.word;
// Need upper and lower hex digits
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
//SBOX transform
    word1 = SBOX[word1_upper][word1_lower];
    word2 = SBOX[word2_upper][word2_lower];
    word3 = SBOX[word3_upper][word3_lower];
    word4 = SBOX[word4_upper][word4_lower];
    return Word(word1, word2, word3, word4);
}

Word rotWord(Word input) {
// Rotate by 1 byte to the left
// a0a1a2a3 becomes a1a2a3a0
    uint8_t lowest = input.word >> 24;
    Word retWord = Word(input.word);
    retWord.word = retWord.word << 8;
    retWord.word = retWord.word + lowest;
    return retWord;
}

Word rcon(int val) {
// Rcon = x^(i-1)000000 (hex digits)
// x = {02}
    Byte maxBit(0x01);
    Byte multVal(0x02);
    for(int i = 0; i < val - 1; i++) {
        maxBit = maxBit * multVal;
    }
    return Word(maxBit.byte, 0x00, 0x00, 0x00);
}

