#include "aes_functions.h"

void MixColumns() {
	const Byte o1(0x01);
	const Byte o2(0x02);
	const Byte o3(0x03);
	
	for(int i = 0; i < Nb; ++i) {
		state->byteArray[0][i] =	(o2 * state->byteArray[0][i]) + \
									(o3 * state->byteArray[1][i]) + \
									state->byteArray[2][i] + \
									state->byteArray[3][i];

		state->byteArray[1][i] =	state->byteArray[0][i] + \
									(o2 * state->byteArray[1][i]) + \
									(o3 * state->byteArray[2][i]) + \
									state->byteArray[3][i];

		state->byteArray[2][i] =	state->byteArray[0][i] + \
									state->byteArray[1][i] + \
									(o2 * state->byteArray[2][i]) + \
									(o3 * state->byteArray[3][i]);

		state->byteArray[3][i] =	(o3 * state->byteArray[0][i]) + \
									state->byteArray[1][i] + \
									state->byteArray[2][i] + \
									(o2 * state->byteArray[3][i]);
	}
}

void InvMixColumns() {
	const Byte o9(0x09);
	const Byte ob(0x0b);
	const Byte od(0x0d);
	const Byte oe(0x0e);

	for(int i = 0; i < Nb; ++i) {
		state->byteArray[0][i] =	(oe * state->byteArray[0][i]) + \
									(ob * state->byteArray[1][i]) + \
									(od * state->byteArray[2][i]) + \
									(o9 * state->byteArray[3][i]);

		state->byteArray[1][i] =	(o9 * state->byteArray[0][i]) + \
									(oe * state->byteArray[1][i]) + \
									(ob * state->byteArray[2][i]) + \
									(od * state->byteArray[3][i]);

		state->byteArray[2][i] =	(od * state->byteArray[0][i]) + \
									(o9 * state->byteArray[1][i]) + \
									(oe * state->byteArray[2][i]) + \
									(ob * state->byteArray[3][i]);

		state->byteArray[3][i] =	(ob * state->byteArray[0][i]) + \
									(od * state->byteArray[1][i]) + \
									(o9 * state->byteArray[2][i]) + \
									(oe * state->byteArray[3][i]);
	}
}

void AddRoundKey(const ByteArray* keys, int round) {
	for (int i = 0; i < Nb; ++i) {
		state->byteArray[0][i] = state->byteArray[0][i] + keys->byteArray[0][round];
		state->byteArray[1][i] = state->byteArray[1][i] + keys->byteArray[1][round];
		state->byteArray[2][i] = state->byteArray[2][i] + keys->byteArray[2][round];
		state->byteArray[3][i] = state->byteArray[3][i] + keys->byteArray[3][round];
	}
}

void InvAddRoundKey(const ByteArray* keys, int round) {
	AddRoundKey(keys, round);
}

