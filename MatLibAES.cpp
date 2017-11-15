#include <stdint.h>
#include <stdlib.h>
#include "MatLibAES.h"
ByteArray::ByteArray(int row1, int col1) {
// Constructor for 2D array of Bytes
// 2D pointer; built in parts.
    row = row1;
    col = col1;
    // Create a 2D array of bytes
    byteArray = new Byte*[row];
    for(int i = 0; i < row; ++i) {
        byteArray[i] = new Byte[col];
    }
}
ByteArray::ByteArray() {
// Default constructor, just makes 4x4 array
    int def = 4; //default value
    ByteArray(def, def);
}
ByteArray::~ByteArray() {
// Destructor, 2D array cleanup
    for(int i = 0; i < row; ++i) {
        delete [] byteArray[i];
    }
}
Byte::Byte() {
// Default constructor
    byte = 0;
}
Byte::Byte(uint8_t byte1) {
// Assign specific byte value to byte
    byte = byte1;
}
Byte Byte::operator+(Byte rhs) {
// Addition in this field is just XOR
    uint8_t retVal = byte ^ rhs.byte;
    return Byte(retVal);
}
Byte Byte::operator*(Byte rhs) {
// AES multiplication implementation
// This represents polynomial arithmetic in a G(256) field
// Implemented based on NIST AES specification
    uint8_t retVal; 
    // working values will all be 16-bit to avoid lost data to overflow
    uint16_t workingRHS = rhs.byte;
    uint16_t workingLHS = byte;
    uint16_t mod = 0x011b; // the modulus value for polynomial arithmetic in G(256) using AES
    uint16_t temp = 0; // storage of current value
    for(int i = 0; i < 8; i++) {
    // Addition step of multiplication
    // Add (XOR) a bit-shifted value of the LHS to the current product
    // bit-shifted by the binary digit value (7 highest to 0 lowest) of the RHS
    // workingLHS and workingRHS modified throughout this loop to simplify logic, reset at the end 
        workingRHS = workingRHS >> i;
        if(workingRHS & 0x01 == 1) { 
            workingLHS = workingLHS << i;
            temp ^= workingLHS;
        }
        // reset values after bit shift
        workingLHS = byte; 
        workingRHS = rhs.byte;
    }
    for(int j = 0; j <8 ; j++) {
    // Modulus loop
    // Add (XOR) the bit-shifted value of the modulus to the current temp value
    // The modulus will be shifted by the amount over the highest digit value (8) that
    // represents the current degree of temp 
    // e.g. if deg(temp) = 13 then bitshift = 13 - 8 and temp = temp ^ mod << bitshift is new value
    // bitshift can be calculated as j - 7 based on the definition of j within the for loop.
        if(((temp << j) & 0x8000) == 0x8000) {
            temp = temp ^ (mod << 7 - j);
        }
    }
    // Convert to 8-bit data type and return a Byte-wrapped value of it.
    retVal = temp;
    return Byte(retVal);
}

int modulo (int a, int b) {
    return a >= 0 ? a % b : (b - abs(a % b)) % b;
}

Word::Word() {
// Default constructor
    word = 0;
}
Word::Word(uint32_t word1) {
// Assign specific word value to Word
    word = word1;
}
Word::Word(uint8_t byte1, uint8_t byte2, uint8_t byte3, uint8_t byte4) {
// Assign specific 4-byte value to word
    uint32_t part1 = byte1 << 24;
    uint32_t part2 = byte2 << 16;
    uint32_t part3 = byte3 << 8;
    uint32_t part4 = byte4;
    word = part1 + part2 + part3 + part4;
}
Word Word::operator^(Word rhs) {
// Simple XOR on the wrapper
    uint32_t retVal = word ^ rhs.word;
    return Word(retVal);
}
