#include <stdint.h>
#include "MatLibAES.h"
ByteArray::ByteArray(int row1, int col1) {
    row = row1;
    col = col1;
    // Create a 2D array of bytes
    byteArray = new Byte*[row];
    for(int i = 0; i < row; ++i) {
        byteArray[i] = new Byte[col];
    }
}
ByteArray::ByteArray() {
    int def = 4; //default value
    ByteArray(def, def);
}
ByteArray::~ByteArray() {
    // 2D array cleanup
    for(int i = 0; i < row; ++i) {
        delete [] byteArray[i];
    }
    delete [] byteArray;
}
Byte::Byte() {
    byte = 0;
}
Byte::Byte(uint8_t byte1) {
    byte = byte1;
}
uint8_t Byte::getByte() {
    return byte;
}
Byte Byte::operator+(Byte rhs) {
    uint8_t retVal = byte ^ rhs.byte;
    return Byte(retVal);
}
Byte Byte::operator*(Byte rhs) {
    uint8_t retVal;
    uint16_t workingRHS = rhs.byte;
    uint16_t workingLHS = byte;
    uint16_t mod = 0x011b; // the modulus value for polynomial arithmetic in G(256) using AES
    uint16_t temp = 0;
    for(int i = 0; i < 8; i++) {
        workingRHS = workingRHS >> i;
        if(workingRHS & 0x01 == 1) {
            workingLHS = workingLHS << i;
            temp ^= workingLHS;

        }
        workingLHS = byte; // reset values after bit shift
        workingRHS = rhs.byte;
    }
    for(int j = 0; j <8 ; j++) {
        if(((temp << j) & 0x8000) == 0x8000) {
            temp = temp ^ (mod << 7 - j);
        }
    }
    retVal = temp;
    return Byte(retVal);
}
