// AES Math Library by Elan Markov
// CSE 539 Final Project
#include <stdint.h>

// Forward declarations
struct ByteArray;
struct Byte;
int modulo (int a, int b);

struct ByteArray {
// Structure for creating an array of Byte items
// only dimensions are private
    private:	
        int row, col;
    public:
        Byte** byteArray;
        ByteArray(int row1, int col1);
        ByteArray();
        ~ByteArray();
};

// Structure for byte items
// Implemented as unsigned 8-bit integers
// Perform AES specified addition and multiplication on a G(256) field
struct Byte {
        uint8_t byte;
        Byte();
        Byte(uint8_t byte1);
        Byte operator+(Byte rhs);
        Byte operator* (Byte rhs);
};

struct Word {
        uint32_t word;
        Word();
        Word(uint32_t word1);
        Word(uint8_t byte1, uint8_t byte2, uint8_t byte3, uint8_t byte4);
        Word operator^(Word rhs);
};
