#include <stdint.h>
struct ByteArray;
struct Byte;
struct ByteArray {
    private:	
        int row, col;
    public:
        Byte** byteArray;
        ByteArray(int row1, int col1);
        ByteArray();
        ~ByteArray();
};
struct Byte {
        uint8_t byte;
        Byte();
        Byte(uint8_t byte1);
        uint8_t getByte();
        Byte operator+(Byte rhs);
        Byte operator* (Byte rhs);
};
