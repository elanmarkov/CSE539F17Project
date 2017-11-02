#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "aes_functions.h"

using namespace std;

ByteArray* Cipher(ByteArray *state, ByteArray *keys);
ByteArray* InvCipher(ByteArray *state, ByteArray *keys);

Byte* GetKeyFromKeyFile(char *keyFilename);
Byte* GetTextWithPaddingFromTextFile(char *textFilename);
Byte* GetCipherText(char *cipherTextFilename);
void CBCEncrypt(Byte *key, Byte *textBlocks, char *filename);
void CBCDecrypt(Byte *key, Byte *cipherTextBlocks, char *cipherTextFilename);

int GetFileSize(ifstream *file);
void CopyBlock(Byte *dest, int destStartIndex, Byte *src, int srcStartIndex);
void ValidatePadding(Byte *text, int size);
void GenerateRandom(Byte *dest, int sizeInBytes);

extern const uint8_t SBOX[16][16] =            
    {{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
    {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
    {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15}, 
    {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75}, 
    {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84}, 
    {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf}, 
    {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8}, 
    {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2}, 
    {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73}, 
    {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
    {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
    {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
    {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
    {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
    {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
    {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}};

extern const uint8_t INVSBOX[16][16] =
    {{0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
    {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
    {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
    {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
    {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
    {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
    {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
    {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
    {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
    {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
    {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
    {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
    {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
    {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
    {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
    {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}};

extern const int Nb = 4;

int KeySize = 0;
int PlainTextWithPaddingSize = 0;
int CipherTextSize = 0;

int main(int argc, char* argv[]) {

/*
    ByteArray key = ByteArray(1, 16);
    key.byteArray[0][0].byte = 0x2b;
    key.byteArray[0][1].byte = 0x7e;
    key.byteArray[0][2].byte = 0x15;
    key.byteArray[0][3].byte = 0x16;
    key.byteArray[0][4].byte = 0x28;
    key.byteArray[0][5].byte = 0xae;
    key.byteArray[0][6].byte = 0xd2;
    key.byteArray[0][7].byte = 0xa6;
    key.byteArray[0][8].byte = 0xab;
    key.byteArray[0][9].byte = 0xf7;
    key.byteArray[0][10].byte = 0x15;
    key.byteArray[0][11].byte = 0x88;
    key.byteArray[0][12].byte = 0x09;
    key.byteArray[0][13].byte = 0xcf;
    key.byteArray[0][14].byte = 0x4f;
    key.byteArray[0][15].byte = 0x3c;
    std::cout<< "Simple AES Implementation to be Implemented3\n";
    Word* wordArray;
    wordArray = new Word[4*(10+1)];
    std::cout<< "byte:" << std::hex << (int) key.byteArray[0][9].byte << '\n';
    keyExpansion(key, wordArray, 4, 4*(10+1));
    std::cout<< "Simple AES Implementation to be Implemented5\n";
    for(int i = 0; i < 4*(10+1); i++) {
        std::cout << "word: " << std::hex << (int) wordArray[i].word << '\n';
    }
    return 0;
*/
    for (int i = 0; i < argc; i++)
    {
        if (argv[i] == "--help")
        {
            printf("Usage: SimpleAES [(-d|-e) | -k] [KEYFILE | KEYLENGTH] [TEXTFILE | KEYFILE]\n");
            return 0;
        }
    }

    if (argc != 4)
    {
        printf("Usage: SimpleAES [(-d|-e) | -k] [KEYFILE | KEYLENGTH] [TEXTFILE | KEYFILE]\n");
        return 0;
    }

    string function = argv[1];

    if (function == "-e")
    {
        char *keyFilename = argv[2];
        char *plaintextFilename = argv[3];

        if (access(keyFilename, F_OK) == 0 &&
            access(plaintextFilename, F_OK == 0))
        {
            if (access(keyFilename, R_OK) == 0 &&
                access(plaintextFilename, R_OK) == 0)
            {
/*
                Byte *key;
                key = (Byte *) malloc (sizeof(Byte) * 16);

                key[0] = Byte(0x2b);
                key[1] = Byte(0x7e);
                key[2] = Byte(0x15);
                key[3] = Byte(0x16);
                key[4] = Byte(0x28);
                key[5] = Byte(0xae);
                key[6] = Byte(0xd2);
                key[7] = Byte(0xa6);
                key[8] = Byte(0xab);
                key[9] = Byte(0xf7);
                key[10] = Byte(0x15);
                key[11] = Byte(0x88);
                key[12] = Byte(0x09);
                key[13] = Byte(0xcf);
                key[14] = Byte(0x4f);
                key[15] = Byte(0x3c);

                KeySize = 16;

                Byte *textBlocks;
                textBlocks = (Byte *) malloc (sizeof(Byte) * 16);

                textBlocks[0] = Byte(0x32);
                textBlocks[1] = Byte(0x43);
                textBlocks[2] = Byte(0xf6);
                textBlocks[3] = Byte(0xa8);
                textBlocks[4] = Byte(0x88);
                textBlocks[5] = Byte(0x5a);
                textBlocks[6] = Byte(0x30);
                textBlocks[7] = Byte(0x8d);
                textBlocks[8] = Byte(0x31);
                textBlocks[9] = Byte(0x31);
                textBlocks[10] = Byte(0x98);
                textBlocks[11] = Byte(0xa2);
                textBlocks[12] = Byte(0xe0);
                textBlocks[13] = Byte(0x37);
                textBlocks[14] = Byte(0x07);
                textBlocks[15] = Byte(0x34);

                PlainTextWithPaddingSize = 16;

                ByteArray keyByteArray = ByteArray(1, 16);
                printf("should print key in order:\n");
                for (int k = 0; k < 16; k++)
                {
                    keyByteArray.byteArray[0][k] = key[k];
                    printf("%X\n", keyByteArray.byteArray[0][k].byte);
                }

                int numWords = 4*(16/4 + 7); //Nb(Nr+1); Nr = KeySize/4 + 6
                ByteArray keyExpanded = ByteArray(4, numWords);

                keyExpansion(keyByteArray, keyExpanded, 16/4, numWords);

                printf("should print input in order:\n");
                ByteArray stateArray = ByteArray(4, 4);
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        stateArray.byteArray[k][j] = textBlocks[4*j + k];
                        printf("%X\n", stateArray.byteArray[k][j].byte);
                    }
                }

                ByteArray *cipherBlock;
                cipherBlock = Cipher(&stateArray, &keyExpanded);

                printf("cipher text: \n");

                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        printf("%X\n", cipherBlock->byteArray[k][j].byte);
                    }
                }*/

                // This function gets the key and sets the global size variable
                Byte *key = GetKeyFromKeyFile(keyFilename);

                // This function gets the plain text to be encrypted and pads it
                Byte *textBlocks = GetTextWithPaddingFromTextFile(plaintextFilename);

                CBCEncrypt(key, textBlocks, plaintextFilename);
            }
            else
            {
                printf("ERROR: No permission to read key file and/or text file.\n");
                return 0;
            }
        }
        else
        {
            printf("ERROR: Key file and/or text file do not exist.\n");
            return 0;
        }
    }
    else if (function == "-d")
    {
        char *keyFilename = argv[2];
        char *cipherTextFilename = argv[3];

        if (access(keyFilename, F_OK) == 0 &&
            access(cipherTextFilename, F_OK == 0))
        {
            if (access(keyFilename, R_OK) == 0 &&
                access(cipherTextFilename, R_OK) == 0)
            {
/*
                Byte *key;
                key = (Byte *) malloc (sizeof(Byte) * 16);

                key[0] = Byte(0x2b);
                key[1] = Byte(0x7e);
                key[2] = Byte(0x15);
                key[3] = Byte(0x16);
                key[4] = Byte(0x28);
                key[5] = Byte(0xae);
                key[6] = Byte(0xd2);
                key[7] = Byte(0xa6);
                key[8] = Byte(0xab);
                key[9] = Byte(0xf7);
                key[10] = Byte(0x15);
                key[11] = Byte(0x88);
                key[12] = Byte(0x09);
                key[13] = Byte(0xcf);
                key[14] = Byte(0x4f);
                key[15] = Byte(0x3c);

                KeySize = 16;

                Byte *cipherBlocks;
                cipherBlocks = (Byte *) malloc (sizeof(Byte) * 32);

                cipherBlocks[0] = Byte(0x33);
                cipherBlocks[1] = Byte(0x33);
                cipherBlocks[2] = Byte(0x33);
                cipherBlocks[3] = Byte(0x33);
                cipherBlocks[4] = Byte(0x33);
                cipherBlocks[5] = Byte(0x33);
                cipherBlocks[6] = Byte(0x33);
                cipherBlocks[7] = Byte(0x33);
                cipherBlocks[8] = Byte(0x33);
                cipherBlocks[9] = Byte(0x33);
                cipherBlocks[10] = Byte(0x33);
                cipherBlocks[11] = Byte(0x33);
                cipherBlocks[12] = Byte(0x33);
                cipherBlocks[13] = Byte(0x33);
                cipherBlocks[14] = Byte(0x33);
                cipherBlocks[15] = Byte(0x33);
                cipherBlocks[16] = Byte(0x39);
                cipherBlocks[17] = Byte(0x25);
                cipherBlocks[18] = Byte(0x84);
                cipherBlocks[19] = Byte(0x1d);
                cipherBlocks[20] = Byte(0x02);
                cipherBlocks[21] = Byte(0xdc);
                cipherBlocks[22] = Byte(0x09);
                cipherBlocks[23] = Byte(0xfb);
                cipherBlocks[24] = Byte(0xdc);
                cipherBlocks[25] = Byte(0x11);
                cipherBlocks[26] = Byte(0x85);
                cipherBlocks[27] = Byte(0x97);
                cipherBlocks[28] = Byte(0x19);
                cipherBlocks[29] = Byte(0x6a);
                cipherBlocks[30] = Byte(0x0b);
                cipherBlocks[31] = Byte(0x32);

                CipherTextSize = 32;

                ByteArray keyByteArray = ByteArray(1, 16);
                printf("should print key in order:\n");
                for (int k = 0; k < 16; k++)
                {
                    keyByteArray.byteArray[0][k] = key[k];
                    printf("%X\n", keyByteArray.byteArray[0][k].byte);
                }

                int numWords = 4*(16/4 + 7); //Nb(Nr+1); Nr = KeySize/4 + 6
                ByteArray keyExpanded = ByteArray(4, numWords);

                keyExpansion(keyByteArray, keyExpanded, 16/4, numWords);

                printf("should print cipher text in order:\n");
                ByteArray stateArray = ByteArray(4, 4);
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        stateArray.byteArray[k][j] = cipherBlocks[4*j + k];
                        printf("%X\n", stateArray.byteArray[k][j].byte);
                    }
                }

                ByteArray *textBlock;
                textBlock = InvCipher(&stateArray, &keyExpanded);

                printf("plain text: \n");

                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        printf("%X\n", textBlock->byteArray[k][j].byte);
                    }
                }*/

                // This function gets the key and sets the global size variable
                Byte *key = GetKeyFromKeyFile(keyFilename);

                // This function gets the cipher text to be decrypted
                Byte *cipherTextBlocks = GetCipherText(cipherTextFilename);

                //validate padding in CBC decrypt
                CBCDecrypt(key, cipherTextBlocks, cipherTextFilename);
                //CBCDecrypt(key, cipherBlocks, cipherTextFilename);

            }
            else
            {
                printf("ERROR: No permission to read key file and/or cipher text file.\n");
                return 0;
            }
        }
        else
        {
            printf("ERROR: Key file and/or cipher text file do not exist.\n");
            return 0;
        }
    }
    else if (function == "-k")
    {
        char *filename = argv[3];

        if (access(filename, F_OK) == 0)
        {
            char overwrite;
            printf("The file you are writing your key to already exists.\n"
                   "Overwrite existing contents with key? [y|n]\n");
            scanf("%c", &overwrite);

            if (overwrite == 'y')
            {
                if (access(filename, W_OK) != 0)
                {
                    printf("You do not have permission to write to the file %s. %s\n", filename,
                           "Print key to a new file or an existing one with sufficient permissions.\n");
                    return 0;
                }
            } else
                return 0;
        }

        string keyLength = argv[2];
        int keyLengthBytes;

        if (keyLength == "128") {
            keyLengthBytes = 16;
        }
        else if (keyLength == "192") {
            keyLengthBytes = 24;
        }
        else if (keyLength == "256") {
            keyLengthBytes = 32;
        }
        else {
            printf("Invalid argument for key length. Valid options are 128, 192, or 256\n");
            return 0;
        }

        Byte *key;
        key = (Byte *) malloc (sizeof(Byte) * keyLengthBytes);

        GenerateRandom(key, keyLengthBytes);

        // Write to key file
        ofstream outfile(filename, ofstream::out | ofstream::binary);

        for (int i = 0; i < keyLengthBytes; i++)
            outfile << key[i].byte;

        outfile.close();
    }
    else
    {
        printf("Invalid argument for function/mode. Valid options are -e, -d, or -k\n");
        return 0;
    }

    return 0;  
}

Byte* GetKeyFromKeyFile(char *keyFilename)
{
    ifstream keyFile(keyFilename, ifstream::in | ifstream::binary);

    KeySize = GetFileSize(&keyFile);

    if (!(KeySize == 16 || KeySize == 24 || KeySize == 32))
    {
        printf("Error: Key size is not compatible\n");
        exit(1);
    }

    Byte *key;
    key = (Byte *) malloc (sizeof(Byte) * KeySize);

    char *tmpBuf;
    tmpBuf = (char *) malloc (sizeof(char) * KeySize);

    keyFile.read(tmpBuf, KeySize);

    for (int i = 0; i < KeySize; i++)
    {
        key[i] = Byte((uint8_t) tmpBuf[i]);
    }

    free(tmpBuf);
    keyFile.close();

    return key;
}

Byte* GetTextWithPaddingFromTextFile(char *textFilename)
{
    ifstream textFile(textFilename, ifstream::in | ifstream::binary);

    int textFileSize = GetFileSize(&textFile);

    int remainder = textFileSize % 16;
    uint8_t padValue = 0x10 - remainder;

    PlainTextWithPaddingSize = textFileSize + (16 - remainder);

    Byte *text;
    text = (Byte *) malloc (sizeof(Byte) * PlainTextWithPaddingSize);

    char *tmpBuf;
    tmpBuf = (char *) malloc (sizeof(char) * textFileSize);

    textFile.read(tmpBuf, textFileSize);

    for (int i = 0; i < textFileSize; i++)
    {
        text[i] = Byte((uint8_t) tmpBuf[i]);
    }

    for (int i = 0; i < (16 - remainder); i++)
    {
        text[textFileSize + i] = Byte(padValue);
    }

    free(tmpBuf);
    textFile.close();

    return text;
}

Byte* GetCipherText(char *cipherTextFilename)
{
    ifstream cipherTextFile(cipherTextFilename, ifstream::in | ifstream::binary);

    CipherTextSize = GetFileSize(&cipherTextFile);

    if (CipherTextSize % 16 != 0)
    {
        printf("Cipher text is corrupt (should be an even block length).\n"
               "Cipher text size = %i\n", CipherTextSize);
        exit(1);
    }

    Byte *cipherText;
    cipherText = (Byte *) malloc (sizeof(Byte) * CipherTextSize);

    char *tmpBuf;
    tmpBuf = (char *) malloc (sizeof(char) * CipherTextSize);

    cipherTextFile.read(tmpBuf, CipherTextSize);

    for (int i = 0; i < CipherTextSize; i++)
    {
        cipherText[i] = Byte((uint8_t) tmpBuf[i]);
    }

    free(tmpBuf);
    cipherTextFile.close();

    return cipherText;
}

int GetFileSize(ifstream *file)
{
    int fileSize;

    file->seekg(0, file->end);
    fileSize = file->tellg();
    file->seekg(file->beg);

    if (fileSize <= 0)
    {
        "Error determining file size, or file is empty.\n";
        exit(1);
    }

    return fileSize;
}

void CBCEncrypt(Byte *key, Byte *textBlocks, char *filename) {
    Byte IV[16];
    GenerateRandom(IV, 16);

    Byte *cipherBuffer;
    cipherBuffer = (Byte *) malloc (sizeof(Byte) * (PlainTextWithPaddingSize + 16));

    CopyBlock(cipherBuffer, 0, IV, 0);

    //Nk = KeySize/4
    ByteArray keyByteArray = ByteArray(1, KeySize);
    for (int k = 0; k < KeySize; k++)
    {
        keyByteArray.byteArray[0][k] = key[k];
    }

    int numWords = 4*(KeySize/4 + 7); //Nb(Nr+1); Nr = KeySize/4 + 6
    ByteArray keyExpanded = ByteArray(4, numWords);

    keyExpansion(keyByteArray, keyExpanded, KeySize/4, numWords);

    for (int i = 0; i < PlainTextWithPaddingSize/16; i++)
    {
        Byte tmpCurrentBlock[16];
        CopyBlock(tmpCurrentBlock, 0, textBlocks, 16*i);

        for (int k = 0; k < 16; k++)
            tmpCurrentBlock[k] = tmpCurrentBlock[k] + IV[k];

        ByteArray stateArray = ByteArray(4, 4);
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                stateArray.byteArray[k][j] = tmpCurrentBlock[4*j + k];
            }
        }

        ByteArray *cipherBlock;
        cipherBlock = Cipher(&stateArray, &keyExpanded);

        Byte linearCipherBlock[16];
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                linearCipherBlock[4*j + k] = cipherBlock->byteArray[k][j];
            }
        }

        CopyBlock(cipherBuffer, 16*(i+1), linearCipherBlock, 0);

        CopyBlock(IV, 0, linearCipherBlock, 0);
    }

    strcat(filename, ".enc");
    ofstream ofile(filename, ofstream::out | ofstream::binary);

    for (int i = 0; i < PlainTextWithPaddingSize + 16; i++)
    {
        ofile << cipherBuffer[i].byte;
    }

    ofile.close();
    free(cipherBuffer);
}

void CBCDecrypt(Byte *key, Byte *cipherTextBlocks, char *cipherTextFilename)
{
    Byte IV[16];
    CopyBlock(IV, 0, cipherTextBlocks, 0);

    Byte *textBuffer;
    textBuffer = (Byte *) malloc (sizeof(Byte)*(CipherTextSize - 16));

    //Nk = KeySize/4
    ByteArray keyByteArray = ByteArray(1, KeySize);
    for (int k = 0; k < KeySize; k++)
    {
        keyByteArray.byteArray[0][k] = key[k];
    }

    int numWords = 4*(KeySize/4 + 7); //Nb(Nr+1); Nr = KeySize/4 + 6
    ByteArray keyExpanded = ByteArray(4, numWords);

    keyExpansion(keyByteArray, keyExpanded, KeySize/4, numWords);

    for (int i = 1; i < CipherTextSize/16; i++)
    {
        Byte tmpCurrentBlock[16];
        CopyBlock(tmpCurrentBlock, 0, cipherTextBlocks, 16*i);

        ByteArray stateArray = ByteArray(4, 4);
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                stateArray.byteArray[k][j] = tmpCurrentBlock[4*j + k];
            }
        }

        ByteArray *textBlock;
        textBlock = InvCipher(&stateArray, &keyExpanded);

        Byte linearTextBlock[16];
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                linearTextBlock[4*j + k] = textBlock->byteArray[k][j];
            }
        }

        for (int k = 0; k < 16; k++)
            linearTextBlock[k] = linearTextBlock[k] + IV[k];

        CopyBlock(textBuffer, 16*(i-1), linearTextBlock, 0);

        CopyBlock(IV, 0, tmpCurrentBlock, 0);
    }

    ValidatePadding(textBuffer, CipherTextSize - 16);

    strcat(cipherTextFilename, ".dec");

    ofstream ofile(cipherTextFilename, ofstream::out | ofstream::binary);
    for (int i = 0; i < CipherTextSize - 16; i++)
    {
        ofile << textBuffer[i].byte;
    }

    ofile.close();
    free(textBuffer);
}

void CopyBlock(Byte *dest, int destStartIndex, Byte *src, int srcStartIndex)
{
    for (int i = 0; i < 16; i++)
    {
        dest[destStartIndex + i] = src[srcStartIndex + i];
    }
}

void ValidatePadding(Byte *text, int size)
{
    Byte lastByteOfText = text[size - 1];
    for (uint8_t i = 0; i < lastByteOfText.byte; i++)
    {
        if (text[(size - 1) - i].byte != lastByteOfText.byte)
        {
            printf("cipher text corrupt - padding is invalid.\n");
            exit(1);
        }

        text[(size - 1) - i] = Byte(0x00);
    }
}

void GenerateRandom(Byte *dest, int sizeInBytes)
{
    ifstream ifs ("/dev/urandom", ifstream::binary);
    if (ifs)
    {
        char *tmpBuf;
        tmpBuf = (char *) malloc (sizeof(char) * sizeInBytes);

        ifs.read(tmpBuf, sizeInBytes);

        for (int i = 0; i < sizeInBytes; i++)
        {
            dest[i] = ((uint8_t) tmpBuf[i]);
        }

        free(tmpBuf);
        ifs.close();
    }
}


ByteArray* Cipher(ByteArray *state, ByteArray *keys)
{
    int Nr = KeySize/4 + 6;

    AddRoundKey(state, keys, 0);

    for (int i = 1; i < Nr; i++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, keys, i);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, keys, Nr);

    return state;
}

ByteArray* InvCipher(ByteArray *state, ByteArray *keys)
{
    int Nr = KeySize/4 + 6;

    InvAddRoundKey(state, keys, Nr);

    for (int i = (Nr - 1); i > 0; i--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        InvAddRoundKey(state, keys, i);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    InvAddRoundKey(state, keys, 0);

    return state;
}

