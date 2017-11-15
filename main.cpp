#include <fstream>
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "aes_functions.h"
#include "HelperFunctions.h"

using namespace std;

ByteArray* Cipher(ByteArray *state, ByteArray *keys);
ByteArray* InvCipher(ByteArray *state, ByteArray *keys);

void CBCEncrypt(Byte *key, Byte *textBlocks, char *filename);
void CBCDecrypt(Byte *key, Byte *cipherTextBlocks, char *cipherTextFilename);

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

    if (strcmp(argv[1],"--help") == 0 || argc != 4)
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

                // This function gets the key and sets the global size variable
                KeySize = GetFileSize(keyFilename);

                if (!(KeySize == 16 || KeySize == 24 || KeySize == 32))
                {
                    printf("Error: Key size is not compatible\n");
                    return 1;
                }

                Byte *key = GetTextFromFile(keyFilename, KeySize); // Static memory allocation; deallocation must be handled
                try
                {
                    // This function gets the plain text to be encrypted and pads it
                    int plainTextSize = GetFileSize(plaintextFilename);

                    if (plainTextSize == 0)
                    {
		    // should be an exception to handle here
                        printf("Text file is empty - nothing to encrypt.\n");
                        free(key);
                        return 1;
                    }

                    int padSize = 16 - (plainTextSize % 16);
                    PlainTextWithPaddingSize = plainTextSize + padSize;

                    Byte *textBlocks = GetPlainTextWithPadding(plaintextFilename, plainTextSize, padSize);

                    CBCEncrypt(key, textBlocks, plaintextFilename);
                }
                catch(...) {
                    cerr << "An error occurred during encryption.\n"; // Memory will be freed below 
                }
                free(key); // Ensure memory is freed
            }
            else
            {
                printf("ERROR: No permission to read key file and/or text file.\n");
                return 1;
            }
        }
        else
        {
            printf("ERROR: Key file and/or text file do not exist.\n");
            return 1;
        }
    }
    else if (function == "-d")
    {
        char *keyFilename = argv[2];
        char *cipherTextFilename = argv[3];

        if (access(keyFilename, F_OK) == 0 &&
            access(cipherTextFilename, F_OK == 0)) // File access check
        {
            if (access(keyFilename, R_OK) == 0 &&
                access(cipherTextFilename, R_OK) == 0) // File read check
            {

                KeySize = GetFileSize(keyFilename);

                //Key must be in the expected 128, 192, or 256 bit form
                if (!(KeySize == 16 || KeySize == 24 || KeySize == 32))
                {
                    printf("Error: Key size is not compatible\n");
                    return 1;
                }

                

                CipherTextSize = GetFileSize(cipherTextFilename);
                if( CipherTextSize == -1) {
                    printf("Error occurred in reading cipher text file.\n");
                    return 1;
                }
                else if (CipherTextSize == 0)
                {
                    printf("Cipher text file is empty - nothing to decrypt.\n");
                    return 1;
                }
                else if (CipherTextSize % 16 != 0)
                {
                    printf("Cipher text is corrupt (should be an even block length).\n"
                                   "Cipher text size = %i\n", CipherTextSize);
                    return 1;
                }
                
                // static allocations - ensure these are deleted at the end of decryption.
                Byte *key = GetTextFromFile(keyFilename, KeySize);
                Byte *cipherTextBlocks = GetTextFromFile(cipherTextFilename, CipherTextSize);
                try 
                {
                    CBCDecrypt(key, cipherTextBlocks, cipherTextFilename);
                }
                catch(...) {
                    cerr << "Error in decryption\n";
                }
                free(key); // deallocate all static allocations
                free(cipherTextBlocks);
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
        
        // key is statically allocated; outfile is opened. Must deallocate and close before exiting.
        Byte *key = 0; // set to null
        key = (Byte *) malloc (sizeof(Byte) * keyLengthBytes);
        ofstream outfile(filename, ofstream::out | ofstream::binary);
        
        try 
        {
            GenerateRandom(key, keyLengthBytes);

            // Write to key file
            for (int i = 0; i < keyLengthBytes; i++)
                outfile << key[i].byte;
        }
        catch(...) {
            cerr << "An error occurred during key generation / writing.\n";
        }
        free(key);
        outfile.close();
    }
    else
    {
        printf("Invalid argument for function/mode. Valid options are -e, -d, or -k\n");
        return 0;
    }

    return 0;  
}

void CBCEncrypt(Byte *key, Byte *textBlocks, char *filename) {
    // Generate IV
    Byte IV[16];
    GenerateRandom(IV, 16);

    Byte *cipherBuffer = 0; // default null pointer, static allocation; must be exception-handled
    cipherBuffer = (Byte *) malloc (sizeof(Byte) * (PlainTextWithPaddingSize + 16));
    ofstream ofile; // handle outfile here as well; will be opened later
    try{
        // Copy IV into first block of cipher text
        CopyBlock(cipherBuffer, 0, IV, 0);

        // Convert key to a ByteArray form (2D array)
        ByteArray keyByteArray = ByteArray(1, KeySize);
        for (int k = 0; k < KeySize; k++)
        {
            keyByteArray.byteArray[0][k] = key[k];
        }

        // numWords = Nb(Nr+1)
        // Nr = KeySize/4 + 6
        int numWords = 4*(KeySize/4 + 7);
        ByteArray keyExpanded = ByteArray(4, numWords);

        keyExpansion(keyByteArray, keyExpanded, KeySize/4, numWords);

        // For each block of plain text
        for (int i = 0; i < PlainTextWithPaddingSize/16; i++)
        {
            Byte tmpCurrentBlock[16];
            CopyBlock(tmpCurrentBlock, 0, textBlocks, 16*i);

            // XOR plain text block with IV
            for (int k = 0; k < 16; k++)
                tmpCurrentBlock[k] = tmpCurrentBlock[k] + IV[k];

            // Convert current plain text block to state
            ByteArray stateArray = ByteArray(4, 4);
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    stateArray.byteArray[k][j] = tmpCurrentBlock[4*j + k];
                }
            }

            // Get cipher text block as ByteArray
            ByteArray *cipherBlock;
            cipherBlock = Cipher(&stateArray, &keyExpanded);

            // Convert to a linear block for copying
            Byte linearCipherBlock[16];
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    linearCipherBlock[4*j + k] = cipherBlock->byteArray[k][j];
                }
            }

            CopyBlock(cipherBuffer, 16*(i+1), linearCipherBlock, 0);

            // Copy the current cipher text to be used as IV for next round of encryption
            CopyBlock(IV, 0, linearCipherBlock, 0);
        }

        strcat(filename, ".enc");
        ofile.open(filename, ofstream::out | ofstream::binary);

        for (int i = 0; i < PlainTextWithPaddingSize + 16; i++)
        {
            ofile << cipherBuffer[i].byte;
        }
    }
    catch(...) {
        cerr << "CBCEncrypt failed!\n";
    }
    if(ofile.is_open())
        ofile.close();
    free(cipherBuffer);
}

void CBCDecrypt(Byte *key, Byte *cipherTextBlocks, char *cipherTextFilename)
{
    // Get IV which is in first block of cipher text
    Byte IV[16];
    CopyBlock(IV, 0, cipherTextBlocks, 0);

    Byte *textBuffer = 0; // default null pointer, static allocation; must be exception-handled
    textBuffer = (Byte *) malloc (sizeof(Byte)*(CipherTextSize - 16));
    ofstream ofile; // handle outfile here as well; will be opened later
    try
    {
        // Convert key to a ByteArray form (2D array)
        ByteArray keyByteArray = ByteArray(1, KeySize);
        for (int k = 0; k < KeySize; k++)
        {
            keyByteArray.byteArray[0][k] = key[k];
        }

        // numWords = Nb(Nr+1)
        // Nr = KeySize/4 + 6
        int numWords = 4*(KeySize/4 + 7);
        ByteArray keyExpanded = ByteArray(4, numWords);

        keyExpansion(keyByteArray, keyExpanded, KeySize/4, numWords);

        // For each block of cipher text, excluding the first block which was IV
        for (int i = 1; i < CipherTextSize/16; i++)
        {
            Byte tmpCurrentBlock[16];
            CopyBlock(tmpCurrentBlock, 0, cipherTextBlocks, 16*i);

           // Convert block to state array
            ByteArray stateArray = ByteArray(4, 4);
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    stateArray.byteArray[k][j] = tmpCurrentBlock[4*j + k];
                }
            }

            // Decrypt block
            ByteArray *textBlock;
            textBlock = InvCipher(&stateArray, &keyExpanded);

            // Convert to linear array for XORing and copying
            Byte linearTextBlock[16];
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    linearTextBlock[4*j + k] = textBlock->byteArray[k][j];
                }
            }

            // XOR with IV
            for (int k = 0; k < 16; k++)
                linearTextBlock[k] = linearTextBlock[k] + IV[k];

            CopyBlock(textBuffer, 16*(i-1), linearTextBlock, 0);

            // Copy the current cipher text block into the IV for the next round of decryption
            CopyBlock(IV, 0, tmpCurrentBlock, 0);
        }

        // Validate padding
        int padBytes = ValidatePadding(textBuffer, CipherTextSize - 16);
        if(padBytes != -1) // if the pad is wrong, don't print output
        {
            strcat(cipherTextFilename, ".dec");

            ofile.open(cipherTextFilename, ofstream::out | ofstream::binary);
            for (int i = 0; i < CipherTextSize - 16 - padBytes; i++)
            {
                ofile << textBuffer[i].byte;
            }
        }
    }
    catch(...) {
        cerr << "CBCDecrypt failed!\n";
    }
    if(ofile.is_open())
        ofile.close();
    free(textBuffer);
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
