#include <cstdlib>
#include "HelperFunctions.h"

using namespace std;

// Get the size in bytes of a file
// Return -1 if unsuccessful
int GetFileSize(char *filename)
{
    ifstream inFile(filename, ifstream::in | ifstream::binary);

    int size;
    inFile.seekg(0, inFile.end);
    size = inFile.tellg();

    if (size < 0)
    {
        inFile.close(); // For secure coding, close infile if in error
        return -1;
    }

    inFile.close(); // For secure coding, close infile upon end of use

    return size;
}

Byte* GetTextFromFile(char *filename, int fileSize)
{
    // File opened and static allocations
    ifstream file(filename, ifstream::in | ifstream::binary);

    Byte *fileText = 0; // Initialize pointers to 0 for secure coding
    fileText = (Byte *) malloc (sizeof(Byte) * fileSize);

    char *tmpBuf = 0; // Initialize pointers to 0 for secure coding
    tmpBuf = (char *) malloc (sizeof(char) * fileSize);

    try // Contain static allocated usage in try/catch block for secure coding
    {
        file.read(tmpBuf, fileSize);

        for (int i = 0; i < fileSize; i++)
        {
            fileText[i] = Byte((uint8_t) tmpBuf[i]);
        }
    }
    catch(...) 
    {
        printf("Error getting text from file.\n");
    }
    free(tmpBuf); // for secure coding, deallocate all memory and close files upon end of use
    file.close();

    return fileText; // Caller will handle any errors here
}

// Adds padding to valid plaintext
Byte* GetPlainTextWithPadding(char *textFilename, int fileSize, int padSize)
{

    // Opening files and static allocations
    ifstream textFile(textFilename, ifstream::in | ifstream::binary);

    uint8_t padValue = 0x10 - (fileSize % 16);

    Byte *text = 0; // Initialize pointers to 0 for secure coding
    text = (Byte *) malloc (sizeof(Byte) * (fileSize + padSize));

    char *tmpBuf = 0; // Initialize pointers to 0 for secure coding
    tmpBuf = (char *) malloc (sizeof(char) * fileSize);

    try // Contain static allocated usage in try/catch block for secure coding
    {
        textFile.read(tmpBuf, fileSize);

        for (int i = 0; i < fileSize; i++)
        {
            text[i] = Byte((uint8_t) tmpBuf[i]);
        }

        for (int i = 0; i < padSize; i++)
        {
            text[fileSize + i] = Byte(padValue);
        }
    }
    catch(...)
    {
        printf("Error in adding padding to plaintext.\n");
    }
    free(tmpBuf);
    textFile.close();

    return text; // the caller will deal with this deallocation
}

//copies part of a block to another block by index
void CopyBlock(Byte *dest, int destStartIndex, Byte *src, int srcStartIndex)
{
    for (int i = 0; i < 16; i++)
    {
        dest[destStartIndex + i] = src[srcStartIndex + i];
    }
}

// After decrypting, check that the padding is valid according to padding scheme
int ValidatePadding(Byte *text, int size)
{
    Byte lastByteOfText = text[size - 1];
    int numPadBytes = (int) lastByteOfText.byte;
    for (uint8_t i = 0; i < lastByteOfText.byte; i++)
    {
        if (text[(size - 1) - i].byte != lastByteOfText.byte)
        {
            printf("cipher text corrupt - padding is invalid.\n");
            return -1; // return error flag and do not print output
        }

        //text[(size - 1) - i] = Byte(0x00);
    }
    return numPadBytes;
}

void GenerateRandom(Byte *dest, int sizeInBytes)
{
    ifstream ifs ("/dev/urandom", ifstream::binary); // use cryptographically secure PRG for secure coding
    if (ifs)
    {
        char *tmpBuf = 0; // Initialize pointers to 0 for secure coding
        tmpBuf = (char *) malloc (sizeof(char) * sizeInBytes);

        try
        {
            ifs.read(tmpBuf, sizeInBytes);

            for (int i = 0; i < sizeInBytes; i++)
            {
                dest[i] = ((uint8_t) tmpBuf[i]);
            }
        }
        catch(...) {
             printf("Error in generating a random number.\n");
        }
        free(tmpBuf); // for secure coding, deallocate all memory and close files upon end of use
        ifs.close(); 
    }
}
