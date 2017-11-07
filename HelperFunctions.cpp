#include <cstdlib>
#include "HelperFunctions.h"

using namespace std;

// Get the size in bytes of a file
int GetFileSize(char *filename)
{
    ifstream inFile(filename, ifstream::in | ifstream::binary);

    int size;
    inFile.seekg(0, inFile.end);
    size = inFile.tellg();

    if (size < 0)
    {
        printf("Error getting file size\n");
        exit(1);
    }

    inFile.close();

    return size;
}

Byte* GetTextFromFile(char *filename, int fileSize)
{
    ifstream file(filename, ifstream::in | ifstream::binary);

    Byte *fileText;
    fileText = (Byte *) malloc (sizeof(Byte) * fileSize);

    char *tmpBuf;
    tmpBuf = (char *) malloc (sizeof(char) * fileSize);

    file.read(tmpBuf, fileSize);

    for (int i = 0; i < fileSize; i++)
    {
        fileText[i] = Byte((uint8_t) tmpBuf[i]);
    }

    free(tmpBuf);
    file.close();

    return fileText;
}

Byte* GetPlainTextWithPadding(char *textFilename, int fileSize, int padSize)
{
    ifstream textFile(textFilename, ifstream::in | ifstream::binary);

    uint8_t padValue = 0x10 - (fileSize % 16);

    Byte *text;
    text = (Byte *) malloc (sizeof(Byte) * (fileSize + padSize));

    char *tmpBuf;
    tmpBuf = (char *) malloc (sizeof(char) * fileSize);

    textFile.read(tmpBuf, fileSize);

    for (int i = 0; i < fileSize; i++)
    {
        text[i] = Byte((uint8_t) tmpBuf[i]);
    }

    for (int i = 0; i < padSize; i++)
    {
        text[fileSize + i] = Byte(padValue);
    }

    free(tmpBuf);
    textFile.close();

    return text;
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