#ifndef _HELPER_FUNCS_H_
#define _HELPER_FUNCS_H_

#include <fstream>
#include "MatLibAES.h"

int GetFileSize(char *filename);
Byte* GetPlainTextWithPadding(char *textFilename, int fileSize, int padSize);
Byte* GetTextFromFile(char *filename, int fileSize);

void CopyBlock(Byte *dest, int destStartIndex, Byte *src, int srcStartIndex);
void ValidatePadding(Byte *text, int size);
void GenerateRandom(Byte *dest, int sizeInBytes);

#endif