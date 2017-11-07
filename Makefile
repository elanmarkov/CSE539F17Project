all: main.o MatLibAES.o HelperFunctions.o aes_functions.o
	g++ -o SimpleAES main.o MatLibAES.o HelperFunctions.o aes_functions.o

main.o: main.cpp MatLibAES.h HelperFunctions.h aes_functions.h
	g++ -c main.cpp

MatLibAES.o: MatLibAES.cpp
	g++ -c MatLibAES.cpp

HelperFunctions.o: HelperFunctions.cpp
	g++ -c HelperFunctions.cpp

aes_functions.o: aes_functions.cpp
	g++ -c aes_functions.cpp