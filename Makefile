#Specify targets
all: fractureCrypto clean

fractureCrypto: ./src/main.o ./src/aes.o ./src/consint.o
	g++ -Wall -Werror ./src/main.o ./src/aes.o ./src/consint.o -o fracture -lncurses

main.o: ./src/main.cpp
	g++ -Wall -Werror -c ./src/main.cpp -o ./src/main.o -lncurses

aes.o: ./src/aes.cpp ./src/aes.h ./src/aes_config.h
	g++ -Wall -Werror -c ./src/aes.cpp -o ./src/aes.o

consint.o: ./src/consint.cpp ./src/consint.h
	g++ -Wall -Werror -c ./src/consint.cpp -o ./src/consint.o -lncurses

#Delete .o files after compile
clean:
	rm ./src/*.o