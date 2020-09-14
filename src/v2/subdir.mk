OBJECTS += ./src/v2/base64.o\
./src/v2/sha.o\
./src/v2/aes.o\
./src/v2/rsa.o

CC_DEPS += ./src/v2/deps/base64.d\
./src/v2/deps/sha.d\
./src/v2/deps/aes.d\
./src/v2/deps/rsa.d

./src/v2/%.o: ./src/v2/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

