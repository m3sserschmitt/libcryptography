OBJECTS += ./src/v2/rsa.o\
./src/v2/aes.o\
./src/v2/sha256.o

CC_DEPS += ./src/v2/deps/rsa.d\
./src/v2/deps/aes.d\
./src/v2/deps/sha256.d

./src/v2/%.o: ./src/v2/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

