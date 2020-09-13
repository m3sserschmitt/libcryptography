OBJECTS += ./src/v1/base64.o\
./src/v1/rsa.o\
./src/v1/sha256.o\
./src/v1/aes.o

CC_DEPS += ./src/v1/deps/base64.d\
./src/v1/deps/rsa.d\
./src/v1/deps/sha256.d\
./src/v1/deps/aes.d

./src/v1/%.o: ./src/v1/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

