OBJECTS += ./src/v1/aes.o\
./src/v1/base64.o\
./src/v1/init.o\
./src/v1/rsa.o\
./src/v1/sha.o

CC_DEPS += ./src/v1/deps/aes.d\
./src/v1/deps/base64.d\
./src/v1/deps/init.d\
./src/v1/deps/rsa.d\
./src/v1/deps/sha.d

./src/v1/%.o: ./src/v1/%.cc
	$(CC) -Wall -c -fPIC $< -o $@
