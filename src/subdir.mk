OBJECTS += ./src/aes.o\
./src/sha256.o\
./src/base64.o\
./src/rsa.o\
./src/init.o\
./src/hash.o

CC_DEPS += ./src/deps/aes.d\
./src/deps/sha256.d\
./src/deps/base64.d\
./src/deps/rsa.d\
./src/deps/init.d\
./src/deps/hash.d

./src/%.o: ./src/%.cc
	$(CC) -Wall -c -fPIC -lcrypto -shared $< -o $@

