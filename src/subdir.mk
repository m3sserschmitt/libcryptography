OBJECTS += ./src/rsa_pem.o\
./src/sha256.o\
./src/aes_init.o\
./src/hash.o\
./src/init.o\
./src/base64.o\
./src/rsa_sign.o\
./src/rsa.o\
./src/aes.o

CC_DEPS += ./src/deps/rsa_pem.d\
./src/deps/sha256.d\
./src/deps/aes_init.d\
./src/deps/hash.d\
./src/deps/init.d\
./src/deps/base64.d\
./src/deps/rsa_sign.d\
./src/deps/rsa.d\
./src/deps/aes.d

./src/%.o: ./src/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

