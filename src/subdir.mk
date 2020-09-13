OBJECTS += ./src/aes.o\
./src/sha256.o\
./src/rsa_pem.o\
./src/init.o\
./src/rsa.o\
./src/hash.o\
./src/base64.o\
./src/aes_init.o\
./src/rsa_sign.o

CC_DEPS += ./src/deps/aes.d\
./src/deps/sha256.d\
./src/deps/rsa_pem.d\
./src/deps/init.d\
./src/deps/rsa.d\
./src/deps/hash.d\
./src/deps/base64.d\
./src/deps/aes_init.d\
./src/deps/rsa_sign.d

./src/%.o: ./src/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

