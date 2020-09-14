OBJECTS += ./src/v3/rsa.o\
./src/v3/aes.o

CC_DEPS += ./src/v3/deps/rsa.d\
./src/v3/deps/aes.d

./src/v3/%.o: ./src/v3/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

