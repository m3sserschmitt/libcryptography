OBJECTS += ./src/v4/aes.o\
./src/v4/rsa.o

CC_DEPS += ./src/v4/deps/aes.d\
./src/v4/deps/rsa.d

./src/v4/%.o: ./src/v4/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

