OBJECTS += ./src/hash.o

CC_DEPS += ./src/deps/hash.d

./src/%.o: ./src/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

