OBJECTS += ./src/hash.o\
./src/init.o

CC_DEPS += ./src/deps/hash.d\
./src/deps/init.d

./src/%.o: ./src/%.cc
	$(CC) -Wall -c -fPIC $< -o $@

