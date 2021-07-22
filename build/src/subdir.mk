OBJECTS += ./src/aes.o \
./src/base64.o \
./src/random.o \
./src/rsa.o \
./src/sha.o 

CC_DEPS += ./src/deps/aes.d \
./src/deps/base64.d \
./src/deps/random.d \
./src/deps/rsa.d \
./src/deps/sha.d 

./src/%.o: ../src/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -fPIC -g -O0 $< -o $@
	@echo 'Build finished: $<'
	@echo

