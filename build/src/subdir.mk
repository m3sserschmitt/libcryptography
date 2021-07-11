OBJECTS += ./src/aes.o \
./src/base64.o \
./src/rsa.o \
./src/sha.o 

CC_DEPS += ./src/deps/aes.d \
./src/deps/base64.d \
./src/deps/rsa.d \
./src/deps/sha.d 

./src/%.o: ../src/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

