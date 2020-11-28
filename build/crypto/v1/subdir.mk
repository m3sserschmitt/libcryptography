OBJECTS += ./crypto/v1/aes.o \
./crypto/v1/base64.o \
./crypto/v1/hash.o \
./crypto/v1/init.o \
./crypto/v1/rsa.o \
./crypto/v1/sha.o 

CC_DEPS += ./crypto/v1/deps/aes.d \
./crypto/v1/deps/base64.d \
./crypto/v1/deps/hash.d \
./crypto/v1/deps/init.d \
./crypto/v1/deps/rsa.d \
./crypto/v1/deps/sha.d 

./crypto/v1/%.o: ../crypto/v1/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

