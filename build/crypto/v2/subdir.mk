OBJECTS += ./crypto/v2/aes.o \
./crypto/v2/base64.o \
./crypto/v2/rsa.o 

CC_DEPS += ./crypto/v2/deps/aes.d \
./crypto/v2/deps/base64.d \
./crypto/v2/deps/rsa.d 

./crypto/v2/%.o: ../crypto/v2/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

