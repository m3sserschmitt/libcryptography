OBJECTS += ./crypto/v3/aes.o \
./crypto/v3/rsa.o 

CC_DEPS += ./crypto/v3/deps/aes.d \
./crypto/v3/deps/rsa.d 

./crypto/v3/%.o: ../crypto/v3/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

