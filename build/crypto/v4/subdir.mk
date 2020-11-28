OBJECTS += ./crypto/v4/aes.o \
./crypto/v4/rsa.o 

CC_DEPS += ./crypto/v4/deps/aes.d \
./crypto/v4/deps/rsa.d 

./crypto/v4/%.o: ../crypto/v4/%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -fPIC -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

