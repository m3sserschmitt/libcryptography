OBJECTS += ./cryptex.o \
./main.o 

CC_DEPS += ./deps/cryptex.d \
./deps/main.d 

./%.o: ../%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

