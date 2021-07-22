OBJECTS += ./main.o 

CC_DEPS += ./deps/main.d 

./%.o: ./%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -g -O0 $< -o $@
	@echo 'Build finished: $<'
	@echo

