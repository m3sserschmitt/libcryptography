OBJECTS += ./main.o 

CC_DEPS += ./deps/main.d 

./%.o: ./%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall -I../include $< -o $@
	@echo 'Build finished: $<'
	@echo

